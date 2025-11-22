//! Manages GDT, IDT, and TSS for VMX virtualization contexts.

use {
    crate::intel::support::{sgdt, sidt},
    alloc::{boxed::Box, vec::Vec},
    core::{arch::asm, mem::size_of_val},
    x86::{
        dtables::{self, DescriptorTablePointer},
        segmentation::{
            BuildDescriptor, CodeSegmentType, DataSegmentType, Descriptor, DescriptorBuilder, SegmentDescriptorBuilder, SegmentSelector, load_ds,
            load_es, load_fs, load_gs, load_ss,
        },
        task,
    },
};

#[repr(C, align(4096))]
pub struct Descriptors {
    pub gdt: Vec<u64>,
    pub gdtr: DescriptorTablePointer<u64>,
    pub idt: Vec<u64>,
    pub idtr: DescriptorTablePointer<u64>,
    pub cs: SegmentSelector,
    pub tr: SegmentSelector,
    pub tss: Box<TaskStateSegment>,
}

unsafe impl Send for Descriptors {}
unsafe impl Sync for Descriptors {}

impl Descriptors {
    pub fn initialize_for_guest() -> Self {
        log::debug!("Capturing current GDT/IDT for Guest...");

        let current_gdtr = sgdt();
        let current_idtr = sidt();

        let current_gdt_slice = unsafe { core::slice::from_raw_parts(current_gdtr.base.cast::<u64>(), (current_gdtr.limit as usize + 1) / 8) };
        let current_idt_slice = unsafe { core::slice::from_raw_parts(current_idtr.base.cast::<u64>(), (current_idtr.limit as usize + 1) / 8) };

        let mut gdt = current_gdt_slice.to_vec();
        let idt = current_idt_slice.to_vec();

        log::debug!("Captured GDT entries: {}, IDT entries: {}", gdt.len(), idt.len());

        let cs = unsafe { x86::segmentation::cs() };

        // Create a TSS for the guest
        let mut tss = Box::new(TaskStateSegment::default());
        tss.base = &tss.segment as *const _ as u64;

        // Add TSS descriptor to guest GDT
        let tss_index = gdt.len();
        let (tss_low, tss_high) = Self::task_segment_descriptor_manual(&tss);
        gdt.push(tss_low);
        gdt.push(tss_high);

        // TR selector points to the TSS we just added
        let tr = SegmentSelector::new(tss_index as u16, x86::Ring::Ring0);

        log::debug!("Added TSS to guest GDT at index {}, TR selector: {:#x}", tss_index, tr.bits());

        let mut descriptors = Descriptors {
            gdt,
            gdtr: DescriptorTablePointer::default(),
            idt,
            idtr: DescriptorTablePointer::default(),
            cs,
            tr,
            tss,
        };

        descriptors.gdtr = DescriptorTablePointer::new_from_slice(&descriptors.gdt);
        descriptors.idtr = DescriptorTablePointer::new_from_slice(&descriptors.idt);

        descriptors
    }

    pub fn initialize_for_host() -> Self {
        log::debug!("Initializing Host GDT/IDT (Extending UEFI GDT)");

        // 1. Capture the CURRENT (UEFI) GDT/IDT.
        // We must reuse the UEFI GDT so that UEFI interrupt handlers (which use UEFI selectors)
        // do not crash when accessing segments like 0x18 (which might be code/data in UEFI, but TSS in a fresh GDT).
        let current_gdtr = sgdt();
        let current_idtr = sidt();

        let current_gdt_slice = unsafe { core::slice::from_raw_parts(current_gdtr.base.cast::<u64>(), (current_gdtr.limit as usize + 1) / 8) };
        let current_idt_slice = unsafe { core::slice::from_raw_parts(current_idtr.base.cast::<u64>(), (current_idtr.limit as usize + 1) / 8) };

        let mut gdt = current_gdt_slice.to_vec();
        let idt = current_idt_slice.to_vec(); // Keep UEFI IDT as is

        // 2. Create a new TSS for the Host
        let mut tss = Box::new(TaskStateSegment::default());
        tss.base = &tss.segment as *const _ as u64;

        // 3. Append our TSS to the END of the existing GDT
        let tss_index = gdt.len();
        let (tss_low, tss_high) = Self::task_segment_descriptor_manual(&tss);
        gdt.push(tss_low);
        gdt.push(tss_high);

        // 4. Setup Host Selectors
        // Reuse the current CS (UEFI Code)
        let cs = unsafe { x86::segmentation::cs() };
        // TR points to our new TSS
        let tr = SegmentSelector::new(tss_index as u16, x86::Ring::Ring0);

        let mut descriptors = Descriptors {
            gdt,
            gdtr: DescriptorTablePointer::default(),
            idt,
            idtr: DescriptorTablePointer::default(),
            cs,
            tr,
            tss,
        };

        // Update GDTR/IDTR to point to our new vectors
        descriptors.gdtr = DescriptorTablePointer::new_from_slice(&descriptors.gdt);
        descriptors.idtr = DescriptorTablePointer::new_from_slice(&descriptors.idt);

        log::debug!("Host GDT extended with TSS. New GDT Size: {}, CS: {:#x}, TR: {:#x}", descriptors.gdt.len(), cs.bits(), tr.bits());

        descriptors
    }

    pub fn load_host_state(&self) {
        log::debug!("Loading Host GDT, IDT, and TR");
        unsafe {
            dtables::lgdt(&self.gdtr);

            // Reload CS to ensure we are using the selector from our GDT (even if it's the same index)
            let cs = self.cs.bits();
            asm!(
                "push {cs}",
                "lea rax, [2f + rip]",
                "push rax",
                "retfq",
                "2:",
                cs = in(reg) u64::from(cs),
                out("rax") _,
            );

            // Reload Data Segments
            // We use index 0 (Null) for DS/ES/SS in 64-bit mode usually, but it's safer
            // to leave them as is or reload a known valid data segment if we had one.
            // Since we are extending the UEFI GDT, the current DS/SS are likely valid.
            // For safety in VMX root, we just reload them with a known valid data selector if we found one,
            // OR we just trust the current state.
            // However, VMX Host State requires valid selectors in the VMCS.
            // For strict correctness, we often just zero them in 64-bit mode (except FS/GS bases).
            let ds = SegmentSelector::from_raw(0);
            load_ds(ds);
            load_es(ds);
            // load_ss(ds); // Be careful reloading SS if RSP is using it!

            dtables::lidt(&self.idtr);
            task::load_tr(self.tr);
        }
        log::debug!("Host GDT, IDT, and TR loaded successfully");
    }

    pub fn get_desc_base(&self, selector: SegmentSelector) -> u64 {
        let index = selector.index() as usize;
        if index >= self.gdt.len() {
            return 0;
        }

        let low = self.gdt[index];
        let mut base = (low >> 16) & 0xFFFFFF;
        base |= ((low >> 56) & 0xFF) << 24;

        // Check for System Descriptor (S=0) to handle 16-byte descriptors (like TSS)
        // S bit is at bit 44.
        if (low & (1 << 44)) == 0 {
            if index + 1 < self.gdt.len() {
                let high = self.gdt[index + 1];
                base |= (high & 0xFFFFFFFF) << 32;
            }
        }
        base
    }

    pub fn get_desc_limit(&self, selector: SegmentSelector) -> u32 {
        let index = selector.index() as usize;
        if index >= self.gdt.len() {
            return 0;
        }

        let entry = self.gdt[index];
        let mut limit = (entry & 0xFFFF) | ((entry >> 32) & 0xF0000);

        if (entry & (1 << 55)) != 0 {
            limit = (limit << 12) | 0xFFF;
        }

        limit as u32
    }

    pub fn get_desc_access_rights(&self, selector: SegmentSelector) -> u32 {
        // Check Index 0
        if selector.index() == 0 {
            return 0x10000; // Unusable
        }

        let index = selector.index() as usize;
        if index >= self.gdt.len() {
            return 0x10000;
        }

        let entry = self.gdt[index];

        let low_ar = (entry >> 40) & 0xFF;
        let high_ar = (entry >> 52) & 0xF;

        let mut ar = (low_ar) | (high_ar << 12);

        // Check S bit (Bit 4). 1 = Code/Data, 0 = System
        if (ar & (1 << 4)) != 0 {
            // CODE or DATA segment

            // Check Type Bit 3 (Executable). 1 = Code, 0 = Data
            if (ar & (1 << 3)) != 0 {
                // CODE Segment (Types 8-15)
                // Force Accessed (Bit 0)
                ar |= 1;
            } else {
                // DATA Segment (Types 0-7)
                // Force to type 3: Read/Write/Accessed
                // Clear bits 0-3 (type field) then set to 0x3
                ar = (ar & !0xF) | 0x3;
            }
        } else {
            // SYSTEM SEGMENT (TSS, LDT)
            // VMX requires TSS to be Busy (Type 11 / 0xB)
            let type_field = ar & 0xF;
            if type_field == 0x9 {
                // Available 64-bit TSS - convert to Busy
                ar |= 2; // 1001b -> 1011b
            }
        }

        ar as u32
    }

    fn task_segment_descriptor_manual(tss: &TaskStateSegment) -> (u64, u64) {
        let base = tss.base;
        let limit = tss.limit;

        let base_low = base & 0xFFFFFF;
        let base_mid = (base >> 24) & 0xFF;
        let limit_low = limit & 0xFFFF;
        let limit_high = (limit >> 16) & 0xF;

        let type_ = 0x9;
        let s = 0;
        let dpl = 0;
        let p = 1;
        let avl = 0;
        let l = 0;
        let db = 0;
        let g = 0;

        let mut low_u64 = 0u64;
        low_u64 |= limit_low;
        low_u64 |= base_low << 16;
        low_u64 |= (type_ as u64) << 40;
        low_u64 |= (s as u64) << 44;
        low_u64 |= (dpl as u64) << 45;
        low_u64 |= (p as u64) << 47;
        low_u64 |= (limit_high as u64) << 48;
        low_u64 |= (avl as u64) << 52;
        low_u64 |= (l as u64) << 53;
        low_u64 |= (db as u64) << 54;
        low_u64 |= (g as u64) << 55;
        low_u64 |= (base_mid as u64) << 56;

        let high_u64 = base >> 32;

        (low_u64, high_u64)
    }

    fn code_segment_descriptor() -> Descriptor {
        DescriptorBuilder::code_descriptor(0, u32::MAX, CodeSegmentType::ExecuteReadAccessed)
            .present()
            .dpl(x86::Ring::Ring0)
            .limit_granularity_4kb()
            .l()
            .finish()
    }

    fn data_segment_descriptor() -> Descriptor {
        DescriptorBuilder::data_descriptor(0, u32::MAX, DataSegmentType::ReadWriteAccessed)
            .present()
            .dpl(x86::Ring::Ring0)
            .limit_granularity_4kb()
            .db()
            .finish()
    }

    // Removed copy_and_patch_idt as we are now reusing the UEFI IDT without modifications
}

#[derive(derivative::Derivative)]
#[derivative(Debug)]
#[repr(C, align(16))]
pub struct TaskStateSegment {
    pub base: u64,
    pub limit: u64,
    pub ar: u32,
    #[allow(dead_code)]
    #[derivative(Debug = "ignore")]
    segment: TaskStateSegmentRaw,
}

impl Default for TaskStateSegment {
    fn default() -> Self {
        let mut segment = TaskStateSegmentRaw([0; 108]);
        segment.0[102] = 0xFF;
        segment.0[103] = 0xFF;
        Self {
            base: 0,
            limit: size_of_val(&segment) as u64 - 1,
            ar: 0x8b00,
            segment,
        }
    }
}

#[repr(C, packed)]
struct TaskStateSegmentRaw([u8; 108]);
