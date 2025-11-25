//! Manages GDT, IDT, and TSS for VMX virtualization contexts.
//!
//! Facilitates the creation and manipulation of the Global Descriptor Table (GDT),
//! Interrupt Descriptor Table (IDT), and Task State Segment (TSS) necessary for VMX operations.
//! Supports both host and guest environments, ensuring compatibility and proper setup for virtualization.
//! Credits to Satoshi Tanda: https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/descriptors.rs

use {
    crate::intel::support::{sgdt, sidt},
    alloc::vec::Vec,
    core::mem::size_of_val,
    x86::{
        dtables::DescriptorTablePointer,
        segmentation::{
            BuildDescriptor, CodeSegmentType, DataSegmentType, Descriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentDescriptorBuilder,
            SegmentSelector, cs,
        },
    },
};

/// Represents the descriptor tables (GDT and IDT) for the host and guest.
/// Contains the GDT, IDT, TSS, and their respective register pointers.
#[repr(C, align(4096))]
pub struct Descriptors {
    /// Vector holding the GDT entries.
    pub gdt: Vec<u64>,

    /// Descriptor table pointer to the GDT.
    pub gdtr: DescriptorTablePointer<u64>,

    /// Vector holding the IDT entries.
    pub idt: Vec<u64>,

    /// Descriptor table pointer to the IDT.
    pub idtr: DescriptorTablePointer<u64>,

    /// Code segment selector.
    pub cs: SegmentSelector,

    /// Task register selector.
    pub tr: SegmentSelector,

    /// Task State Segment.
    pub tss: TaskStateSegment,
}

unsafe impl Send for Descriptors {}
unsafe impl Sync for Descriptors {}

impl Descriptors {
    /// Creates a new GDT based on the current one, including TSS.
    ///
    /// Copies the current GDT and appends a TSS descriptor to it. Useful for guest
    /// VM setup to ensure compatibility with VMX requirements.
    ///
    /// # Returns
    /// A `Descriptors` instance with an updated GDT including TSS.
    pub fn initialize_for_guest() -> Self {
        log::debug!("Creating a new GDT with TSS for guest");

        // Get the current GDT.
        let current_gdtr = sgdt();
        let current_gdt = unsafe { core::slice::from_raw_parts(current_gdtr.base.cast::<u64>(), usize::from(current_gdtr.limit + 1) / 8) };

        // Get the current IDT.
        let current_idtr = sidt();
        let current_idt = unsafe { core::slice::from_raw_parts(current_idtr.base.cast::<u64>(), usize::from(current_idtr.limit + 1) / 8) };

        let mut descriptors = Descriptors {
            gdt: current_gdt.to_vec(),
            gdtr: DescriptorTablePointer::<u64>::default(),
            idt: current_idt.to_vec(),
            idtr: DescriptorTablePointer::<u64>::default(),
            cs: SegmentSelector::from_raw(0),
            tr: SegmentSelector::from_raw(0),
            tss: TaskStateSegment::default(),
        };

        // Fix up the TSS base to point to the actual location after struct initialization
        descriptors.tss.base = &descriptors.tss.segment as *const _ as u64;

        // NOTE: Do NOT modify IDT entries! They have a completely different format than GDT entries.
        // IDT entries are Interrupt/Trap Gate Descriptors, not segment descriptors.
        // Just copy them as-is from the current IDT.

        // Append the TSS descriptor. Push extra 0 as it is 16 bytes.
        // See: 3.5.2 Segment Descriptor Tables in IA-32e Mode
        let tr_index = descriptors.gdt.len() as u16;

        // CRITICAL: Create TSS descriptor with type 0xB (Busy TSS) for VMCS
        // VMX requires that the guest TR descriptor in the GDT has type 0xB
        let tss_desc = Self::task_segment_descriptor_busy(&descriptors.tss);
        descriptors.gdt.push(tss_desc.as_u64());
        descriptors.gdt.push(0);

        descriptors.gdtr = DescriptorTablePointer::new_from_slice(&descriptors.gdt);
        descriptors.cs = cs();
        descriptors.tr = SegmentSelector::new(tr_index, x86::Ring::Ring0);

        log::debug!("New GDT with TSS created for guest successfully!");

        descriptors
    }

    /// Creates a new GDT with TSS from scratch for the host.
    ///
    /// Initializes a GDT with essential descriptors, including a TSS descriptor,
    /// tailored for host operation in a VMX environment.
    ///
    /// # Returns
    /// A `Descriptors` instance with a newly created GDT for the host.
    pub fn initialize_for_host() -> Self {
        log::debug!("Creating a new GDT with TSS for host");

        let mut descriptors = Descriptors {
            gdt: Vec::new(),
            gdtr: DescriptorTablePointer::<u64>::default(),
            idt: Vec::new(),
            idtr: DescriptorTablePointer::<u64>::default(),
            cs: SegmentSelector::from_raw(0),
            tr: SegmentSelector::from_raw(0),
            tss: TaskStateSegment::default(),
        };

        // CRITICAL: Fix up the TSS base to point to the actual location
        // This must be done AFTER the Descriptors struct is in its final location
        descriptors.tss.base = &descriptors.tss.segment as *const _ as u64;

        log::debug!("TSS base address: {:#018x}", descriptors.tss.base);
        log::debug!("TSS limit: {:#018x}", descriptors.tss.limit);

        // Build the GDT with proper segment descriptors
        descriptors.gdt.push(0); // Index 0: NULL descriptor
        descriptors.gdt.push(Self::code_segment_descriptor().as_u64()); // Index 1: Code segment (selector 0x08)
        descriptors.gdt.push(Self::data_segment_descriptor().as_u64()); // Index 2: Data segment (selector 0x10)

        // CRITICAL: For host, create Available TSS (type 0x9) because we'll use LTR
        // LTR instruction expects type 0x9 and will automatically change it to 0xB
        let tss_desc = Self::task_segment_descriptor_available(&descriptors.tss).as_u64();
        log::debug!("TSS descriptor low: {:#018x}", tss_desc);
        descriptors.gdt.push(tss_desc); // Index 3: TSS (selector 0x18)
        descriptors.gdt.push(0); // Index 4: TSS high part (64-bit TSS is 16 bytes)

        descriptors.gdtr = DescriptorTablePointer::new_from_slice(&descriptors.gdt);
        descriptors.cs = SegmentSelector::new(1, x86::Ring::Ring0); // CS = 0x08
        descriptors.tr = SegmentSelector::new(3, x86::Ring::Ring0); // TR = 0x18

        // Initialize the IDT with current IDT entries for the host
        // NOTE: Do NOT modify IDT entries! They are Interrupt/Trap Gate Descriptors
        // with a completely different format than segment descriptors.
        descriptors.idt = Self::copy_current_idt();
        descriptors.idtr = DescriptorTablePointer::new_from_slice(&descriptors.idt);

        log::debug!("New GDT with TSS and IDT created for host successfully!");

        descriptors
    }

    /// Builds an Available TSS descriptor (type 0x9) for use with LTR instruction.
    ///
    /// This is used for the HOST because LTR requires type 0x9 and will automatically
    /// change it to 0xB when it loads the TR.
    fn task_segment_descriptor_available(tss: &TaskStateSegment) -> Descriptor {
        let desc: Descriptor = <DescriptorBuilder as GateDescriptorBuilder<u32>>::tss_descriptor(tss.base, tss.limit, true)
            .present()
            .dpl(x86::Ring::Ring0)
            .finish();

        let desc_value = desc.as_u64();
        let mut bytes = desc_value.to_le_bytes();

        // Fix G bit for byte-granular limit
        let byte6 = bytes[6];
        let limit_high = byte6 & 0x0F;
        let flags = (byte6 >> 4) & 0x0F;
        let fixed_flags = flags & 0b0001; // Keep only AVL, clear G/D/B/L
        bytes[6] = limit_high | (fixed_flags << 4);

        // Keep type as 0x9 (Available TSS) - LTR will change it to 0xB
        let fixed_desc_value = u64::from_le_bytes(bytes);
        unsafe { core::mem::transmute::<u64, Descriptor>(fixed_desc_value) }
    }

    /// Builds a Busy TSS descriptor (type 0xB) for VMCS guest state.
    ///
    /// This is used for the GUEST because VMX requires the guest TR descriptor
    /// in the GDT to have type 0xB (Busy TSS) to match the TR_ACCESS_RIGHTS
    /// field in the VMCS.
    fn task_segment_descriptor_busy(tss: &TaskStateSegment) -> Descriptor {
        let desc: Descriptor = <DescriptorBuilder as GateDescriptorBuilder<u32>>::tss_descriptor(tss.base, tss.limit, true)
            .present()
            .dpl(x86::Ring::Ring0)
            .finish();

        let desc_value = desc.as_u64();
        let mut bytes = desc_value.to_le_bytes();

        log::debug!("TSS descriptor bytes BEFORE: {:02x?}", bytes);
        log::debug!("TSS descriptor value BEFORE: {:#018x}", desc_value);

        // Byte 6 contains both limit high (lower nibble) and flags (upper nibble)
        let byte6 = bytes[6];
        let limit_high = byte6 & 0x0F;
        let flags = (byte6 >> 4) & 0x0F;

        log::debug!("Byte 6: {:#04x} (limit_high={:#x}, flags={:#x})", byte6, limit_high, flags);
        log::debug!("Flags breakdown:");
        log::debug!("  G (bit 3): {}", (flags >> 3) & 1);
        log::debug!("  D/B (bit 2): {}", (flags >> 2) & 1);
        log::debug!("  L (bit 1): {}", (flags >> 1) & 1);
        log::debug!("  AVL (bit 0): {}", flags & 1);

        // CRITICAL FIX: For TSS with byte-granular limit (0x67 = 103 bytes), G bit MUST be 0!
        // Also ensure L=0 and D/B=0 for 64-bit TSS, preserve AVL
        let fixed_flags = flags & 0b0001; // Keep only AVL (bit 0), clear G, D/B, and L
        let fixed_byte6 = limit_high | (fixed_flags << 4);
        bytes[6] = fixed_byte6;

        let byte5_before = bytes[5];
        log::debug!("Byte 5 (access byte) BEFORE modification: {:#04x}", byte5_before);
        log::debug!("  Type (bits 0-3): {:#x}", byte5_before & 0xF);
        log::debug!("  S (bit 4): {}", (byte5_before >> 4) & 1);
        log::debug!("  DPL (bits 5-6): {}", (byte5_before >> 5) & 3);
        log::debug!("  P (bit 7): {}", (byte5_before >> 7) & 1);

        // CRITICAL FOR GUEST: Change type from 0x9 to 0xB (Busy TSS)
        // VMX requires guest TR descriptor to have type 0xB
        let current_type = byte5_before & 0xF;
        log::debug!("Current TSS type: {:#x}, changing to 0xB (Busy TSS) for VMCS", current_type);

        // Clear type bits (0-3) and set to 0xB
        let byte5_after = (byte5_before & 0xF0) | 0x0B;
        bytes[5] = byte5_after;

        log::debug!("Byte 5 (access byte) changed to: {:#04x}", byte5_after);
        log::debug!("  Type (bits 0-3): {:#x} (0xB = Busy TSS for VMX)", byte5_after & 0xF);

        let fixed_desc_value = u64::from_le_bytes(bytes);

        log::debug!("TSS descriptor bytes AFTER:  {:02x?}", bytes);
        log::debug!("TSS descriptor value AFTER:  {:#018x}", fixed_desc_value);
        log::debug!("Fixed byte 6: {:#04x} (limit_high={:#x}, flags={:#x})", fixed_byte6, limit_high, fixed_flags);

        // Reconstruct the descriptor from the modified value
        unsafe { core::mem::transmute::<u64, Descriptor>(fixed_desc_value) }
    }

    /// Constructs a code segment descriptor for use in the GDT.
    fn code_segment_descriptor() -> Descriptor {
        DescriptorBuilder::code_descriptor(0, u32::MAX, CodeSegmentType::ExecuteReadAccessed)
            .present()
            .dpl(x86::Ring::Ring0)
            .limit_granularity_4kb()
            .l()
            .finish()
    }

    /// Constructs a data segment descriptor for use in the GDT.
    fn data_segment_descriptor() -> Descriptor {
        DescriptorBuilder::data_descriptor(0, u32::MAX, DataSegmentType::ReadWriteAccessed)
            .present()
            .dpl(x86::Ring::Ring0)
            .limit_granularity_4kb()
            .db()
            .finish()
    }

    /// Copies the current IDT for the guest/host.
    fn copy_current_idt() -> Vec<u64> {
        log::trace!("Copying current IDT");

        let current_idtr = sidt();
        let current_idt = unsafe { core::slice::from_raw_parts(current_idtr.base.cast::<u64>(), usize::from(current_idtr.limit + 1) / 8) };

        let new_idt = current_idt.to_vec();

        log::trace!("Copied current IDT");

        new_idt
    }
}

/// Represents the Task State Segment (TSS).
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct TaskStateSegment {
    /// The base address of the TSS.
    pub base: u64,

    /// The size of the TSS minus one.
    pub limit: u64,

    /// Access rights for the TSS.
    pub ar: u32,

    /// The actual TSS data.
    #[allow(dead_code)]
    #[derivative(Debug = "ignore")]
    segment: TaskStateSegmentRaw,
}

impl Default for TaskStateSegment {
    fn default() -> Self {
        let segment = TaskStateSegmentRaw([0; 104]);
        // CRITICAL: Don't calculate base address here!
        // The struct will be moved, so the address calculated here will be wrong.
        // The base will be fixed up in initialize_for_host/guest after the struct
        // is in its final location.
        Self {
            base: 0, // Will be fixed up later
            limit: size_of_val(&segment) as u64 - 1,
            ar: 0x8b00, // Native AR format: type 0xB in upper byte (like memn0ps original)
            segment,
        }
    }
}

/// Low-level representation of the 64-bit Task State Segment (TSS).
#[allow(dead_code)]
struct TaskStateSegmentRaw([u8; 104]);
