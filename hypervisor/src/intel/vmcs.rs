//! A crate responsible for managing the VMCS region for VMX operations.

use {
    crate::{
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            controls::{VmxControl, adjust_vmx_controls},
            descriptor::Descriptors,
            invept::invept_single_context,
            invvpid::{VPID_TAG, invvpid_single_context},
            support::{cr3, rdmsr, vmread, vmwrite},
        },
    },
    bit_field::BitField,
    core::fmt,
    x86::{
        bits64::{paging::BASE_PAGE_SIZE, rflags},
        debugregs::dr7,
        msr,
        segmentation::{SegmentSelector, cs, ds, es, fs, gs, ss},
        vmx::vmcs,
    },
    x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
};

const HOST_IA32_PAT_FULL: u32 = 0x00002C00;
const HOST_IA32_EFER_FULL: u32 = 0x00002C02;

#[repr(C, align(4096))]
pub struct Vmcs {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub reserved: [u8; BASE_PAGE_SIZE - 8],
}

impl Vmcs {
    pub fn init(&mut self) {
        self.revision_id = rdmsr(msr::IA32_VMX_BASIC) as u32;
        self.revision_id.set_bit(31, false);
    }

    pub fn setup_guest_registers_state(guest_descriptor: &Descriptors, guest_registers: &GuestRegisters) {
        log::debug!("Setting up Guest Registers State");

        // FIX 3: Calculate VMX fixed bits for Guest CR0
        let vmx_cr0_fixed0 = unsafe { rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let vmx_cr0_fixed1 = unsafe { rdmsr(msr::IA32_VMX_CR0_FIXED1) };
        let initial_cr0 = Cr0::read_raw()
            // Apply mandatory fixed bits
            | vmx_cr0_fixed0
            & vmx_cr0_fixed1
            // Ensure 64-bit execution requirements are met (PG=1, PE=1)
            | Cr0Flags::PAGING.bits() | Cr0Flags::PROTECTED_MODE_ENABLE.bits();

        vmwrite(vmcs::guest::CR0, initial_cr0);

        // CRITICAL CHECK: Guest CR3 is set to the host's current CR3. This assumes the host's paging tables
        // correctly identity map the guest's entry point (0x4000).
        vmwrite(vmcs::guest::CR3, cr3());

        // FIX 7: Force CR4 to be VMX-compliant.
        let vmx_cr4_fixed0 = unsafe { rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let vmx_cr4_fixed1 = unsafe { rdmsr(msr::IA32_VMX_CR4_FIXED1) };
        let initial_cr4 = Cr4::read_raw() | vmx_cr4_fixed0 & vmx_cr4_fixed1;

        vmwrite(vmcs::guest::CR4, initial_cr4);

        vmwrite(vmcs::guest::DR7, unsafe { dr7().0 as u64 });

        vmwrite(vmcs::guest::RSP, guest_registers.rsp);
        vmwrite(vmcs::guest::RIP, guest_registers.rip);
        vmwrite(vmcs::guest::RFLAGS, rflags::read().bits());

        let code_selector = cs();
        // FIX 6: Use a known good data selector (Index 2, Ring 0 -> 0x10) for stability.
        let data_selector = SegmentSelector::new(2, x86::Ring::Ring0);

        // Selectors
        vmwrite(vmcs::guest::CS_SELECTOR, code_selector.bits());
        vmwrite(vmcs::guest::SS_SELECTOR, data_selector.bits());
        vmwrite(vmcs::guest::DS_SELECTOR, data_selector.bits());
        vmwrite(vmcs::guest::ES_SELECTOR, data_selector.bits());
        vmwrite(vmcs::guest::FS_SELECTOR, data_selector.bits());
        vmwrite(vmcs::guest::GS_SELECTOR, data_selector.bits());
        vmwrite(vmcs::guest::LDTR_SELECTOR, 0u16);
        vmwrite(vmcs::guest::TR_SELECTOR, guest_descriptor.tr.bits());

        // Limits - Parsed directly from GDT to ensure validity
        vmwrite(vmcs::guest::CS_LIMIT, guest_descriptor.get_desc_limit(code_selector));
        vmwrite(vmcs::guest::SS_LIMIT, guest_descriptor.get_desc_limit(data_selector));
        vmwrite(vmcs::guest::DS_LIMIT, guest_descriptor.get_desc_limit(data_selector));
        vmwrite(vmcs::guest::ES_LIMIT, guest_descriptor.get_desc_limit(data_selector));
        vmwrite(vmcs::guest::FS_LIMIT, guest_descriptor.get_desc_limit(data_selector));
        vmwrite(vmcs::guest::GS_LIMIT, guest_descriptor.get_desc_limit(data_selector));
        vmwrite(vmcs::guest::LDTR_LIMIT, 0u32);
        vmwrite(vmcs::guest::TR_LIMIT, guest_descriptor.get_desc_limit(guest_descriptor.tr));

        // Access Rights - Get from GDT and force data segment types for SS/DS/ES
        let mut cs_ar = guest_descriptor.get_desc_access_rights(code_selector);
        let mut ss_ar = guest_descriptor.get_desc_access_rights(data_selector);
        let mut ds_ar = guest_descriptor.get_desc_access_rights(data_selector);
        let mut es_ar = guest_descriptor.get_desc_access_rights(data_selector);
        let mut fs_ar = guest_descriptor.get_desc_access_rights(data_selector);
        let mut gs_ar = guest_descriptor.get_desc_access_rights(data_selector);

        // FIX 1: Enforce 64-bit mode for the Guest Code Segment Access Rights (CS_ACCESS_RIGHTS).
        // Bit 13 (L bit) must be 1 for 64-bit mode.
        // Bit 14 (D/B bit) must be 0 for 64-bit mode.
        const CS_64BIT_MODE: u32 = 1 << 13;
        const DB_BIT: u32 = 1 << 14;
        cs_ar |= CS_64BIT_MODE;
        cs_ar &= !DB_BIT;

        // CRITICAL FIX: Force SS/DS/ES to be data segments
        // If bit 3 of the type field is set (executable), clear it and force data type.
        for ar in [&mut ss_ar, &mut ds_ar, &mut es_ar, &mut fs_ar, &mut gs_ar] {
            // Check if it's a code/data segment (S bit = 1) and executable (bit 3 = 1)
            if (*ar & (1 << 4)) != 0 && (*ar & (1 << 3)) != 0 {
                // It's a code segment being used as data - convert it
                *ar = (*ar & !0xF) | 0x3; // Force type to Read/Write/Accessed data
            }
        }

        log::debug!("Computed access rights: CS={:#x} SS={:#x} DS={:#x} ES={:#x} FS={:#x} GS={:#x}", cs_ar, ss_ar, ds_ar, es_ar, fs_ar, gs_ar);

        vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, cs_ar as u64);
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, ss_ar as u64);
        vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, ds_ar as u64);
        vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, es_ar as u64);
        vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, fs_ar as u64);
        vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, gs_ar as u64);
        vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, 0x10000u64); // Unusable
        vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, guest_descriptor.get_desc_access_rights(guest_descriptor.tr) as u64);

        // Base Addresses
        vmwrite(vmcs::guest::TR_BASE, guest_descriptor.get_desc_base(guest_descriptor.tr));

        // For FS/GS Base, use MSRs as they are usually used in 64-bit mode
        vmwrite(vmcs::guest::FS_BASE, unsafe { msr::rdmsr(msr::IA32_FS_BASE) });
        vmwrite(vmcs::guest::GS_BASE, unsafe { msr::rdmsr(msr::IA32_GS_BASE) });

        // Other Bases are usually 0 in flat 64-bit mode, but for strictness:
        vmwrite(vmcs::guest::CS_BASE, 0u64);
        vmwrite(vmcs::guest::SS_BASE, 0u64);
        vmwrite(vmcs::guest::DS_BASE, 0u64);
        vmwrite(vmcs::guest::ES_BASE, 0u64);
        vmwrite(vmcs::guest::LDTR_BASE, 0u64);

        vmwrite(vmcs::guest::GDTR_BASE, guest_descriptor.gdtr.base as u64);

        // FIX 5: Use host's IDTR to ensure exception handlers are available
        vmwrite(vmcs::guest::IDTR_BASE, guest_descriptor.idtr.base as u64);

        vmwrite(vmcs::guest::GDTR_LIMIT, guest_descriptor.gdtr.limit as u64);
        vmwrite(vmcs::guest::IDTR_LIMIT, guest_descriptor.idtr.limit as u64);

        // FIX 2: Ensure EFER has LME (Bit 8) and LMA (Bit 10) set for 64-bit mode.
        const LME_AND_LMA: u64 = (1 << 8) | (1 << 10);
        vmwrite(vmcs::guest::IA32_EFER_FULL, unsafe { msr::rdmsr(msr::IA32_EFER) } | LME_AND_LMA);

        vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX);

        // CRITICAL: Set interruptibility state and activity state
        vmwrite(vmcs::guest::INTERRUPTIBILITY_STATE, 0u64);
        vmwrite(vmcs::guest::ACTIVITY_STATE, 0u64); // Active state
        vmwrite(vmcs::guest::PENDING_DBG_EXCEPTIONS, 0u64);

        log::debug!("=== GUEST STATE DEBUG ===");
        log::debug!("Guest CR0: {:#x}", vmread(vmcs::guest::CR0));
        log::debug!("Guest CR3: {:#x}", vmread(vmcs::guest::CR3));
        log::debug!("Guest CR4: {:#x}", vmread(vmcs::guest::CR4));
        log::debug!("Guest RIP: {:#x}", vmread(vmcs::guest::RIP));
        log::debug!("Guest RSP: {:#x}", vmread(vmcs::guest::RSP));
        log::debug!("Guest RFLAGS: {:#x}", vmread(vmcs::guest::RFLAGS));
        log::debug!(
            "Guest CS: sel={:#x} base={:#x} limit={:#x} ar={:#x}",
            vmread(vmcs::guest::CS_SELECTOR),
            vmread(vmcs::guest::CS_BASE),
            vmread(vmcs::guest::CS_LIMIT),
            vmread(vmcs::guest::CS_ACCESS_RIGHTS)
        );
        log::debug!(
            "Guest SS: sel={:#x} base={:#x} limit={:#x} ar={:#x}",
            vmread(vmcs::guest::SS_SELECTOR),
            vmread(vmcs::guest::SS_BASE),
            vmread(vmcs::guest::SS_LIMIT),
            vmread(vmcs::guest::SS_ACCESS_RIGHTS)
        );
        log::debug!(
            "Guest DS: sel={:#x} base={:#x} limit={:#x} ar={:#x}",
            vmread(vmcs::guest::DS_SELECTOR),
            vmread(vmcs::guest::DS_BASE),
            vmread(vmcs::guest::DS_LIMIT),
            vmread(vmcs::guest::DS_ACCESS_RIGHTS)
        );
        log::debug!(
            "Guest TR: sel={:#x} base={:#x} limit={:#x} ar={:#x}",
            vmread(vmcs::guest::TR_SELECTOR),
            vmread(vmcs::guest::TR_BASE),
            vmread(vmcs::guest::TR_LIMIT),
            vmread(vmcs::guest::TR_ACCESS_RIGHTS)
        );
        log::debug!(
            "Guest LDTR: sel={:#x} base={:#x} limit={:#x} ar={:#x}",
            vmread(vmcs::guest::LDTR_SELECTOR),
            vmread(vmcs::guest::LDTR_BASE),
            vmread(vmcs::guest::LDTR_LIMIT),
            vmread(vmcs::guest::LDTR_ACCESS_RIGHTS)
        );
        log::debug!("Guest GDTR: base={:#x} limit={:#x}", vmread(vmcs::guest::GDTR_BASE), vmread(vmcs::guest::GDTR_LIMIT));
        log::debug!("Guest IDTR: base={:#x} limit={:#x}", vmread(vmcs::guest::IDTR_BASE), vmread(vmcs::guest::IDTR_LIMIT));
        log::debug!("Guest EFER: {:#x}", vmread(vmcs::guest::IA32_EFER_FULL));
        log::debug!("Guest DR7: {:#x}", vmread(vmcs::guest::DR7));
        log::debug!("Guest Interruptibility: {:#x}", vmread(vmcs::guest::INTERRUPTIBILITY_STATE));
        log::debug!("Guest Activity: {:#x}", vmread(vmcs::guest::ACTIVITY_STATE));

        log::debug!("Guest Registers State setup successfully!");
    }

    pub fn setup_host_registers_state(host_descriptor: &Descriptors, pml4_pa: u64) -> Result<(), HypervisorError> {
        log::debug!("Setting up Host Registers State");

        // FIX 8: Enforce VMX compliance on Host CR0/CR4 by applying VMX fixed bits
        let vmx_cr0_fixed0 = unsafe { rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let vmx_cr4_fixed0 = unsafe { rdmsr(msr::IA32_VMX_CR4_FIXED0) };

        vmwrite(vmcs::host::CR0, Cr0::read_raw() | vmx_cr0_fixed0);
        vmwrite(vmcs::host::CR3, pml4_pa);
        vmwrite(vmcs::host::CR4, Cr4::read_raw() | vmx_cr4_fixed0);

        let data_selector = SegmentSelector::new(2, x86::Ring::Ring0);

        vmwrite(vmcs::host::CS_SELECTOR, host_descriptor.cs.bits());
        vmwrite(vmcs::host::SS_SELECTOR, data_selector.bits());
        vmwrite(vmcs::host::DS_SELECTOR, data_selector.bits());
        vmwrite(vmcs::host::ES_SELECTOR, data_selector.bits());
        vmwrite(vmcs::host::FS_SELECTOR, data_selector.bits());
        vmwrite(vmcs::host::GS_SELECTOR, data_selector.bits());
        vmwrite(vmcs::host::TR_SELECTOR, host_descriptor.tr.bits());

        vmwrite(vmcs::host::FS_BASE, unsafe { msr::rdmsr(msr::IA32_FS_BASE) });
        vmwrite(vmcs::host::GS_BASE, unsafe { msr::rdmsr(msr::IA32_GS_BASE) });
        vmwrite(vmcs::host::TR_BASE, host_descriptor.tss.base);
        vmwrite(vmcs::host::GDTR_BASE, host_descriptor.gdtr.base as u64);
        vmwrite(vmcs::host::IDTR_BASE, host_descriptor.idtr.base as u64);

        vmwrite(HOST_IA32_EFER_FULL, unsafe { msr::rdmsr(msr::IA32_EFER) });
        vmwrite(HOST_IA32_PAT_FULL, unsafe { msr::rdmsr(msr::IA32_PAT) });

        vmwrite(vmcs::host::IA32_SYSENTER_CS, unsafe { msr::rdmsr(msr::IA32_SYSENTER_CS) });
        vmwrite(vmcs::host::IA32_SYSENTER_ESP, unsafe { msr::rdmsr(msr::IA32_SYSENTER_ESP) });
        vmwrite(vmcs::host::IA32_SYSENTER_EIP, unsafe { msr::rdmsr(msr::IA32_SYSENTER_EIP) });

        // CRITICAL FIX: Set HOST_RIP and HOST_RSP here during VMCS setup, not in assembly!
        unsafe extern "efiapi" {
            fn vmexit_asm_handler();
        }

        vmwrite(vmcs::host::RIP, vmexit_asm_handler as u64);

        let host_rsp: u64;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) host_rsp, options(nomem, nostack));
        }
        vmwrite(vmcs::host::RSP, host_rsp);

        log::info!("Host RIP set to: {:#x}", vmexit_asm_handler as u64);
        log::info!("Host RSP set to: {:#x}", host_rsp);

        log::debug!("Host Registers State setup successfully!");

        Ok(())
    }

    pub fn setup_vmcs_control_fields(primary_eptp: u64, msr_bitmap: u64) -> Result<(), HypervisorError> {
        log::debug!("Setting up VMCS Control Fields");

        // FIX 9: Enforce mandatory control bits for PRIMARY_PROCBASED_EXEC_CONTROLS
        const PRIMARY_MANDATORY: u64 = (vmcs::control::PrimaryControls::INTERRUPT_WINDOW_EXITING.bits() as u64)
            | (vmcs::control::PrimaryControls::USE_TSC_OFFSETTING.bits() as u64);

        const PRIMARY_CTL: u64 = (vmcs::control::PrimaryControls::SECONDARY_CONTROLS.bits() as u64)
            | (vmcs::control::PrimaryControls::USE_MSR_BITMAPS.bits() as u64)
            | PRIMARY_MANDATORY;

        const SECONDARY_CTL: u64 = (vmcs::control::SecondaryControls::ENABLE_RDTSCP.bits()
            | vmcs::control::SecondaryControls::ENABLE_XSAVES_XRSTORS.bits()
            | vmcs::control::SecondaryControls::ENABLE_INVPCID.bits()
            | vmcs::control::SecondaryControls::ENABLE_VPID.bits()
            | vmcs::control::SecondaryControls::ENABLE_EPT.bits()
            | vmcs::control::SecondaryControls::CONCEAL_VMX_FROM_PT.bits()
            | vmcs::control::SecondaryControls::UNRESTRICTED_GUEST.bits()) as u64;
        const ENTRY_CTL: u64 = (vmcs::control::EntryControls::IA32E_MODE_GUEST.bits()
    | vmcs::control::EntryControls::LOAD_DEBUG_CONTROLS.bits()
    | vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits()
    // CRITICAL FIX: Ensure IA32_EFER is loaded on VM Entry
    | vmcs::control::EntryControls::LOAD_IA32_EFER.bits()) as u64;
        const EXIT_CTL: u64 = (vmcs::control::ExitControls::HOST_ADDRESS_SPACE_SIZE.bits()
            | vmcs::control::ExitControls::SAVE_DEBUG_CONTROLS.bits()
            | vmcs::control::ExitControls::CONCEAL_VMX_FROM_PT.bits()) as u64;
        const PINBASED_CTL: u64 = 0;

        vmwrite(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased, PRIMARY_CTL));
        vmwrite(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased2, SECONDARY_CTL));
        vmwrite(vmcs::control::VMENTRY_CONTROLS, adjust_vmx_controls(VmxControl::VmEntry, ENTRY_CTL));
        vmwrite(vmcs::control::VMEXIT_CONTROLS, adjust_vmx_controls(VmxControl::VmExit, EXIT_CTL));
        vmwrite(vmcs::control::PINBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL));

        let vmx_cr0_fixed0 = unsafe { rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let vmx_cr0_fixed1 = unsafe { rdmsr(msr::IA32_VMX_CR0_FIXED1) };

        let vmx_cr4_fixed0 = unsafe { rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let vmx_cr4_fixed1 = unsafe { rdmsr(msr::IA32_VMX_CR4_FIXED1) };

        vmwrite(
            vmcs::control::CR0_GUEST_HOST_MASK,
            vmx_cr0_fixed0 | !vmx_cr0_fixed1 | Cr0Flags::CACHE_DISABLE.bits() | Cr0Flags::WRITE_PROTECT.bits(),
        );
        vmwrite(vmcs::control::CR4_GUEST_HOST_MASK, vmx_cr4_fixed0 | !vmx_cr4_fixed1);

        // FIX: Ensure CR0 Read Shadow is VMX compliant (applies mandatory fixed bits)
        vmwrite(vmcs::control::CR0_READ_SHADOW, Cr0::read_raw() | vmx_cr0_fixed0);
        vmwrite(vmcs::control::CR4_READ_SHADOW, Cr4::read_raw() & !Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits());

        vmwrite(vmcs::control::MSR_BITMAPS_ADDR_FULL, msr_bitmap);

        vmwrite(vmcs::control::EPTP_FULL, primary_eptp);
        vmwrite(vmcs::control::VPID, VPID_TAG);

        invept_single_context(primary_eptp);
        invvpid_single_context(VPID_TAG);

        log::debug!("VMCS Control Fields setup successfully!");

        Ok(())
    }
}

impl fmt::Debug for Vmcs {
    fn fmt(&self, format: &mut fmt::Formatter<'_>) -> fmt::Result {
        format
            .debug_struct("Vmcs")
            .field("Current VMCS: ", &(self as *const _))
            .field("Revision ID: ", &self.revision_id)
            .finish_non_exhaustive()
    }
}
