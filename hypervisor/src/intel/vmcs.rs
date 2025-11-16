//! A crate responsible for managing the VMCS region for VMX operations.
//!
//! This crate provides functionality to set up the VMCS region in memory, which
//! is vital for VMX operations on the CPU. It also offers utility functions for
//! adjusting VMCS entries and displaying VMCS state for debugging purposes.

use {
    crate::{
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            controls::{VmxControl, adjust_vmx_controls},
            descriptor::Descriptors,
            invept::invept_single_context,
            invvpid::{VPID_TAG, invvpid_single_context},
            segmentation::{access_rights_from_native, lar, lsl},
            support::{cr3, rdmsr, sidt, vmread, vmwrite},
        },
    },
    bit_field::BitField,
    core::fmt,
    x86::{
        bits64::{paging::BASE_PAGE_SIZE, rflags},
        debugregs::dr7,
        msr,
        segmentation::{cs, ds, es, fs, gs, ss},
        vmx::vmcs,
    },
    x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
};

/// Represents the VMCS region in memory.
///
/// The VMCS region is essential for VMX operations on the CPU.
/// This structure offers methods for setting up the VMCS region, adjusting VMCS entries,
/// and performing related tasks.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.2 FORMAT OF THE VMCS REGION
#[repr(C, align(4096))]
pub struct Vmcs {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub reserved: [u8; BASE_PAGE_SIZE - 8],
}

impl Vmcs {
    /// Initializes the VMCS region.
    pub fn init(&mut self) {
        self.revision_id = rdmsr(msr::IA32_VMX_BASIC) as u32;
        self.revision_id.set_bit(31, false);
    }

    /// Initialize the guest state for the currently loaded VMCS.
    ///
    /// The method sets up various guest state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.4 GUEST-STATE AREA.
    ///
    /// # Arguments
    /// * `guest_descriptor` - Descriptor tables for the guest.
    /// * `guest_registers` - Guest registers for the guest.
    /// * `host_cr3` - The host's CR3 value (PML4 physical address) to use for guest
    pub fn setup_guest_registers_state(guest_descriptor: &Descriptors, guest_registers: &GuestRegisters, host_cr3: u64) {
        log::debug!("Setting up Guest Registers State");

        // ---------------------------------------------------------------------
        // Control registers: CR0 / CR3 / CR4
        // ---------------------------------------------------------------------
        //
        // TEMPORARY DEBUG: Try 32-bit protected mode instead of 64-bit
        // to rule out long-mode-specific issues
        let mut guest_cr0 = Cr0::read_raw();
        guest_cr0 &= !Cr0Flags::PAGING.bits(); // Disable PG bit
        guest_cr0 &= !Cr0Flags::WRITE_PROTECT.bits(); // Disable WP bit

        let guest_cr3 = 0u64; // CR3 not used when paging is disabled

        let mut guest_cr4 = Cr4::read_raw();
        guest_cr4 &= !Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits();
        guest_cr4 &= !Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits(); // Disable PAE for 32-bit mode

        vmwrite(vmcs::guest::CR0, guest_cr0);
        vmwrite(vmcs::guest::CR3, guest_cr3);
        vmwrite(vmcs::guest::CR4, guest_cr4);

        log::debug!("Guest CR0 (32-bit mode): {:#018x}, Guest CR3: {:#018x}, Guest CR4: {:#018x}", guest_cr0, guest_cr3, guest_cr4);

        // Debug registers
        vmwrite(vmcs::guest::DR7, unsafe { dr7().0 as u64 });

        // Guest general-purpose / control-flow state
        vmwrite(vmcs::guest::RSP, guest_registers.rsp);
        vmwrite(vmcs::guest::RIP, guest_registers.rip);
        vmwrite(vmcs::guest::RFLAGS, rflags::read().bits());

        log::debug!("Guest RSP: {:#018x}, Guest RIP: {:#018x}", guest_registers.rsp, guest_registers.rip);

        // ---------------------------------------------------------------------
        // IA32_EFER: must be consistent with IA32E_MODE_GUEST entry controls
        // ---------------------------------------------------------------------
        //
        // TEMPORARY DEBUG: Disable long mode to test 32-bit protected mode
        let mut guest_efer = rdmsr(msr::IA32_EFER);
        guest_efer &= !(1 << 8); // Clear LME (Long Mode Enable)
        guest_efer &= !(1 << 10); // Clear LMA (Long Mode Active)
        vmwrite(vmcs::guest::IA32_EFER_FULL, guest_efer);

        log::debug!("Guest EFER (32-bit mode): {:#018x}", guest_efer);

        // ---------------------------------------------------------------------
        // Segment selectors
        // ---------------------------------------------------------------------
        // CRITICAL FIX: Use selector 0x0008 for CS (index 1) instead of 0x0018
        // Index 1 is more likely to be a valid code segment in the UEFI GDT
        vmwrite(vmcs::guest::CS_SELECTOR, 0x0008u16); // Use index 1 instead of current CS
        vmwrite(vmcs::guest::SS_SELECTOR, 0x0010u16); // Use index 2 for SS (data segment)
        vmwrite(vmcs::guest::DS_SELECTOR, 0x0010u16);
        vmwrite(vmcs::guest::ES_SELECTOR, 0x0010u16);
        vmwrite(vmcs::guest::FS_SELECTOR, 0x0010u16);
        vmwrite(vmcs::guest::GS_SELECTOR, 0x0010u16);

        vmwrite(vmcs::guest::LDTR_SELECTOR, 0u16);
        // For 32-bit mode, TR can be 0 with unrestricted guest
        vmwrite(vmcs::guest::TR_SELECTOR, 0u16);

        // All segment base registers are zero for flat model
        vmwrite(vmcs::guest::TR_BASE, 0u64);

        // ---------------------------------------------------------------------
        // Segment limits - use flat 4GB limit for 32-bit mode
        // ---------------------------------------------------------------------
        vmwrite(vmcs::guest::CS_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::SS_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::DS_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::ES_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::FS_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::GS_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::LDTR_LIMIT, 0u32);
        vmwrite(vmcs::guest::TR_LIMIT, 0x67u32); // Minimum size for 32-bit TSS

        // ---------------------------------------------------------------------
        // Segment access rights - manually set for 32-bit protected mode
        // ---------------------------------------------------------------------
        // CS: 32-bit code segment (type=0xB, present, DPL=0, G=1, D/B=1)
        // Type 0xB = Execute/Read, accessed, conforming
        vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, 0xC09B as u64); // Present, DPL=0, Code, G=1, D/B=1

        // Data segments: 32-bit data segment (type=0x3, present, DPL=0, G=1, D/B=1)
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, 0xC093 as u64); // Present, DPL=0, Data, G=1, D/B=1
        vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, 0xC093 as u64);
        vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, 0xC093 as u64);
        vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, 0xC093 as u64);
        vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, 0xC093 as u64);
        vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, 0x10000 as u64); // Unusable
        vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, 0x8B as u64); // 32-bit TSS (busy)

        // ---------------------------------------------------------------------
        // Descriptor tables
        // ---------------------------------------------------------------------
        vmwrite(vmcs::guest::GDTR_BASE, guest_descriptor.gdtr.base as u64);
        vmwrite(vmcs::guest::GDTR_LIMIT, guest_descriptor.gdtr.limit as u64);

        // Guest IDTR: Use the host's IDT for now since we're in unrestricted guest mode
        // This prevents triple faults by ensuring valid exception handlers exist
        let host_idtr = sidt();
        vmwrite(vmcs::guest::IDTR_BASE, host_idtr.base as u64);
        vmwrite(vmcs::guest::IDTR_LIMIT, host_idtr.limit as u64);

        // Guest SYSENTER MSRs - must be initialized!
        vmwrite(vmcs::guest::IA32_SYSENTER_CS, 0u64);
        vmwrite(vmcs::guest::IA32_SYSENTER_ESP, 0u64);
        vmwrite(vmcs::guest::IA32_SYSENTER_EIP, 0u64);

        // No VMCS shadowing in use
        vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX);

        // Guest interruptibility state - must be initialized!
        // Set to 0 (no blocking conditions)
        vmwrite(vmcs::guest::INTERRUPTIBILITY_STATE, 0u32);

        // Guest activity state - 0 = Active
        vmwrite(vmcs::guest::ACTIVITY_STATE, 0u32);

        // Guest pending debug exceptions - must be 0
        vmwrite(vmcs::guest::PENDING_DBG_EXCEPTIONS, 0u64);

        log::debug!("Guest Registers State setup successfully!");
    }

    /// Initialize the host state for the currently loaded VMCS.
    ///
    /// The method sets up various host state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.5 HOST-STATE AREA.
    ///
    /// # Arguments
    /// * `host_descriptor` - Descriptor tables for the host.
    /// * `pml4_pa` - Physical address of the host PML4 for CR3.
    pub fn setup_host_registers_state(host_descriptor: &Descriptors, pml4_pa: u64) -> Result<(), HypervisorError> {
        log::debug!("Setting up Host Registers State");

        let host_idtr = sidt();

        // ---------------------------------------------------------------------
        // Host Control Registers (MANDATORY)
        // ---------------------------------------------------------------------
        // These MUST match the current CPU state with VMXE enabled
        vmwrite(vmcs::host::CR0, Cr0::read_raw());
        vmwrite(vmcs::host::CR3, pml4_pa);
        vmwrite(vmcs::host::CR4, Cr4::read_raw());

        // ---------------------------------------------------------------------
        // Host RSP and RIP (MANDATORY)
        // ---------------------------------------------------------------------
        // RIP: Must point to the VM-exit handler
        // The vmexit_handler is defined in vmexit.rs as a naked function
        // that handles VM exits and returns control back to Rust code.
        //
        // NOTE: If you don't have a vmexit_handler function yet, you need to create one.
        // For now, we'll use a placeholder that you MUST replace with your actual handler.

        // Host RIP must point to the VM-exit handler
        // This assembly function will be called when a VM-exit occurs
        unsafe extern "C" {
            fn vmexit_handler();
        }
        vmwrite(vmcs::host::RIP, vmexit_handler as u64);

        // Host RSP will be set dynamically in the launch_vm assembly code
        // before executing VMLAUNCH/VMRESUME
        // NOTE: We do NOT set it here - the assembly stub in vmlaunch.rs
        // sets it to the current stack pointer right before VMLAUNCH/VMRESUME
        // This ensures we have a valid stack when VM-exit occurs
        // DO NOT write 0 or any static value here!

        // ---------------------------------------------------------------------
        // Host Segment Selectors (MANDATORY)
        // ---------------------------------------------------------------------
        // CS and TR must use the NEW host GDT selectors
        // SS, DS, ES, FS, GS should be set to valid selectors (or 0 with proper handling)
        vmwrite(vmcs::host::CS_SELECTOR, host_descriptor.cs.bits());
        vmwrite(vmcs::host::SS_SELECTOR, host_descriptor.cs.bits()); // Use same as CS for simplicity
        vmwrite(vmcs::host::DS_SELECTOR, host_descriptor.cs.bits()); // Use same as CS for simplicity
        vmwrite(vmcs::host::ES_SELECTOR, host_descriptor.cs.bits()); // Use same as CS for simplicity
        vmwrite(vmcs::host::FS_SELECTOR, 0u16); // FS can be 0 if FS_BASE is set
        vmwrite(vmcs::host::GS_SELECTOR, 0u16); // GS can be 0 if GS_BASE is set
        vmwrite(vmcs::host::TR_SELECTOR, host_descriptor.tr.bits());

        // ---------------------------------------------------------------------
        // Host Segment Base Addresses (MANDATORY for FS, GS, TR, GDTR, IDTR)
        // ---------------------------------------------------------------------
        // Read current FS and GS base addresses from MSRs
        let host_fs_base = rdmsr(msr::IA32_FS_BASE);
        let host_gs_base = rdmsr(msr::IA32_GS_BASE);

        vmwrite(vmcs::host::FS_BASE, host_fs_base);
        vmwrite(vmcs::host::GS_BASE, host_gs_base);
        vmwrite(vmcs::host::TR_BASE, host_descriptor.tss.base);
        vmwrite(vmcs::host::GDTR_BASE, host_descriptor.gdtr.base as u64);
        vmwrite(vmcs::host::IDTR_BASE, host_idtr.base as u64);

        // ---------------------------------------------------------------------
        // Host SYSENTER MSRs (MANDATORY)
        // ---------------------------------------------------------------------
        // These must be set even if not used
        let host_sysenter_cs = rdmsr(msr::IA32_SYSENTER_CS);
        let host_sysenter_esp = rdmsr(msr::IA32_SYSENTER_ESP);
        let host_sysenter_eip = rdmsr(msr::IA32_SYSENTER_EIP);

        vmwrite(vmcs::host::IA32_SYSENTER_CS, host_sysenter_cs);
        vmwrite(vmcs::host::IA32_SYSENTER_ESP, host_sysenter_esp);
        vmwrite(vmcs::host::IA32_SYSENTER_EIP, host_sysenter_eip);

        // ---------------------------------------------------------------------
        // Host IA32_EFER (CONDITIONAL - required if loading on VM-exit is enabled)
        // ---------------------------------------------------------------------
        // Since we set HOST_ADDRESS_SPACE_SIZE (bit 9) in exit controls,
        // we should also load IA32_EFER on VM-exit
        let host_efer = rdmsr(msr::IA32_EFER);
        vmwrite(vmcs::host::IA32_EFER_FULL, host_efer);

        log::debug!("Host Registers State setup successfully!");

        Ok(())
    }

    /// Initialize the VMCS control values for the currently loaded VMCS.
    ///
    /// The method sets up various VMX control fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual sections:
    /// - 25.6 VM-EXECUTION CONTROL FIELDS
    /// - 25.7 VM-EXIT CONTROL FIELDS
    /// - 25.8 VM-ENTRY CONTROL FIELDS
    ///
    /// # Arguments
    ///
    /// * `primary_eptp` - The EPTP value for the primary EPT.
    /// * `msr_bitmap` - The physical address of the MSR bitmap.
    ///
    /// # Returns
    ///
    /// * `Result<(), HypervisorError>` - A result indicating the success or failure of the operation.
    pub fn setup_vmcs_control_fields(primary_eptp: u64, msr_bitmap: u64) -> Result<(), HypervisorError> {
        log::debug!("Setting up VMCS Control Fields");

        const PRIMARY_CTL: u64 =
            (vmcs::control::PrimaryControls::SECONDARY_CONTROLS.bits() | vmcs::control::PrimaryControls::USE_MSR_BITMAPS.bits()) as u64;

        const SECONDARY_CTL: u64 = (vmcs::control::SecondaryControls::ENABLE_RDTSCP.bits()
            | vmcs::control::SecondaryControls::ENABLE_XSAVES_XRSTORS.bits()
            | vmcs::control::SecondaryControls::ENABLE_INVPCID.bits()
            | vmcs::control::SecondaryControls::ENABLE_VPID.bits()
            | vmcs::control::SecondaryControls::ENABLE_EPT.bits()
            | vmcs::control::SecondaryControls::CONCEAL_VMX_FROM_PT.bits()
            | vmcs::control::SecondaryControls::UNRESTRICTED_GUEST.bits()) as u64;

        const ENTRY_CTL: u64 =
            (vmcs::control::EntryControls::LOAD_DEBUG_CONTROLS.bits() | vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits()) as u64;
        // NOTE: IA32E_MODE_GUEST is NOT set - we're testing 32-bit mode

        const EXIT_CTL: u64 = (vmcs::control::ExitControls::HOST_ADDRESS_SPACE_SIZE.bits()
            | vmcs::control::ExitControls::SAVE_DEBUG_CONTROLS.bits()
            | vmcs::control::ExitControls::LOAD_IA32_EFER.bits()
            | vmcs::control::ExitControls::CONCEAL_VMX_FROM_PT.bits()) as u64;

        const PINBASED_CTL: u64 = 0;

        vmwrite(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased, PRIMARY_CTL));
        vmwrite(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased2, SECONDARY_CTL));
        vmwrite(vmcs::control::VMENTRY_CONTROLS, adjust_vmx_controls(VmxControl::VmEntry, ENTRY_CTL));
        vmwrite(vmcs::control::VMEXIT_CONTROLS, adjust_vmx_controls(VmxControl::VmExit, EXIT_CTL));
        vmwrite(vmcs::control::PINBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL));

        let vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };

        let vmx_cr4_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let vmx_cr4_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };

        // Credits to @vmctx
        vmwrite(
            vmcs::control::CR0_GUEST_HOST_MASK,
            vmx_cr0_fixed0 | !vmx_cr0_fixed1 | Cr0Flags::CACHE_DISABLE.bits() | Cr0Flags::WRITE_PROTECT.bits(),
        );
        vmwrite(vmcs::control::CR4_GUEST_HOST_MASK, vmx_cr4_fixed0 | !vmx_cr4_fixed1);

        vmwrite(vmcs::control::CR0_READ_SHADOW, Cr0::read_raw());
        vmwrite(vmcs::control::CR4_READ_SHADOW, Cr4::read_raw() & !Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits());

        vmwrite(vmcs::control::MSR_BITMAPS_ADDR_FULL, msr_bitmap);
        vmwrite(vmcs::control::EXCEPTION_BITMAP, 0u32); // No exceptions intercepted for now

        // VM-entry interrupt information - must be 0 for normal entry
        // These fields control event injection on VM entry
        // For now, we don't inject any events, so set them all to 0

        vmwrite(vmcs::control::EPTP_FULL, primary_eptp);
        vmwrite(vmcs::control::VPID, VPID_TAG);

        invept_single_context(primary_eptp);
        invvpid_single_context(VPID_TAG);

        log::debug!("VMCS Control Fields setup successfully!");

        Ok(())
    }
}

/// Debug implementation to dump the VMCS fields.
impl fmt::Debug for Vmcs {
    /// Formats the VMCS for display.
    ///
    /// # Arguments
    /// * `format` - Formatter instance.
    ///
    /// # Returns
    /// Formatting result.
    fn fmt(&self, format: &mut fmt::Formatter<'_>) -> fmt::Result {
        format
            .debug_struct("Vmcs")
            .field("Current VMCS: ", &(self as *const _))
            .field("Revision ID: ", &self.revision_id)
            /* VMCS Guest state fields */
            .field("Guest CR0: ", &vmread(vmcs::guest::CR0))
            .field("Guest CR3: ", &vmread(vmcs::guest::CR3))
            .field("Guest CR4: ", &vmread(vmcs::guest::CR4))
            .field("Guest DR7: ", &vmread(vmcs::guest::DR7))
            .field("Guest RSP: ", &vmread(vmcs::guest::RSP))
            .field("Guest RIP: ", &vmread(vmcs::guest::RIP))
            .field("Guest RFLAGS: ", &vmread(vmcs::guest::RFLAGS))
            .field("Guest CS Selector: ", &vmread(vmcs::guest::CS_SELECTOR))
            .field("Guest SS Selector: ", &vmread(vmcs::guest::SS_SELECTOR))
            .field("Guest DS Selector: ", &vmread(vmcs::guest::DS_SELECTOR))
            .field("Guest ES Selector: ", &vmread(vmcs::guest::ES_SELECTOR))
            .field("Guest FS Selector: ", &vmread(vmcs::guest::FS_SELECTOR))
            .field("Guest GS Selector: ", &vmread(vmcs::guest::GS_SELECTOR))
            .field("Guest LDTR Selector: ", &vmread(vmcs::guest::LDTR_SELECTOR))
            .field("Guest TR Selector: ", &vmread(vmcs::guest::TR_SELECTOR))
            .field("Guest CS Base: ", &vmread(vmcs::guest::CS_BASE))
            .field("Guest SS Base: ", &vmread(vmcs::guest::SS_BASE))
            .field("Guest DS Base: ", &vmread(vmcs::guest::DS_BASE))
            .field("Guest ES Base: ", &vmread(vmcs::guest::ES_BASE))
            .field("Guest FS Base: ", &vmread(vmcs::guest::FS_BASE))
            .field("Guest GS Base: ", &vmread(vmcs::guest::GS_BASE))
            .field("Guest LDTR Base: ", &vmread(vmcs::guest::LDTR_BASE))
            .field("Guest TR Base: ", &vmread(vmcs::guest::TR_BASE))
            .field("Guest CS Limit: ", &vmread(vmcs::guest::CS_LIMIT))
            .field("Guest SS Limit: ", &vmread(vmcs::guest::SS_LIMIT))
            .field("Guest DS Limit: ", &vmread(vmcs::guest::DS_LIMIT))
            .field("Guest ES Limit: ", &vmread(vmcs::guest::ES_LIMIT))
            .field("Guest FS Limit: ", &vmread(vmcs::guest::FS_LIMIT))
            .field("Guest GS Limit: ", &vmread(vmcs::guest::GS_LIMIT))
            .field("Guest LDTR Limit: ", &vmread(vmcs::guest::LDTR_LIMIT))
            .field("Guest TR Limit: ", &vmread(vmcs::guest::TR_LIMIT))
            .field("Guest CS Access Rights: ", &vmread(vmcs::guest::CS_ACCESS_RIGHTS))
            .field("Guest SS Access Rights: ", &vmread(vmcs::guest::SS_ACCESS_RIGHTS))
            .field("Guest DS Access Rights: ", &vmread(vmcs::guest::DS_ACCESS_RIGHTS))
            .field("Guest ES Access Rights: ", &vmread(vmcs::guest::ES_ACCESS_RIGHTS))
            .field("Guest FS Access Rights: ", &vmread(vmcs::guest::FS_ACCESS_RIGHTS))
            .field("Guest GS Access Rights: ", &vmread(vmcs::guest::GS_ACCESS_RIGHTS))
            .field("Guest LDTR Access Rights: ", &vmread(vmcs::guest::LDTR_ACCESS_RIGHTS))
            .field("Guest TR Access Rights: ", &vmread(vmcs::guest::TR_ACCESS_RIGHTS))
            .field("Guest GDTR Base: ", &vmread(vmcs::guest::GDTR_BASE))
            .field("Guest IDTR Base: ", &vmread(vmcs::guest::IDTR_BASE))
            .field("Guest GDTR Limit: ", &vmread(vmcs::guest::GDTR_LIMIT))
            .field("Guest IDTR Limit: ", &vmread(vmcs::guest::IDTR_LIMIT))
            .field("Guest IA32_DEBUGCTL_FULL: ", &vmread(vmcs::guest::IA32_DEBUGCTL_FULL))
            .field("Guest IA32_SYSENTER_CS: ", &vmread(vmcs::guest::IA32_SYSENTER_CS))
            .field("Guest IA32_SYSENTER_ESP: ", &vmread(vmcs::guest::IA32_SYSENTER_ESP))
            .field("Guest IA32_SYSENTER_EIP: ", &vmread(vmcs::guest::IA32_SYSENTER_EIP))
            .field("Guest IA32_EFER_FULL: ", &vmread(vmcs::guest::IA32_EFER_FULL))
            .field("Guest VMCS Link Pointer: ", &vmread(vmcs::guest::LINK_PTR_FULL))
            .field("Guest Activity State: ", &vmread(vmcs::guest::ACTIVITY_STATE))
            /* VMCS Host state fields */
            .field("Host CR0: ", &vmread(vmcs::host::CR0))
            .field("Host CR3: ", &vmread(vmcs::host::CR3))
            .field("Host CR4: ", &vmread(vmcs::host::CR4))
            .field("Host RSP: ", &vmread(vmcs::host::RSP))
            .field("Host RIP: ", &vmread(vmcs::host::RIP))
            .field("Host CS Selector: ", &vmread(vmcs::host::CS_SELECTOR))
            .field("Host SS Selector: ", &vmread(vmcs::host::SS_SELECTOR))
            .field("Host DS Selector: ", &vmread(vmcs::host::DS_SELECTOR))
            .field("Host ES Selector: ", &vmread(vmcs::host::ES_SELECTOR))
            .field("Host FS Selector: ", &vmread(vmcs::host::FS_SELECTOR))
            .field("Host GS Selector: ", &vmread(vmcs::host::GS_SELECTOR))
            .field("Host TR Selector: ", &vmread(vmcs::host::TR_SELECTOR))
            .field("Host FS Base: ", &vmread(vmcs::host::FS_BASE))
            .field("Host GS Base: ", &vmread(vmcs::host::GS_BASE))
            .field("Host TR Base: ", &vmread(vmcs::host::TR_BASE))
            .field("Host GDTR Base: ", &vmread(vmcs::host::GDTR_BASE))
            .field("Host IDTR Base: ", &vmread(vmcs::host::IDTR_BASE))
            .field("Host IA32_SYSENTER_CS: ", &vmread(vmcs::host::IA32_SYSENTER_CS))
            .field("Host IA32_SYSENTER_ESP: ", &vmread(vmcs::host::IA32_SYSENTER_ESP))
            .field("Host IA32_SYSENTER_EIP: ", &vmread(vmcs::host::IA32_SYSENTER_EIP))
            .field("Host IA32_EFER_FULL: ", &vmread(vmcs::host::IA32_EFER_FULL))
            /* VMCS Control fields */
            .field("Primary Proc Based Execution Controls: ", &vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS))
            .field("Secondary Proc Based Execution Controls: ", &vmread(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS))
            .field("VM Entry Controls: ", &vmread(vmcs::control::VMENTRY_CONTROLS))
            .field("VM Exit Controls: ", &vmread(vmcs::control::VMEXIT_CONTROLS))
            .field("Pin Based Execution Controls: ", &vmread(vmcs::control::PINBASED_EXEC_CONTROLS))
            .field("CR0 Read Shadow: ", &vmread(vmcs::control::CR0_READ_SHADOW))
            .field("CR4 Read Shadow: ", &vmread(vmcs::control::CR4_READ_SHADOW))
            .field("MSR Bitmaps Address: ", &vmread(vmcs::control::MSR_BITMAPS_ADDR_FULL))
            .field("EPT Pointer: ", &vmread(vmcs::control::EPTP_FULL))
            .field("VPID: ", &vmread(vmcs::control::VPID))
            .finish_non_exhaustive()
    }
}
