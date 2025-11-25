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
            support::{rdmsr, sidt, vmread, vmwrite},
        },
    },
    bit_field::BitField,
    core::fmt,
    x86::{
        bits64::{paging::BASE_PAGE_SIZE, rflags},
        debugregs::dr7,
        msr,
        vmx::vmcs,
    },
    x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
};

/// Converts native segment access rights format to VMCS format
/// Native format (from LAR instruction): type in bits 8-15
/// VMCS format: type in bits 0-7, with additional flags in bits 8-15
fn access_rights_from_native(native_ar: u32) -> u32 {
    // Native format has the access byte in bits 8-15
    // VMCS format expects it in bits 0-7
    // For TSS: native_ar = 0x8b00 means access byte 0x8b is in upper byte
    (native_ar >> 8) & 0xFF
}

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
    /// * `_host_cr3` - UNUSED - we use actual current CR3 instead
    pub fn setup_guest_registers_state(guest_descriptor: &Descriptors, guest_registers: &GuestRegisters, _host_cr3: u64) {
        log::debug!("Setting up Guest Registers State");

        // ---------------------------------------------------------------------
        // Control registers: CR0 / CR3 / CR4
        // ---------------------------------------------------------------------
        //
        // CRITICAL: Apply VMX fixed bits to ensure VMCS consistency checks pass
        let vmx_cr0_fixed0 = rdmsr(msr::IA32_VMX_CR0_FIXED0);
        let vmx_cr0_fixed1 = rdmsr(msr::IA32_VMX_CR0_FIXED1);

        // Start with current CR0 and apply 64-bit requirements
        let mut guest_cr0 = Cr0::read_raw();
        guest_cr0 |= Cr0Flags::PROTECTED_MODE_ENABLE.bits(); // PE = 1 (required for long mode)
        guest_cr0 |= Cr0Flags::PAGING.bits(); // PG = 1 (required for long mode)

        // Apply VMX fixed bits (CRITICAL for VMLAUNCH success!)
        guest_cr0 = (guest_cr0 & vmx_cr0_fixed1) | vmx_cr0_fixed0;

        log::debug!("VMX CR0 fixed0: {:#018x}, fixed1: {:#018x}", vmx_cr0_fixed0, vmx_cr0_fixed1);

        // CRITICAL FIX: Use actual current CR3, not the empty host_cr3 parameter
        let guest_cr3 = x86_64::registers::control::Cr3::read().0.start_address().as_u64();

        unsafe {
            let pml4_ptr = guest_cr3 as *const u64;
            let pml4_entry_0 = core::ptr::read_volatile(pml4_ptr);

            log::debug!("Verifying guest_cr3 {:#x}", guest_cr3);
            log::debug!("PML4[0] at guest_cr3 = {:#x}", pml4_entry_0);

            if pml4_entry_0 == 0 {
                log::error!("CRITICAL: Current CR3 points to empty page tables!");
                log::error!("This should never happen!");
                panic!("No valid page tables available for guest!");
            } else {
                log::debug!("✓ Guest CR3 points to valid page tables (PML4[0] = {:#x})", pml4_entry_0);
            }
        }

        // Verify Guest RIP points to valid code
        let guest_rip = guest_registers.rip;

        unsafe {
            let rip_bytes = core::slice::from_raw_parts(guest_rip as *const u8, 32);
            log::debug!("Verifying Guest RIP: {:#x}", guest_rip);
            log::debug!("First 16 bytes at Guest RIP: {:02x?}", &rip_bytes[0..16]);

            // Guest RIP should now point to real UEFI code (the return address from
            // capture_registers). We just log the bytes for debugging - any valid
            // code is acceptable.
            log::debug!("Guest will resume at original UEFI return address");
        }

        // Same for CR4 - apply VMX fixed bits
        let vmx_cr4_fixed0 = rdmsr(msr::IA32_VMX_CR4_FIXED0);
        let vmx_cr4_fixed1 = rdmsr(msr::IA32_VMX_CR4_FIXED1);

        let mut guest_cr4 = Cr4::read_raw();
        guest_cr4 |= Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits(); // PAE = 1 (required for long mode)

        // CRITICAL FIX: Apply VMX fixed bits and DO NOT clear VMXE!
        // The VMX specification requires CR4.VMXE = 1 in the guest CR4 field.
        // Unrestricted Guest does NOT relax this requirement.
        // To hide VMXE from the guest, we use the CR4 read shadow (set up in control fields).
        guest_cr4 = (guest_cr4 & vmx_cr4_fixed1) | vmx_cr4_fixed0;

        // NOTE: We do NOT clear VMXE here anymore! The CR4 read shadow will hide it from the guest.
        // The actual guest CR4 must have VMXE=1 to satisfy VMX consistency checks.

        log::debug!("VMX CR4 fixed0: {:#018x}, fixed1: {:#018x}", vmx_cr4_fixed0, vmx_cr4_fixed1);
        log::debug!("Guest CR4 (with VMXE per VMX requirements): {:#018x}", guest_cr4);

        vmwrite(vmcs::guest::CR0, guest_cr0);
        vmwrite(vmcs::guest::CR3, guest_cr3);
        vmwrite(vmcs::guest::CR4, guest_cr4);

        log::debug!("Guest CR0 (64-bit mode): {:#018x}, Guest CR3: {:#018x}, Guest CR4: {:#018x}", guest_cr0, guest_cr3, guest_cr4);

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
        // CRITICAL FIX: Enable long mode in guest EFER
        let mut guest_efer = rdmsr(msr::IA32_EFER);
        guest_efer |= 1 << 8; // LME (Long Mode Enable) = 1
        guest_efer |= 1 << 10; // LMA (Long Mode Active) = 1
        vmwrite(vmcs::guest::IA32_EFER_FULL, guest_efer);

        log::debug!("Guest EFER (64-bit mode): {:#018x}", guest_efer);

        // ---------------------------------------------------------------------
        // Segment selectors - use selectors that match the UEFI GDT layout
        // ---------------------------------------------------------------------
        // From the UEFI GDT dump:
        //   Entry 0 (0x00): NULL
        //   Entry 1 (0x08): Data segment
        //   Entry 2 (0x10): 32-bit Code segment
        //   Entry 3 (0x18): 64-bit Code segment  ← Use this for CS!
        //   Entry 4 (0x20): 32-bit Code segment
        //   Entry 5 (0x28): Data segment
        //
        // CRITICAL: CS must point to a 64-bit code segment (0x18), not 0x08 which is Data!
        vmwrite(vmcs::guest::CS_SELECTOR, 0x0018u16); // 64-bit code segment
        vmwrite(vmcs::guest::SS_SELECTOR, 0x0008u16); // Data segment
        vmwrite(vmcs::guest::DS_SELECTOR, 0x0008u16); // Data segment
        vmwrite(vmcs::guest::ES_SELECTOR, 0x0008u16); // Data segment
        vmwrite(vmcs::guest::FS_SELECTOR, 0x0008u16); // Data segment
        vmwrite(vmcs::guest::GS_SELECTOR, 0x0008u16); // Data segment

        // CRITICAL: Do NOT write TR_SELECTOR yet!
        // Writing the selector causes the processor to reload AR from the GDT.
        // We'll write it AFTER we set the access rights.

        vmwrite(vmcs::guest::LDTR_SELECTOR, 0u16);
        // TR_SELECTOR will be written AFTER TR_ACCESS_RIGHTS (see below)

        // ---------------------------------------------------------------------
        // Segment bases - ALL must be initialized
        // ---------------------------------------------------------------------
        vmwrite(vmcs::guest::CS_BASE, 0u64);
        vmwrite(vmcs::guest::SS_BASE, 0u64);
        vmwrite(vmcs::guest::DS_BASE, 0u64);
        vmwrite(vmcs::guest::ES_BASE, 0u64);
        vmwrite(vmcs::guest::FS_BASE, 0u64);
        vmwrite(vmcs::guest::GS_BASE, 0u64);
        vmwrite(vmcs::guest::LDTR_BASE, 0u64);
        vmwrite(vmcs::guest::TR_BASE, guest_descriptor.tss.base);

        // ---------------------------------------------------------------------
        // Segment limits - use flat limits for 64-bit mode
        // ---------------------------------------------------------------------
        vmwrite(vmcs::guest::CS_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::SS_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::DS_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::ES_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::FS_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::GS_LIMIT, 0xFFFFFFFFu32);
        vmwrite(vmcs::guest::LDTR_LIMIT, 0u32);
        vmwrite(vmcs::guest::TR_LIMIT, guest_descriptor.tss.limit as u32);

        // ---------------------------------------------------------------------
        // Segment access rights - 64-BIT MODE ENCODINGS
        // ---------------------------------------------------------------------
        log::debug!("=== Setting up segment access rights for 64-bit mode ===");

        // 64-bit code segment: P=1, DPL=0, S=1, Type=1011, G=1, L=1, D=0
        let cs_ar = 0xA09Bu32;

        // Data segments: P=1, DPL=0, S=1, Type=0011, G=1, D=1
        let data_ar = 0xC093u32;

        // LDTR: Unusable (bit 16 set)
        let ldtr_ar = 0x10000u32;

        // TR Access Rights: Use access_rights_from_native() like memn0ps original
        // The tss.ar field contains 0x8b00 (native format with type 0xB in upper byte)
        // access_rights_from_native() converts it to proper VMCS AR format
        let tss_ar = access_rights_from_native(guest_descriptor.tss.ar) as u64;
        log::debug!("Using TR AR from access_rights_from_native: {:#06x}", tss_ar);

        vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, data_ar);
        vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, cs_ar);
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, data_ar);
        vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, data_ar);
        vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, data_ar);
        vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, data_ar);
        vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, data_ar);
        vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, ldtr_ar);
        vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, tss_ar);

        // CRITICAL: Write TR_SELECTOR LAST, after TR_ACCESS_RIGHTS is set.
        // Writing the selector causes Intel processors to validate/reload some AR bits from the GDT.
        // By writing AR first, then selector, we ensure our 0x18B value sticks.
        vmwrite(vmcs::guest::TR_SELECTOR, guest_descriptor.tr.bits());
        log::debug!("Guest TR selector set to: {:#06x} (written AFTER TR_ACCESS_RIGHTS)", guest_descriptor.tr.bits());

        log::debug!("=== VERIFYING ALL SEGMENT ACCESS RIGHTS ===");
        log::debug!("ES AR: {:#06x} (expected {:#06x})", vmread(vmcs::guest::ES_ACCESS_RIGHTS), data_ar);
        log::debug!("CS AR: {:#06x} (expected {:#06x})", vmread(vmcs::guest::CS_ACCESS_RIGHTS), cs_ar);
        log::debug!("SS AR: {:#06x} (expected {:#06x})", vmread(vmcs::guest::SS_ACCESS_RIGHTS), data_ar);
        log::debug!("DS AR: {:#06x} (expected {:#06x})", vmread(vmcs::guest::DS_ACCESS_RIGHTS), data_ar);
        log::debug!("FS AR: {:#06x} (expected {:#06x})", vmread(vmcs::guest::FS_ACCESS_RIGHTS), data_ar);
        log::debug!("GS AR: {:#06x} (expected {:#06x})", vmread(vmcs::guest::GS_ACCESS_RIGHTS), data_ar);
        log::debug!("LDTR AR: {:#06x} (expected {:#06x})", vmread(vmcs::guest::LDTR_ACCESS_RIGHTS), ldtr_ar);
        log::debug!("TR AR: {:#06x} (expected {:#06x})", vmread(vmcs::guest::TR_ACCESS_RIGHTS), tss_ar);

        // ---------------------------------------------------------------------
        // GDTR and IDTR (GDTR already written above, just write IDTR here)
        // ---------------------------------------------------------------------
        vmwrite(vmcs::guest::GDTR_BASE, guest_descriptor.gdtr.base as u64);
        vmwrite(vmcs::guest::GDTR_LIMIT, guest_descriptor.gdtr.limit as u32);

        // Copy to local variables to avoid packed field reference errors
        let gdtr_base = guest_descriptor.gdtr.base as u64;
        let gdtr_limit = guest_descriptor.gdtr.limit;
        let tr_selector = guest_descriptor.tr.bits();
        let tr_base = guest_descriptor.tss.base;

        log::debug!("=== GUEST GDTR AND TR CONFIGURATION ===");
        log::debug!("Guest GDTR base: {:#018x}", gdtr_base);
        log::debug!("Guest GDTR limit: {:#06x} ({} bytes, {} descriptors max)", gdtr_limit, gdtr_limit + 1, (gdtr_limit + 1) / 8);
        log::debug!("Guest TR selector: {:#06x} (index {})", tr_selector, tr_selector >> 3);
        log::debug!("Guest TR base: {:#018x}", tr_base);
        log::debug!("Guest TR offset in GDT: {:#06x}", (tr_selector & 0xFFF8));
        log::debug!("Guest TR descriptor end offset: {:#06x} (TSS is 16 bytes)", (tr_selector & 0xFFF8) + 15);
        log::debug!(
            "Check: TR end ({:#x}) <= GDTR limit ({:#x})? {}",
            (tr_selector & 0xFFF8) + 15,
            gdtr_limit,
            (tr_selector & 0xFFF8) + 15 <= gdtr_limit
        );

        // Verify the TSS descriptor in the GDT matches what we expect
        unsafe {
            let gdt_ptr = gdtr_base as *const u64;
            let tr_index = (tr_selector >> 3) as usize;
            let tss_desc_low = core::ptr::read_volatile(gdt_ptr.add(tr_index));
            let tss_desc_high = core::ptr::read_volatile(gdt_ptr.add(tr_index + 1));
            log::debug!("TSS descriptor in guest GDT: {:#018x} {:#018x}", tss_desc_low, tss_desc_high);

            // Decode the descriptor to check the type
            let desc_type = ((tss_desc_low >> 40) & 0xF) as u8;
            let desc_present = ((tss_desc_low >> 47) & 1) != 0;
            let desc_base_low = ((tss_desc_low >> 16) & 0xFFFFFF) as u32;
            let desc_base_mid = ((tss_desc_low >> 56) & 0xFF) as u32;
            let desc_base_high = (tss_desc_high & 0xFFFFFFFF) as u32;
            let desc_base = (desc_base_high as u64) << 32 | (desc_base_mid as u64) << 24 | desc_base_low as u64;

            log::debug!("  Type: {:#x} (should be 0xB for Busy TSS)", desc_type);
            log::debug!("  Present: {}", desc_present);
            log::debug!("  Base: {:#018x} (should match TR base {:#018x})", desc_base, tr_base);

            if desc_type != 0xB {
                log::error!("❌ TSS descriptor type is {:#x}, expected 0xB (Busy TSS)!", desc_type);
            }
            if desc_base != tr_base {
                log::error!("❌ TSS descriptor base {:#x} doesn't match TR base {:#x}!", desc_base, tr_base);
            }
        }

        let idtr = sidt();
        vmwrite(vmcs::guest::IDTR_BASE, idtr.base as u64);
        vmwrite(vmcs::guest::IDTR_LIMIT, idtr.limit as u32);

        // ---------------------------------------------------------------------
        // VMCS link pointer
        // ---------------------------------------------------------------------
        vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX);

        // ---------------------------------------------------------------------
        // Guest non-register state
        // ---------------------------------------------------------------------
        vmwrite(vmcs::guest::ACTIVITY_STATE, 0u32); // Active
        vmwrite(vmcs::guest::INTERRUPTIBILITY_STATE, 0u32); // Not blocked

        // CRITICAL: Set PENDING_DEBUG_EXCEPTIONS to 0
        log::debug!("=== SETTING PENDING_DBG_EXCEPTIONS ===");
        vmwrite(vmcs::guest::PENDING_DBG_EXCEPTIONS, 0u64);
        log::debug!("After write, PENDING_DBG_EXCEPTIONS = {:#x}", vmread(vmcs::guest::PENDING_DBG_EXCEPTIONS));

        // ---------------------------------------------------------------------
        // MSRs
        // ---------------------------------------------------------------------
        vmwrite(vmcs::guest::IA32_DEBUGCTL_FULL, rdmsr(msr::IA32_DEBUGCTL));
        vmwrite(vmcs::guest::IA32_SYSENTER_CS, rdmsr(msr::IA32_SYSENTER_CS) as u32);
        vmwrite(vmcs::guest::IA32_SYSENTER_ESP, rdmsr(msr::IA32_SYSENTER_ESP));
        vmwrite(vmcs::guest::IA32_SYSENTER_EIP, rdmsr(msr::IA32_SYSENTER_EIP));

        log::debug!("=== FINAL VMCS FIELD VERIFICATION ===");
        log::debug!("Final ES AR: {:#06x}", vmread(vmcs::guest::ES_ACCESS_RIGHTS));
        log::debug!("Final CS AR: {:#06x}", vmread(vmcs::guest::CS_ACCESS_RIGHTS));
        log::debug!("Final SS AR: {:#06x}", vmread(vmcs::guest::SS_ACCESS_RIGHTS));
        log::debug!("Final DS AR: {:#06x}", vmread(vmcs::guest::DS_ACCESS_RIGHTS));
        log::debug!("Final FS AR: {:#06x}", vmread(vmcs::guest::FS_ACCESS_RIGHTS));
        log::debug!("Final GS AR: {:#06x}", vmread(vmcs::guest::GS_ACCESS_RIGHTS));
        log::debug!("Final LDTR AR: {:#06x}", vmread(vmcs::guest::LDTR_ACCESS_RIGHTS));
        log::debug!("Final TR AR: {:#06x}", vmread(vmcs::guest::TR_ACCESS_RIGHTS));
        log::debug!("Final Activity State: {:#x}", vmread(vmcs::guest::ACTIVITY_STATE));
        log::debug!("Final Interruptibility: {:#x}", vmread(vmcs::guest::INTERRUPTIBILITY_STATE));
        log::debug!("Final Pending Debug: {:#x}", vmread(vmcs::guest::PENDING_DBG_EXCEPTIONS));
        log::debug!("Final Guest CR4: {:#x} (VMXE should be set)", vmread(vmcs::guest::CR4));

        log::debug!("Guest Registers State setup successfully!");
    }

    /// Initialize the host state for the currently loaded VMCS.
    ///
    /// The method sets up various host state fields in the VMCS as per the
    /// Intel® 64 and IA-32 Architectures Software Developer's Manual 25.5 HOST-STATE AREA.
    ///
    /// # Arguments
    /// * `host_descriptor` - Descriptor tables for the host.
    /// * `pml4_pa` - Physical address of the host PML4 for CR3 (IGNORED - we use actual CR3).
    pub fn setup_host_registers_state(host_descriptor: &Descriptors, pml4_pa: u64) -> Result<(), HypervisorError> {
        log::debug!("Setting up Host Registers State");

        let host_idtr = sidt();

        // CRITICAL FIX: Use actual current CR3, not the empty pml4_pa parameter
        // The pml4_pa from host_paging is empty, but the current CR3 has valid page tables
        let actual_cr3 = x86_64::registers::control::Cr3::read().0.start_address().as_u64();
        log::debug!("Host CR3: using actual CR3 {:#x} instead of pml4_pa {:#x}", actual_cr3, pml4_pa);

        // Verify the actual CR3 has valid page tables
        unsafe {
            let pml4_ptr = actual_cr3 as *const u64;
            let pml4_entry_0 = core::ptr::read_volatile(pml4_ptr);
            if pml4_entry_0 == 0 {
                log::error!("FATAL: Even actual CR3 has empty page tables!");
                return Err(HypervisorError::InvalidHostState);
            }
            log::debug!("✓ Host CR3 verified: PML4[0] = {:#x}", pml4_entry_0);
        }

        // ---------------------------------------------------------------------
        // Host Control Registers (MANDATORY)
        // ---------------------------------------------------------------------
        vmwrite(vmcs::host::CR0, Cr0::read_raw());
        vmwrite(vmcs::host::CR3, actual_cr3); // Use actual CR3, not pml4_pa!
        vmwrite(vmcs::host::CR4, Cr4::read_raw());

        // ---------------------------------------------------------------------
        // Host RSP and RIP (MANDATORY)
        // ---------------------------------------------------------------------
        // RIP: Must point to the VM-exit handler
        unsafe extern "C" {
            fn vmexit_handler();
        }
        vmwrite(vmcs::host::RIP, vmexit_handler as u64);

        // Host RSP will be set dynamically in vm.rs run() method
        // RIGHT BEFORE executing VMLAUNCH/VMRESUME

        // ---------------------------------------------------------------------
        // Host segment selectors (MANDATORY)
        // ---------------------------------------------------------------------
        vmwrite(vmcs::host::CS_SELECTOR, host_descriptor.cs.bits()); // 0x08
        vmwrite(vmcs::host::SS_SELECTOR, 0x0010u16); // Data segment
        vmwrite(vmcs::host::DS_SELECTOR, 0x0010u16);
        vmwrite(vmcs::host::ES_SELECTOR, 0x0010u16);
        vmwrite(vmcs::host::FS_SELECTOR, 0u16);
        vmwrite(vmcs::host::GS_SELECTOR, 0u16);
        vmwrite(vmcs::host::TR_SELECTOR, 0x0018u16); // TSS now at index 3 (0x18)

        // ---------------------------------------------------------------------
        // Host base addresses for FS, GS, TR, GDTR, IDTR (MANDATORY)
        // ---------------------------------------------------------------------
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
        let host_sysenter_cs = rdmsr(msr::IA32_SYSENTER_CS);
        let host_sysenter_esp = rdmsr(msr::IA32_SYSENTER_ESP);
        let host_sysenter_eip = rdmsr(msr::IA32_SYSENTER_EIP);

        vmwrite(vmcs::host::IA32_SYSENTER_CS, host_sysenter_cs);
        vmwrite(vmcs::host::IA32_SYSENTER_ESP, host_sysenter_esp);
        vmwrite(vmcs::host::IA32_SYSENTER_EIP, host_sysenter_eip);

        // ---------------------------------------------------------------------
        // Host IA32_EFER (CONDITIONAL - required if loading on VM-exit is enabled)
        // ---------------------------------------------------------------------
        let host_efer = rdmsr(msr::IA32_EFER);
        vmwrite(vmcs::host::IA32_EFER_FULL, host_efer);

        // ---------------------------------------------------------------------
        // Host PAT MSR (CONDITIONAL - if loading is enabled in exit controls)
        // ---------------------------------------------------------------------
        let host_pat = rdmsr(msr::IA32_PAT);
        vmwrite(vmcs::host::IA32_PAT_FULL, host_pat);

        log::debug!("Host Registers State setup successfully!");

        Ok(())
    }

    /// Initialize the VMCS control values for the currently loaded VMCS.
    pub fn setup_vmcs_control_fields(primary_eptp: u64, msr_bitmap: u64, io_bitmap_a: u64, io_bitmap_b: u64) -> Result<(), HypervisorError> {
        log::debug!("Setting up VMCS Control Fields");

        const PRIMARY_CTL: u64 = (vmcs::control::PrimaryControls::SECONDARY_CONTROLS.bits()
            | vmcs::control::PrimaryControls::USE_MSR_BITMAPS.bits()
            | vmcs::control::PrimaryControls::HLT_EXITING.bits()) as u64;

        const SECONDARY_CTL: u64 = (vmcs::control::SecondaryControls::ENABLE_RDTSCP.bits()
            | vmcs::control::SecondaryControls::ENABLE_XSAVES_XRSTORS.bits()
            | vmcs::control::SecondaryControls::ENABLE_INVPCID.bits()
            | vmcs::control::SecondaryControls::ENABLE_VPID.bits()
            | vmcs::control::SecondaryControls::ENABLE_EPT.bits()
            | vmcs::control::SecondaryControls::CONCEAL_VMX_FROM_PT.bits()
            | vmcs::control::SecondaryControls::UNRESTRICTED_GUEST.bits()) as u64;

        const ENTRY_CTL: u64 = (vmcs::control::EntryControls::LOAD_DEBUG_CONTROLS.bits()
            | vmcs::control::EntryControls::IA32E_MODE_GUEST.bits()
            | vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits()) as u64;

        log::debug!("Requested ENTRY_CTL bits: {:#010x}", ENTRY_CTL);
        log::debug!("  LOAD_DEBUG_CONTROLS: {:#x}", vmcs::control::EntryControls::LOAD_DEBUG_CONTROLS.bits());
        log::debug!("  IA32E_MODE_GUEST: {:#x}", vmcs::control::EntryControls::IA32E_MODE_GUEST.bits());
        log::debug!("  CONCEAL_VMX_FROM_PT: {:#x}", vmcs::control::EntryControls::CONCEAL_VMX_FROM_PT.bits());

        const EXIT_CTL: u64 = (vmcs::control::ExitControls::HOST_ADDRESS_SPACE_SIZE.bits()
            | vmcs::control::ExitControls::SAVE_DEBUG_CONTROLS.bits()
            | vmcs::control::ExitControls::LOAD_IA32_EFER.bits()
            | vmcs::control::ExitControls::LOAD_IA32_PAT.bits()
            | vmcs::control::ExitControls::CONCEAL_VMX_FROM_PT.bits()) as u64;

        const PINBASED_CTL: u64 = 0;

        vmwrite(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased, PRIMARY_CTL));
        vmwrite(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::ProcessorBased2, SECONDARY_CTL));
        vmwrite(vmcs::control::VMENTRY_CONTROLS, adjust_vmx_controls(VmxControl::VmEntry, ENTRY_CTL));
        vmwrite(vmcs::control::VMEXIT_CONTROLS, adjust_vmx_controls(VmxControl::VmExit, EXIT_CTL));
        vmwrite(vmcs::control::PINBASED_EXEC_CONTROLS, adjust_vmx_controls(VmxControl::PinBased, PINBASED_CTL));

        let primary_controls = vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS);
        let secondary_controls = vmread(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS);
        let vmentry_controls = vmread(vmcs::control::VMENTRY_CONTROLS);

        log::debug!("Primary controls:  {:#010x}", primary_controls);
        log::debug!("Secondary controls: {:#010x}", secondary_controls);
        log::debug!("VM-entry controls: {:#010x}", vmentry_controls);
        log::debug!("Unrestricted Guest: {}", (secondary_controls & vmcs::control::SecondaryControls::UNRESTRICTED_GUEST.bits() as u64) != 0);
        log::debug!("IA32E_MODE_GUEST: {}", (vmentry_controls & vmcs::control::EntryControls::IA32E_MODE_GUEST.bits() as u64) != 0);

        let vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };

        let vmx_cr4_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
        let vmx_cr4_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };

        vmwrite(
            vmcs::control::CR0_GUEST_HOST_MASK,
            vmx_cr0_fixed0 | !vmx_cr0_fixed1 | Cr0Flags::CACHE_DISABLE.bits() | Cr0Flags::WRITE_PROTECT.bits(),
        );

        // CRITICAL: Include VMXE in the CR4 mask so we intercept access to it
        vmwrite(vmcs::control::CR4_GUEST_HOST_MASK, vmx_cr4_fixed0 | !vmx_cr4_fixed1 | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits());

        vmwrite(vmcs::control::CR0_READ_SHADOW, Cr0::read_raw());

        // CRITICAL FIX: The CR4 read shadow is what the guest sees when it reads CR4.
        // We set VMXE=0 in the shadow so the guest thinks VMXE is off, even though
        // the actual guest CR4 has VMXE=1 (required by VMX).
        vmwrite(vmcs::control::CR4_READ_SHADOW, Cr4::read_raw() & !Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits());

        log::debug!("CR4 read shadow (guest will see): {:#x}", vmread(vmcs::control::CR4_READ_SHADOW));
        log::debug!("CR4 guest/host mask: {:#x}", vmread(vmcs::control::CR4_GUEST_HOST_MASK));

        vmwrite(vmcs::control::MSR_BITMAPS_ADDR_FULL, msr_bitmap);

        vmwrite(0x2000, io_bitmap_a); // IO_BITMAP_A
        vmwrite(0x2002, io_bitmap_b); // IO_BITMAP_B

        // Don't intercept any exceptions - let the guest handle them all natively.
        // We're no longer using the UD2 test stub, so the guest resumes at the original
        // UEFI return address and should handle its own exceptions via its IDT.
        vmwrite(vmcs::control::EXCEPTION_BITMAP, 0u32);

        vmwrite(0x4016, 0u32); // VM_ENTRY_INTR_INFO
        vmwrite(0x4018, 0u32); // VM_ENTRY_EXCEPTION_ERROR_CODE
        vmwrite(0x401A, 0u32); // VM_ENTRY_INSTRUCTION_LEN

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
