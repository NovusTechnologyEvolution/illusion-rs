use {
    crate::{
        error::HypervisorError,
        intel::{
            ept::AccessType,
            hooks::hook_manager::SHARED_HOOK_MANAGER,
            support::vmread,
            vm::Vm,
            vmerror::EptViolationExitQualification,
            vmexit::{
                ExitType,
                mtf::{set_monitor_trap_flag, update_guest_interrupt_flag},
            },
        },
    },
    log::*,
    x86::{bits64::paging::PAddr, vmx::vmcs},
};

/// Handles VM exits for EPT violations.
/// EPT violations occur when an operation is performed on an EPT entry that does not provide permissions to access that page.
///
/// This function addresses the EPT violation by either swapping the page to a shadow page
/// or restoring the original page based on the exit qualification. It also sets up the monitor trap flag
/// if necessary.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the virtual machine (VM) instance.
///
/// # Returns
///
/// * `Result<ExitType, HypervisorError>` - `Ok(ExitType::Continue)` if the EPT violation was handled successfully, or a `HypervisorError` if an error occurred.
pub fn handle_ept_violation(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling EPT Violation VM exit...");

    let guest_pa = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
    trace!("Faulting Guest PA: {:#x}", guest_pa);

    let guest_page_pa = PAddr::from(guest_pa).align_down_to_base_page();
    trace!("Faulting Guest Page PA: {:#x}", guest_page_pa);

    let guest_large_page_pa = guest_page_pa.align_down_to_large_page();
    trace!("Faulting Guest Large Page PA: {:#x}", guest_large_page_pa);

    let exit_qualification_value = vmread(vmcs::ro::EXIT_QUALIFICATION);
    let ept_violation_qualification = EptViolationExitQualification::from_exit_qualification(exit_qualification_value);
    trace!("Exit Qualification for EPT Violations: {:#?}", ept_violation_qualification);
    trace!("Faulting Guest RIP: {:#x}", vm.guest_registers.rip);

    // Lock the shared hook manager
    let mut hook_manager = SHARED_HOOK_MANAGER.lock();

    // CRITICAL FIX: Check if this page has a shadow page registered
    // If not, this is an EPT violation for a non-hooked page, which shouldn't happen
    // in normal operation but can occur during certain edge cases
    let shadow_page_result = hook_manager.memory_manager.get_shadow_page_as_ptr(guest_page_pa.as_u64());

    if shadow_page_result.is_none() {
        // No shadow page found - this EPT violation is not for a hooked page
        // This can happen if:
        // 1. A page was unhooked but the EPT permissions weren't fully restored
        // 2. There's an EPT misconfiguration
        // 3. Something else is accessing memory in an unexpected way

        error!("EPT Violation for non-hooked page at GPA {:#x}, RIP {:#x}", guest_pa, vm.guest_registers.rip);
        error!("Exit qualification: {:?}", ept_violation_qualification);

        // Try to get the page table to restore permissions
        if let Some(pre_alloc_pt) = hook_manager.memory_manager.get_page_table_as_mut(guest_large_page_pa.as_u64()) {
            // Restore full permissions to allow the access
            warn!("Restoring RWX permissions to unhooked page {:#x}", guest_page_pa);
            vm.primary_ept
                .modify_page_permissions(guest_page_pa.as_u64(), AccessType::READ_WRITE_EXECUTE, pre_alloc_pt)?;
            return Ok(ExitType::Continue);
        }

        // If we can't find the page table, this is a more serious issue
        // Log detailed info for debugging
        error!("CRITICAL: Cannot find page table for large page {:#x}", guest_large_page_pa);
        error!("This may indicate an EPT configuration issue");

        // Return error to trigger proper handling/debugging
        return Err(HypervisorError::ShadowPageNotFound);
    }

    let shadow_page_pa = PAddr::from(shadow_page_result.unwrap());
    trace!("Shadow Page PA: {:#x}", shadow_page_pa.as_u64());

    let pre_alloc_pt = hook_manager
        .memory_manager
        .get_page_table_as_mut(guest_large_page_pa.as_u64())
        .ok_or(HypervisorError::PageTableNotFound)?;

    // dump_primary_ept_entries(vm, guest_pa, pre_alloc_pt)?;

    if ept_violation_qualification.readable && ept_violation_qualification.writable && !ept_violation_qualification.executable {
        // The page is readable and writable but NOT executable
        // This means execution was attempted on a non-executable page
        // Instruction Fetch: true,
        // Page Permissions: R:true, W:true, X:false (readable, writable, but non-executable).
        trace!("Page Permissions: R:true, W:true, X:false (readable, writable, but non-executable).");
        trace!("Execution attempt on non-executable page, switching to hooked shadow-copy page.");
        vm.primary_ept
            .swap_page(guest_page_pa.as_u64(), shadow_page_pa.as_u64(), AccessType::EXECUTE, pre_alloc_pt)?;
        trace!("Page swapped successfully!");
    } else if ept_violation_qualification.executable && !ept_violation_qualification.readable && !ept_violation_qualification.writable {
        // The page is executable but NOT readable or writable
        // This means a read/write was attempted on an execute-only page
        // Instruction Fetch: false,
        // Page Permissions: R:false, W:false, X:true (non-readable, non-writable, but executable).
        trace!("Read/Write attempt on execute-only page, restoring original page.");
        trace!("Page Permissions: R:false, W:false, X:true (non-readable, non-writable, but executable).");
        vm.primary_ept
            .swap_page(guest_page_pa.as_u64(), guest_page_pa.as_u64(), AccessType::READ_WRITE_EXECUTE, pre_alloc_pt)?;

        // We make this read-write-execute to allow the instruction performing a read-write
        // operation and then switch back to execute-only shadow page from handle_mtf vmexit
        vm.mtf_counter = Some(1);

        // Set the monitor trap flag and initialize counter to the number of overwritten instructions
        set_monitor_trap_flag(true);

        // Ensure all data mutations to vm are done before calling this.
        // This function will update the guest interrupt flag to prevent interrupts while single-stepping
        update_guest_interrupt_flag(vm, false)?;
    } else {
        // Unexpected EPT violation type - log for debugging
        warn!(
            "Unexpected EPT violation type: R={}, W={}, X={} at GPA {:#x}, RIP {:#x}",
            ept_violation_qualification.readable,
            ept_violation_qualification.writable,
            ept_violation_qualification.executable,
            guest_pa,
            vm.guest_registers.rip
        );

        // Handle instruction fetch on a page with no permissions (R=0, W=0, X=0)
        // This can happen if the page was marked with no permissions
        if !ept_violation_qualification.readable && !ept_violation_qualification.writable && !ept_violation_qualification.executable {
            // Determine if this was a fetch or data access based on the violation info
            // Bit 2 of exit qualification indicates instruction fetch
            let is_instruction_fetch = (exit_qualification_value >> 2) & 1 != 0;

            if is_instruction_fetch {
                trace!("Instruction fetch on no-permission page, switching to shadow page");
                vm.primary_ept
                    .swap_page(guest_page_pa.as_u64(), shadow_page_pa.as_u64(), AccessType::EXECUTE, pre_alloc_pt)?;
            } else {
                trace!("Data access on no-permission page, enabling RWX temporarily");
                vm.primary_ept
                    .swap_page(guest_page_pa.as_u64(), guest_page_pa.as_u64(), AccessType::READ_WRITE_EXECUTE, pre_alloc_pt)?;
                vm.mtf_counter = Some(1);
                set_monitor_trap_flag(true);
                update_guest_interrupt_flag(vm, false)?;
            }
        }
    }

    trace!("EPT Violation handled successfully!");

    // Do not increment RIP, since we want it to execute the same instruction again.
    Ok(ExitType::Continue)
}
