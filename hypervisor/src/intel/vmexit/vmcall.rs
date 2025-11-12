//! Handle VM exits caused by VMCALL (hypercall) from the guest.

use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            ept::AccessType,
            events::EventInjection,
            hooks::hook_manager::{HookManager, SHARED_HOOK_MANAGER},
            vm::Vm,
            vmexit::{
                mtf::{set_monitor_trap_flag, update_guest_interrupt_flag},
                ExitType,
            },
        },
    },
    log::*,
    x86::bits64::paging::PAddr,
};

/// Handles a VMCALL VM exit by executing the corresponding action based on the VMCALL command.
///
/// # Parameters
///
/// * `vm`: A mutable reference to the virtual machine instance encountering the VMCALL exit.
///
/// # Returns
///
/// * `Ok(ExitType)`: continue execution
/// * `Err(HypervisorError)`: something about the page / hook wasn't found
pub fn handle_vmcall(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    trace!("Handling VMCALL VM exit...");
    trace!("Register state before handling VM exit: {:?}", vm.guest_registers);

    let vmcall_number = vm.guest_registers.rax;
    trace!("Guest RAX - VMCALL command number: {:#x}", vmcall_number);
    trace!("Guest RIP: {:#x}", vm.guest_registers.rip);

    let guest_function_pa = PAddr::from(PhysicalAddress::pa_from_va_with_current_cr3(vm.guest_registers.rip)?);
    trace!("Guest PA: {:#x}", guest_function_pa.as_u64());

    let guest_page_pa = guest_function_pa.align_down_to_base_page();
    trace!("Guest Page PA: {:#x}", guest_page_pa.as_u64());

    let guest_large_page_pa = guest_page_pa.align_down_to_large_page();
    trace!("Guest Large Page PA: {:#x}", guest_large_page_pa.as_u64());

    let mut hook_manager = SHARED_HOOK_MANAGER.lock();

    let exit_type = if let Some(shadow_page_pa) = hook_manager.memory_manager.get_shadow_page_as_ptr(guest_page_pa.as_u64()) {
        trace!("Shadow Page PA: {:#x}", shadow_page_pa);
        trace!("Executing VMCALL hook on shadow page for EPT hook at PA: {:#x} with VA: {:#x}", guest_function_pa, vm.guest_registers.rip);

        let pre_alloc_pt = hook_manager
            .memory_manager
            .get_page_table_as_mut(guest_large_page_pa.as_u64())
            .ok_or(HypervisorError::PageTableNotFound)?;

        // swap the page so the guest executes our shadow
        vm.primary_ept
            .swap_page(guest_page_pa.as_u64(), guest_page_pa.as_u64(), AccessType::READ_WRITE_EXECUTE, pre_alloc_pt)?;

        let hook_info = hook_manager
            .memory_manager
            .get_hook_info_by_function_pa(guest_page_pa.as_u64(), guest_function_pa.as_u64())
            .ok_or(HypervisorError::HookInfoNotFound)?;

        debug!("Hook info: {:#x?}", hook_info);

        // figure out how many bytes we overwrote so we can single-step them back in MTF
        let instruction_count =
            HookManager::calculate_instruction_count(guest_function_pa.as_u64(), HookManager::hook_size(hook_info.ept_hook_type)) as u64;

        vm.mtf_counter = Some(instruction_count);

        // turn on MTF so the next instructions are single-stepped
        set_monitor_trap_flag(true);

        // and make sure interrupts don't ruin it
        update_guest_interrupt_flag(vm, false)?;

        Ok(ExitType::Continue)
    } else {
        // guest did VMCALL somewhere we didn't hook -> inject #UD like Intel docs say
        // https://www.felixcloutier.com/x86/vmcall
        EventInjection::vmentry_inject_ud();
        Ok(ExitType::Continue)
    };

    exit_type
}
