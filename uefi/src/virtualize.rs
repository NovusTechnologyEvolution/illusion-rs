//! Provides a mechanism to virtualize the system by installing a hypervisor on the current processor,
//! utilizing custom stack allocation and low-level assembly for context switching.

use {
    crate::stack::allocate_host_stack,
    core::{alloc::Layout, arch::global_asm, ptr},
    hypervisor::{
        global_const::STACK_PAGES_PER_PROCESSOR,
        intel::{capture::GuestRegisters, page::Page},
        vmm::start_hypervisor,
    },
    log::debug,
};

/// Installs the hypervisor on the current processor.
///
/// # Arguments
///
/// * `guest_registers` - The guest registers to use for the hypervisor.
pub fn virtualize_system(guest_registers: &GuestRegisters) -> ! {
    debug!("Allocating stack space for host");

    let layout = Layout::array::<Page>(STACK_PAGES_PER_PROCESSOR).unwrap();
    let stack = unsafe { allocate_host_stack(layout) };
    let size = layout.size();

    debug!("Zeroing stack space for host");
    unsafe {
        ptr::write_bytes(stack, 0, size);
    }

    if stack == core::ptr::null_mut() {
        panic!("Failed to allocate stack");
    }

    let stack_base = stack as u64 + layout.size() as u64 - 0x10;
    log::trace!("Stack range: {:#x?}", stack as u64..stack_base);

    unsafe { switch_stack(guest_registers, start_hypervisor as usize, stack_base as _) };
}

extern "efiapi" {
    /// Jumps to the landing code with the new stack pointer.
    fn switch_stack(guest_registers: &GuestRegisters, landing_code: usize, host_stack: u64) -> !;
}

global_asm!(
    r#"
// The module containing the `switch_stack` function. Jumps to the landing code with the new stack pointer.
.global switch_stack
switch_stack:
    xchg    bx, bx
    mov     rsp, r8
    jmp     rdx
"#
);
