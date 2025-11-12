use {core::arch::global_asm, hypervisor::intel::capture::GuestRegisters};

// This is provided by the EFI/assembly side.
unsafe extern "efiapi" {
    /// Jumps to the landing code with the new stack pointer.
    ///
    /// # Safety
    /// Implemented in assembly/firmware and assumes the arguments are valid.
    fn switch_stack(guest_registers: &GuestRegisters, landing_code: usize, host_stack: u64) -> !;
}

/// Thin wrapper the rest of the UEFI crate can call.
/// `processor.rs` can `use crate::virtualize::virtualize_system` now.
pub fn virtualize_system(guest_registers: &GuestRegisters, landing_code: usize, host_stack: u64) -> ! {
    // safe wrapper around the extern assembly entry
    unsafe { switch_stack(guest_registers, landing_code, host_stack) }
}

// Assembly stub that actually switches stacks and jumps.
// We export the symbol here, so we don't need a Rust `#[no_mangle]` above.
global_asm!(
    r#"
    .global switch_stack
switch_stack:
    // handy bochs/aligned breakpoint
    xchg    bx, bx

    // SysV-ish argument order (what the original stub assumed):
    // rdi = &GuestRegisters
    // rsi = landing_code
    // rdx = host_stack
    //
    // we want: rsp = host_stack, then jmp landing_code

    mov     rsp, rdx
    jmp     rsi
"#
);
