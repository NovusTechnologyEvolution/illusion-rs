//! VM launch stub for Intel VMX.
//!
//! This is the same pattern as the capture stub: small assembly body, but a long list of
//! named offsets so Rust code can refer to guest register slots in a structured way.

use {
    crate::intel::capture::GuestRegisters,
    core::{arch::global_asm, mem},
};

unsafe extern "efiapi" {
    /// Tries to launch a VM using the state laid out in `registers`.
    ///
    /// Return value and exact calling convention are coming from the uploaded stub, so we keep it.
    pub fn launch_vm(registers: &mut GuestRegisters, launched: u64) -> u64;
}

/// Safe wrapper around the EFI/assembly VM-launch routine.
pub fn vmlaunch(registers: &mut GuestRegisters, launched: u64) -> u64 {
    unsafe { launch_vm(registers, launched) }
}

global_asm!(
    r#"
    .global launch_vm

launch_vm:
    // your uploaded file only set a value and returned — keep that.
    mov     rax, 0
    ret

    /* {registers_rax} {registers_rbx} {registers_rcx} {registers_rdx}
       {registers_rsi} {registers_rdi} {registers_rbp} {registers_rsp}
       {registers_r8} {registers_r9} {registers_r10} {registers_r11}
       {registers_r12} {registers_r13} {registers_r14} {registers_r15}
       {registers_rip} {registers_rflags}
       {registers_xmm0} {registers_xmm1} {registers_xmm2} {registers_xmm3}
       {registers_xmm4} {registers_xmm5} {registers_xmm6} {registers_xmm7}
       {registers_xmm8} {registers_xmm9} {registers_xmm10} {registers_xmm11}
       {registers_xmm12} {registers_xmm13} {registers_xmm14} {registers_xmm15} */
"#,
    registers_rax = const mem::offset_of!(GuestRegisters, rax),
    registers_rbx = const mem::offset_of!(GuestRegisters, rbx),
    registers_rcx = const mem::offset_of!(GuestRegisters, rcx),
    registers_rdx = const mem::offset_of!(GuestRegisters, rdx),
    registers_rsi = const mem::offset_of!(GuestRegisters, rsi),
    registers_rdi = const mem::offset_of!(GuestRegisters, rdi),
    registers_rbp = const mem::offset_of!(GuestRegisters, rbp),
    registers_rsp = const mem::offset_of!(GuestRegisters, rsp),
    registers_r8  = const mem::offset_of!(GuestRegisters, r8),
    registers_r9  = const mem::offset_of!(GuestRegisters, r9),
    registers_r10 = const mem::offset_of!(GuestRegisters, r10),
    registers_r11 = const mem::offset_of!(GuestRegisters, r11),
    registers_r12 = const mem::offset_of!(GuestRegisters, r12),
    registers_r13 = const mem::offset_of!(GuestRegisters, r13),
    registers_r14 = const mem::offset_of!(GuestRegisters, r14),
    registers_r15 = const mem::offset_of!(GuestRegisters, r15),
    registers_rip = const mem::offset_of!(GuestRegisters, rip),
    registers_rflags = const mem::offset_of!(GuestRegisters, rflags),
    registers_xmm0 = const mem::offset_of!(GuestRegisters, xmm0),
    registers_xmm1 = const mem::offset_of!(GuestRegisters, xmm1),
    registers_xmm2 = const mem::offset_of!(GuestRegisters, xmm2),
    registers_xmm3 = const mem::offset_of!(GuestRegisters, xmm3),
    registers_xmm4 = const mem::offset_of!(GuestRegisters, xmm4),
    registers_xmm5 = const mem::offset_of!(GuestRegisters, xmm5),
    registers_xmm6 = const mem::offset_of!(GuestRegisters, xmm6),
    registers_xmm7 = const mem::offset_of!(GuestRegisters, xmm7),
    registers_xmm8 = const mem::offset_of!(GuestRegisters, xmm8),
    registers_xmm9 = const mem::offset_of!(GuestRegisters, xmm9),
    registers_xmm10 = const mem::offset_of!(GuestRegisters, xmm10),
    registers_xmm11 = const mem::offset_of!(GuestRegisters, xmm11),
    registers_xmm12 = const mem::offset_of!(GuestRegisters, xmm12),
    registers_xmm13 = const mem::offset_of!(GuestRegisters, xmm13),
    registers_xmm14 = const mem::offset_of!(GuestRegisters, xmm14),
    registers_xmm15 = const mem::offset_of!(GuestRegisters, xmm15),
);
