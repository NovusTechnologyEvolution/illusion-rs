// hypervisor/src/intel/vmlaunch.rs
//! VM launch stub for Intel VMX.
//!
//! Small assembly stub that actually executes VMLAUNCH/VMRESUME and returns
//! the resulting RFLAGS so Rust code can check for VM-instruction success/failure.

use {
    crate::intel::capture::GuestRegisters,
    core::{arch::global_asm, mem},
};

unsafe extern "efiapi" {
    /// Tries to launch a VM using the state laid out in `registers`.
    ///
    /// `launched`:
    ///   - 0 → first entry, use VMLAUNCH
    ///   - 1 → subsequent entries, use VMRESUME
    ///
    /// Returns the CPU RFLAGS after executing the VMX instruction.
    pub fn launch_vm(registers: &mut GuestRegisters, launched: u64) -> u64;
}

/// Safe wrapper around the EFI/assembly VM-launch routine.
pub fn vmlaunch(registers: &mut GuestRegisters, launched: u64) -> u64 {
    unsafe { launch_vm(registers, launched) }
}

global_asm!(
    r#"
    .globl launch_vm

    // Windows x64 / EFI calling convention:
    //   RCX = &mut GuestRegisters
    //   RDX = has_launched (0 = first entry -> VMLAUNCH, 1 = VMRESUME)
launch_vm:
    // Save callee-saved registers we might clobber in this stub.
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    // NOTE:
    // For now we don't synchronize GuestRegisters <-> CPU GPRs here.
    // VM entry/exit uses VMCS-managed control state, and our Rust code
    // reads/writes VMCS guest fields directly (RIP/RSP/RFLAGS, etc.).
    // This stub's job is just:
    //   - pick VMLAUNCH vs VMRESUME
    //   - execute it
    //   - return the resulting RFLAGS so vm_succeed() can decode errors.

    // Decide between VMLAUNCH / VMRESUME based on `launched`.
    test    rdx, rdx
    jnz     1f

    // First time: VMLAUNCH
    vmlaunch
    jmp     2f

1:
    // Subsequent entries: VMRESUME
    vmresume

2:
    // On return from the VMX instruction (success or VMfail),
    // grab the current RFLAGS and hand them back in RAX.
    pushfq
    pop     rax

    // Restore callee-saved registers.
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx

    ret

    /* Keep these offsets wired up for tooling/consistency; they aren't
       used in this stub but mirror the capture stub layout.

       {registers_rax} {registers_rbx} {registers_rcx} {registers_rdx}
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
