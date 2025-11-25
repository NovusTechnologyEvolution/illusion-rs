// hypervisor/src/intel/vmlaunch.rs
//! VM launch stub - WORKING VERSION without RIP-relative statics

use {
    crate::intel::capture::GuestRegisters,
    core::{arch::global_asm, mem},
};

unsafe extern "sysv64" {
    pub fn launch_vm(registers: *mut GuestRegisters, launched: u64) -> u64;
}

unsafe extern "sysv64" {
    pub fn vmexit_handler();
}

pub fn vmlaunch(registers: &mut GuestRegisters, launched: u64) -> u64 {
    unsafe {
        let registers_ptr = registers as *mut GuestRegisters;
        launch_vm(registers_ptr, launched)
    }
}

global_asm!(
    r#"
    .globl launch_vm
    .globl vmexit_handler

launch_vm:
    // System V AMD64 ABI calling convention:
    // RDI = first argument = &GuestRegisters (mut pointer)
    // RSI = second argument = launched (u64)
    
    // Save RDI (GuestRegisters pointer) and RSI (launched flag) on stack
    push    rdi
    push    rsi
    
    // Save callee-saved registers
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15

    // Retrieve the launched flag from stack
    // Stack layout now (top to bottom):
    // [rsp + 0]  = r15
    // [rsp + 8]  = r14
    // [rsp + 16] = r13
    // [rsp + 24] = r12
    // [rsp + 32] = rbp
    // [rsp + 40] = rbx
    // [rsp + 48] = rsi (launched flag)
    // [rsp + 56] = rdi (GuestRegisters pointer)
    mov     rcx, [rsp + 48]
    
    // Decide between VMLAUNCH / VMRESUME based on launched flag
    test    rcx, rcx
    jnz     .Lresume

.Llaunch:
    // Get GuestRegisters pointer from stack
    mov     r8, [rsp + 56]
    
    // Load guest general-purpose registers
    mov     rax, [{registers_rax} + r8]
    mov     rbx, [{registers_rbx} + r8]
    mov     rcx, [{registers_rcx} + r8]
    mov     rdx, [{registers_rdx} + r8]
    mov     rsi, [{registers_rsi} + r8]
    mov     rdi, [{registers_rdi} + r8]
    mov     rbp, [{registers_rbp} + r8]
    mov     r9,  [{registers_r9} + r8]
    mov     r10, [{registers_r10} + r8]
    mov     r11, [{registers_r11} + r8]
    mov     r12, [{registers_r12} + r8]
    mov     r13, [{registers_r13} + r8]
    mov     r14, [{registers_r14} + r8]
    mov     r15, [{registers_r15} + r8]
    
    // Load r8 last since we were using it as base pointer
    mov     r8,  [{registers_r8} + r8]
    
    // CRITICAL: About to execute VMLAUNCH
    // If this hangs, we never reach vmexit_handler OR .Lfailed
    vmlaunch
    
    // If we get here, VMLAUNCH failed
    jmp     .Lfailed

.Lresume:
    // Load guest registers for VMRESUME
    mov     r8, [rsp + 56]  // Get GuestRegisters pointer
    
    mov     rax, [{registers_rax} + r8]
    mov     rbx, [{registers_rbx} + r8]
    mov     rcx, [{registers_rcx} + r8]
    mov     rdx, [{registers_rdx} + r8]
    mov     rsi, [{registers_rsi} + r8]
    mov     rdi, [{registers_rdi} + r8]
    mov     rbp, [{registers_rbp} + r8]
    mov     r9,  [{registers_r9} + r8]
    mov     r10, [{registers_r10} + r8]
    mov     r11, [{registers_r11} + r8]
    mov     r12, [{registers_r12} + r8]
    mov     r13, [{registers_r13} + r8]
    mov     r14, [{registers_r14} + r8]
    mov     r15, [{registers_r15} + r8]
    mov     r8,  [{registers_r8} + r8]
    
    vmresume
    
    // If we get here, VMRESUME failed
    jmp     .Lfailed

.Lfailed:
    // VM-entry failed - return RFLAGS in RAX
    pushfq
    pop     rax

    // Restore stack and callee-saved registers
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    pop     rsi     // Discard saved launched flag
    pop     rdi     // Discard saved GuestRegisters pointer

    ret

vmexit_handler:
    // CRITICAL: At this point, RSP has been loaded from HOST_RSP in VMCS
    // HOST_RSP points to the stack AFTER the 8 register pushes in launch_vm
    
    // Stack layout when we enter here:
    // [HOST_RSP + 0]  = r15 (from launch_vm)
    // [HOST_RSP + 8]  = r14
    // [HOST_RSP + 16] = r13
    // [HOST_RSP + 24] = r12
    // [HOST_RSP + 32] = rbp
    // [HOST_RSP + 40] = rbx
    // [HOST_RSP + 48] = rsi (launched flag)
    // [HOST_RSP + 56] = rdi (GuestRegisters pointer)
    // [HOST_RSP + 64] = return address (from call to launch_vm)
    
    // Save all guest registers to temporary stack locations
    push    rax
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    push    rbp
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
    
    // Get GuestRegisters pointer from the saved launch_vm stack
    // After we pushed 15 registers (15*8 = 120 bytes), the pointer is at:
    // [rsp + 120 + 56] = [rsp + 176]
    mov     r8, [rsp + 176]
    
    // Save guest registers back to struct
    // Note: we need to read from our temp stack
    mov     rax, [rsp + 14*8]   // Get saved rax
    mov     [{registers_rax} + r8], rax
    
    mov     rax, [rsp + 13*8]   // Get saved rbx
    mov     [{registers_rbx} + r8], rax
    
    mov     rax, [rsp + 12*8]   // Get saved rcx
    mov     [{registers_rcx} + r8], rax
    
    mov     rax, [rsp + 11*8]   // Get saved rdx
    mov     [{registers_rdx} + r8], rax
    
    mov     rax, [rsp + 10*8]   // Get saved rsi
    mov     [{registers_rsi} + r8], rax
    
    mov     rax, [rsp + 9*8]    // Get saved rdi
    mov     [{registers_rdi} + r8], rax
    
    mov     rax, [rsp + 8*8]    // Get saved rbp
    mov     [{registers_rbp} + r8], rax
    
    mov     rax, [rsp + 7*8]    // Get saved r8
    mov     [{registers_r8} + r8], rax
    
    mov     rax, [rsp + 6*8]    // Get saved r9
    mov     [{registers_r9} + r8], rax
    
    mov     rax, [rsp + 5*8]    // Get saved r10
    mov     [{registers_r10} + r8], rax
    
    mov     rax, [rsp + 4*8]    // Get saved r11
    mov     [{registers_r11} + r8], rax
    
    mov     rax, [rsp + 3*8]    // Get saved r12
    mov     [{registers_r12} + r8], rax
    
    mov     rax, [rsp + 2*8]    // Get saved r13
    mov     [{registers_r13} + r8], rax
    
    mov     rax, [rsp + 1*8]    // Get saved r14
    mov     [{registers_r14} + r8], rax
    
    mov     rax, [rsp + 0*8]    // Get saved r15
    mov     [{registers_r15} + r8], rax
    
    // Restore our working registers
    add     rsp, 15*8   // Pop all saved guest registers
    
    // Set RAX=0 (success - RFLAGS with no error flags)
    xor     rax, rax
    
    // Restore callee-saved registers and return (in reverse order)
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    pop     rsi     // Discard saved launched flag
    pop     rdi     // Discard saved GuestRegisters pointer
    
    ret
"#,
    registers_rax = const mem::offset_of!(GuestRegisters, rax),
    registers_rbx = const mem::offset_of!(GuestRegisters, rbx),
    registers_rcx = const mem::offset_of!(GuestRegisters, rcx),
    registers_rdx = const mem::offset_of!(GuestRegisters, rdx),
    registers_rsi = const mem::offset_of!(GuestRegisters, rsi),
    registers_rdi = const mem::offset_of!(GuestRegisters, rdi),
    registers_rbp = const mem::offset_of!(GuestRegisters, rbp),
    registers_r8  = const mem::offset_of!(GuestRegisters, r8),
    registers_r9  = const mem::offset_of!(GuestRegisters, r9),
    registers_r10 = const mem::offset_of!(GuestRegisters, r10),
    registers_r11 = const mem::offset_of!(GuestRegisters, r11),
    registers_r12 = const mem::offset_of!(GuestRegisters, r12),
    registers_r13 = const mem::offset_of!(GuestRegisters, r13),
    registers_r14 = const mem::offset_of!(GuestRegisters, r14),
    registers_r15 = const mem::offset_of!(GuestRegisters, r15),
);
