// hypervisor/src/intel/vmlaunch.rs
use {
    crate::intel::capture::GuestRegisters,
    core::{arch::global_asm, mem},
};

unsafe extern "efiapi" {
    pub fn launch_vm(registers: &mut GuestRegisters, launched: u64) -> u64;
    pub fn vmexit_asm_handler();
    /// External handler defined in vmm.rs to report launch failures
    pub fn vmlaunch_failed(rflags: u64, error_code: u64);
}

pub fn vmlaunch(registers: &mut GuestRegisters, launched: u64) -> u64 {
    unsafe { launch_vm(registers, launched) }
}

global_asm!(
    r#"
    .intel_syntax noprefix
    .global launch_vm
    .global vmexit_asm_handler
    .global vmlaunch_failed

launch_vm:
    // Save callee-saved registers
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15
    
    // Save parameters
    push    rdx              // launched flag
    push    rcx              // GuestRegisters pointer
    
    // CRITICAL FIX: DO NOT set HOST_RSP/HOST_RIP here!
    // These must be set once during VMCS setup, not on every launch/resume.
    
    // Get GuestRegisters pointer
    mov     rcx, [rsp]
    
    // Load ALL guest registers from GuestRegisters struct
    mov     rax, [rcx + {rax_off}]
    mov     rbx, [rcx + {rbx_off}]
    mov     rdx, [rcx + {rdx_off}]
    mov     rbp, [rcx + {rbp_off}]
    mov     rsi, [rcx + {rsi_off}]
    mov     rdi, [rcx + {rdi_off}]
    mov     r8,  [rcx + {r8_off}]
    mov     r9,  [rcx + {r9_off}]
    mov     r10, [rcx + {r10_off}]
    mov     r11, [rcx + {r11_off}]
    mov     r12, [rcx + {r12_off}]
    mov     r13, [rcx + {r13_off}]
    mov     r14, [rcx + {r14_off}]
    mov     r15, [rcx + {r15_off}]
    
    // Load RCX last (destroys pointer)
    mov     rcx, [rcx + {rcx_off}]
    
    // Check launched flag on stack [rsp + 8]
    cmp     qword ptr [rsp + 8], 0
    jnz     do_resume

do_launch:
    vmlaunch
    jmp     launch_fail

do_resume:
    vmresume
    jmp     launch_fail

vmexit_asm_handler:
    // Stack: [GuestRegisters*] [launched_flag] [r15] [r14] [r13] [r12] [rsi] [rdi] [rbp] [rbx] [return_addr]
    
    // Save guest RCX temporarily
    push    rcx
    
    // Get GuestRegisters pointer (it's at [rsp + 8] now)
    mov     rcx, [rsp + 8]
    
    // Save all guest GPRs
    mov     [rcx + {rax_off}], rax
    mov     [rcx + {rbx_off}], rbx
    // Save the pushed RCX value
    mov     rax, [rsp]
    mov     [rcx + {rcx_off}], rax
    mov     [rcx + {rdx_off}], rdx
    mov     [rcx + {rbp_off}], rbp
    mov     [rcx + {rsi_off}], rsi
    mov     [rcx + {rdi_off}], rdi
    mov     [rcx + {r8_off}],  r8
    mov     [rcx + {r9_off}],  r9
    mov     [rcx + {r10_off}], r10
    mov     [rcx + {r11_off}], r11
    mov     [rcx + {r12_off}], r12
    mov     [rcx + {r13_off}], r13
    mov     [rcx + {r14_off}], r14
    mov     [rcx + {r15_off}], r15
    
    // Clean up stack: remove guest RCX, GuestRegisters pointer, and launched flag
    add     rsp, 24
    
    // Return success (0)
    xor     rax, rax
    
    // Restore callee-saved registers
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret

launch_fail:
    // Stack: [GuestRegisters*] [launched_flag] [r15] [r14] ... [rbx]
    
    // 1. Clean up stack arguments (GuestRegisters pointer and launched flag)
    add     rsp, 16
    
    // 2. Prepare Argument 1 (RCX) = RFLAGS
    pushfq
    pop     rcx
    
    // 3. Prepare Argument 2 (RDX) = Error Code (Default 0)
    xor     rdx, rdx
    
    // 4. Check ZF (Bit 6) -> VMfailValid
    test    cl, 0x40        // Test ZF
    jz      check_cf
    
    // ZF is set: Read VM-Instruction Error Field (Encoding 0x4400)
    mov     rax, 0x4400
    vmread  rdx, rax
    jmp     call_handler

check_cf:
    // 5. Check CF (Bit 0) -> VMfailInvalid
    test    cl, 0x01        // Test CF
    jz      call_handler    // Should not happen if we are here, but fail safe
    
    // CF is set: Invalid VMCS pointer or corruption
    mov     rdx, 0xFFFF     // 0xFFFF indicates VMfailInvalid

call_handler:
    // 6. Call Rust handler: vmlaunch_failed(rflags, error_code)
    // Allocate shadow space (32 bytes) for Microsoft x64 ABI
    sub     rsp, 32
    call    vmlaunch_failed
    add     rsp, 32
    
    // 7. Restore registers and return (Though the handler should panic)
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret
    
    .att_syntax prefix
"#,
    rax_off = const mem::offset_of!(GuestRegisters, rax),
    rbx_off = const mem::offset_of!(GuestRegisters, rbx),
    rcx_off = const mem::offset_of!(GuestRegisters, rcx),
    rdx_off = const mem::offset_of!(GuestRegisters, rdx),
    rsi_off = const mem::offset_of!(GuestRegisters, rsi),
    rdi_off = const mem::offset_of!(GuestRegisters, rdi),
    rbp_off = const mem::offset_of!(GuestRegisters, rbp),
    r8_off  = const mem::offset_of!(GuestRegisters, r8),
    r9_off  = const mem::offset_of!(GuestRegisters, r9),
    r10_off = const mem::offset_of!(GuestRegisters, r10),
    r11_off = const mem::offset_of!(GuestRegisters, r11),
    r12_off = const mem::offset_of!(GuestRegisters, r12),
    r13_off = const mem::offset_of!(GuestRegisters, r13),
    r14_off = const mem::offset_of!(GuestRegisters, r14),
    r15_off = const mem::offset_of!(GuestRegisters, r15),
);
