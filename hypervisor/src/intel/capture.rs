// hypervisor/src/intel/capture.rs

use core::{arch::global_asm, mem::offset_of};

/// Register layout captured by the assembly stub and shared across Intel code.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GuestRegisters {
    // General-purpose registers saved in assembly
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
    pub rip: u64,

    // MSR hook-related fields used elsewhere
    pub original_lstar: u64,
    pub hook_lstar: u64,

    // XMM registers — other code uses offset_of! on these
    pub xmm0: [u8; 16],
    pub xmm1: [u8; 16],
    pub xmm2: [u8; 16],
    pub xmm3: [u8; 16],
    pub xmm4: [u8; 16],
    pub xmm5: [u8; 16],
    pub xmm6: [u8; 16],
    pub xmm7: [u8; 16],
    pub xmm8: [u8; 16],
    pub xmm9: [u8; 16],
    pub xmm10: [u8; 16],
    pub xmm11: [u8; 16],
    pub xmm12: [u8; 16],
    pub xmm13: [u8; 16],
    pub xmm14: [u8; 16],
    pub xmm15: [u8; 16],
}

// declare the symbol implemented by the asm below
unsafe extern "efiapi" {
    pub fn capture_registers(registers: &mut GuestRegisters) -> bool;
}

global_asm!(
    r#"
    .globl capture_registers
capture_registers:
    // RCX = &mut GuestRegisters (EFI/Win64 calling convention)

    // Save GPRs
    mov [rcx + {rax_off}], rax
    mov [rcx + {rcx_off}], rcx
    mov [rcx + {rdx_off}], rdx
    mov [rcx + {rbx_off}], rbx
    mov [rcx + {rsp_off}], rsp
    mov [rcx + {rbp_off}], rbp
    mov [rcx + {rsi_off}], rsi
    mov [rcx + {rdi_off}], rdi
    mov [rcx + {r8_off}],  r8
    mov [rcx + {r9_off}],  r9
    mov [rcx + {r10_off}], r10
    mov [rcx + {r11_off}], r11
    mov [rcx + {r12_off}], r12
    mov [rcx + {r13_off}], r13
    mov [rcx + {r14_off}], r14
    mov [rcx + {r15_off}], r15

    // Save RFLAGS
    pushfq
    pop rax
    mov [rcx + {rflags_off}], rax

    // Save RIP (return address)
    mov rax, [rsp]
    mov [rcx + {rip_off}], rax

    // return true
    mov al, 1
    ret
"#,
    rax_off = const offset_of!(GuestRegisters, rax),
    rcx_off = const offset_of!(GuestRegisters, rcx),
    rdx_off = const offset_of!(GuestRegisters, rdx),
    rbx_off = const offset_of!(GuestRegisters, rbx),
    rsp_off = const offset_of!(GuestRegisters, rsp),
    rbp_off = const offset_of!(GuestRegisters, rbp),
    rsi_off = const offset_of!(GuestRegisters, rsi),
    rdi_off = const offset_of!(GuestRegisters, rdi),
    r8_off  = const offset_of!(GuestRegisters, r8),
    r9_off  = const offset_of!(GuestRegisters, r9),
    r10_off = const offset_of!(GuestRegisters, r10),
    r11_off = const offset_of!(GuestRegisters, r11),
    r12_off = const offset_of!(GuestRegisters, r12),
    r13_off = const offset_of!(GuestRegisters, r13),
    r14_off = const offset_of!(GuestRegisters, r14),
    r15_off = const offset_of!(GuestRegisters, r15),
    rflags_off = const offset_of!(GuestRegisters, rflags),
    rip_off    = const offset_of!(GuestRegisters, rip),
);
