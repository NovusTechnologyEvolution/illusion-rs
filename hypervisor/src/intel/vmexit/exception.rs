//! Module handling VM exits due to exceptions or non-maskable interrupts (NMIs).
//! It includes handling for various types of exceptions such as page faults,
//! general protection faults, breakpoints, and invalid opcodes.

use {
    crate::intel::{
        events::EventInjection,
        support::vmread,
        vm::Vm,
        vmerror::{EptViolationExitQualification, ExceptionInterrupt, VmExitInterruptionInformation},
        vmexit::ExitType,
    },
    x86::vmx::vmcs,
};

/// Handles exceptions and NMIs that occur during VM execution.
///
/// This function is called when the VM exits due to an exception or NMI.
/// It determines the type of exception, handles it accordingly, and prepares
/// the VM for resumption.
///
/// # Arguments
///
/// * `vm` - A mutable reference to the VM structure representing the current VM.
///
/// # Returns
///
/// * `ExitType::Continue` - Indicating that VM execution should continue after handling the exception
pub fn handle_exception(vm: &mut Vm) -> ExitType {
    log::debug!("Handling ExceptionOrNmi VM exit...");

    let interruption_info_value = vmread(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
    let interruption_error_code_value = vmread(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE);

    if let Some(interruption_info) = VmExitInterruptionInformation::from_u32(interruption_info_value as u32) {
        if let Some(exception_interrupt) = ExceptionInterrupt::from_u32(interruption_info.vector.into()) {
            match exception_interrupt {
                ExceptionInterrupt::PageFault => {
                    let exit_qualification_value = vmread(vmcs::ro::EXIT_QUALIFICATION);
                    let ept_violation_qualification = EptViolationExitQualification::from_exit_qualification(exit_qualification_value);
                    log::trace!("Exit Qualification for EPT Violations: {:#?}", ept_violation_qualification);

                    // Log page fault details for debugging
                    log::debug!(
                        "#PF at RIP={:#x}, CR2 (faulting addr)={:#x}, error_code={:#x}",
                        vm.guest_registers.rip,
                        exit_qualification_value,
                        interruption_error_code_value
                    );

                    EventInjection::vmentry_inject_pf(interruption_error_code_value as u32);
                }
                ExceptionInterrupt::GeneralProtectionFault => {
                    log::error!("=== #GP (General Protection Fault) EXCEPTION ===");
                    log::error!("RIP={:#x} RSP={:#x} Error={:#x}", vmread(vmcs::guest::RIP), vmread(vmcs::guest::RSP), interruption_error_code_value);
                    log::error!(
                        "CS={:#x} SS={:#x} CR3={:#x}",
                        vmread(vmcs::guest::CS_SELECTOR),
                        vmread(vmcs::guest::SS_SELECTOR),
                        vmread(vmcs::guest::CR3)
                    );

                    // Log CR0/CR4 state which often causes #GP
                    let cr0 = vmread(vmcs::guest::CR0);
                    let cr4 = vmread(vmcs::guest::CR4);
                    let cr0_shadow = vmread(vmcs::control::CR0_READ_SHADOW);
                    let cr4_shadow = vmread(vmcs::control::CR4_READ_SHADOW);
                    log::error!("CR0={:#x} (shadow={:#x}) CR4={:#x} (shadow={:#x})", cr0, cr0_shadow, cr4, cr4_shadow);

                    // Re-inject to guest - it may have its own handler
                    EventInjection::vmentry_inject_gp(interruption_error_code_value as u32);
                }
                ExceptionInterrupt::Breakpoint => {
                    log::debug!("#BP at RIP={:#x}", vm.guest_registers.rip);
                    EventInjection::vmentry_inject_bp();
                }
                ExceptionInterrupt::InvalidOpcode => {
                    log::error!("=== #UD (Invalid Opcode) EXCEPTION DETECTED ===");
                    dump_ud_diagnostics(vm);

                    // Re-inject to guest instead of panicking
                    EventInjection::vmentry_inject_ud();
                    log::warn!("Re-injecting #UD to guest at RIP={:#x}", vm.guest_registers.rip);
                }
                ExceptionInterrupt::DoubleFault => {
                    log::error!("=== DOUBLE FAULT DETECTED ===");
                    log::error!("RIP={:#x} RSP={:#x}", vm.guest_registers.rip, vm.guest_registers.rsp);
                    log::error!("This is usually fatal - check for stack overflow or IDT issues");

                    // Double faults use error code 0, inject as hardware exception
                    EventInjection::inject_hw_exception(8, Some(0)); // Vector 8 = #DF
                }
                ExceptionInterrupt::StackSegmentFault => {
                    log::error!("=== #SS (Stack Segment Fault) ===");
                    log::error!("RIP={:#x} RSP={:#x} Error={:#x}", vm.guest_registers.rip, vm.guest_registers.rsp, interruption_error_code_value);
                    EventInjection::inject_hw_exception(12, Some(interruption_error_code_value as u32)); // Vector 12 = #SS
                }
                ExceptionInterrupt::SegmentNotPresent => {
                    log::error!("=== #NP (Segment Not Present) ===");
                    log::error!("RIP={:#x} Error={:#x}", vm.guest_registers.rip, interruption_error_code_value);
                    EventInjection::inject_hw_exception(11, Some(interruption_error_code_value as u32)); // Vector 11 = #NP
                }
                ExceptionInterrupt::InvalidTSS => {
                    log::error!("=== #TS (Invalid TSS) ===");
                    log::error!("RIP={:#x} Error={:#x}", vm.guest_registers.rip, interruption_error_code_value);
                    EventInjection::inject_hw_exception(10, Some(interruption_error_code_value as u32)); // Vector 10 = #TS
                }
                ExceptionInterrupt::DivisionError => {
                    log::debug!("#DE at RIP={:#x}", vm.guest_registers.rip);
                    EventInjection::inject_hw_exception(0, None); // Vector 0 = #DE
                }
                ExceptionInterrupt::Debug => {
                    log::debug!("#DB at RIP={:#x}", vm.guest_registers.rip);
                    EventInjection::inject_hw_exception(1, None); // Vector 1 = #DB
                }
                ExceptionInterrupt::NonMaskableInterrupt => {
                    log::debug!("NMI received at RIP={:#x}", vm.guest_registers.rip);
                    EventInjection::inject_nmi(); // NMI uses different injection type
                }
                ExceptionInterrupt::Overflow => {
                    log::debug!("#OF at RIP={:#x}", vm.guest_registers.rip);
                    EventInjection::inject_hw_exception(4, None); // Vector 4 = #OF
                }
                ExceptionInterrupt::BoundRangeExceeded => {
                    log::debug!("#BR at RIP={:#x}", vm.guest_registers.rip);
                    EventInjection::inject_hw_exception(5, None); // Vector 5 = #BR
                }
                ExceptionInterrupt::DeviceNotAvailable => {
                    log::debug!("#NM at RIP={:#x}", vm.guest_registers.rip);
                    EventInjection::inject_hw_exception(7, None); // Vector 7 = #NM
                }
                ExceptionInterrupt::AlignmentCheck => {
                    log::debug!("#AC at RIP={:#x} Error={:#x}", vm.guest_registers.rip, interruption_error_code_value);
                    EventInjection::inject_hw_exception(17, Some(interruption_error_code_value as u32)); // Vector 17 = #AC
                }
                ExceptionInterrupt::MachineCheck => {
                    log::error!("=== #MC (Machine Check) - THIS IS BAD ===");
                    log::error!("RIP={:#x}", vm.guest_registers.rip);
                    EventInjection::inject_hw_exception(18, None); // Vector 18 = #MC
                }
                ExceptionInterrupt::SimdFloatingPointException => {
                    log::debug!("#XF at RIP={:#x}", vm.guest_registers.rip);
                    EventInjection::inject_hw_exception(19, None); // Vector 19 = #XF
                }
                _ => {
                    log::warn!("Unhandled exception: {:?} at RIP={:#x}", exception_interrupt, vm.guest_registers.rip);
                    // Try to re-inject as a generic hardware exception
                    EventInjection::inject_hw_exception(interruption_info.vector as u32, None);
                }
            }
        } else {
            log::error!("Invalid Exception Interrupt Vector: {}", interruption_info.vector);
            // Don't panic - try to continue
        }
    } else {
        log::error!("Invalid VM Exit Interruption Information: {:#x}", interruption_info_value);
        // Don't panic - try to continue
    }

    log::debug!("Exception Handled successfully!");

    ExitType::Continue
}

/// Dumps detailed diagnostics for #UD exceptions
fn dump_ud_diagnostics(vm: &Vm) {
    let rip = vm.guest_registers.rip;
    let rsp = vm.guest_registers.rsp;

    // Check what caused the VM-exit
    let exit_intr_info = vmread(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
    let exit_intr_err = vmread(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE);
    let exit_qual = vmread(vmcs::ro::EXIT_QUALIFICATION);
    let instr_len = vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
    log::error!("VM-exit interruption info: {:#x}", exit_intr_info);
    log::error!("VM-exit interruption err:  {:#x}", exit_intr_err);
    log::error!("Exit qualification:        {:#x}", exit_qual);
    log::error!("Instruction length:        {:#x}", instr_len);

    // Check IDT vectoring info
    let idt_vec_info = vmread(vmcs::ro::IDT_VECTORING_INFO);
    let idt_vec_err = vmread(vmcs::ro::IDT_VECTORING_ERR_CODE);
    log::error!("IDT vectoring info:        {:#x}", idt_vec_info);
    log::error!("IDT vectoring err code:    {:#x}", idt_vec_err);

    log::error!("RIP: {:#x}, RSP: {:#x}", rip, rsp);
    log::error!("RFLAGS: {:#x}", vm.guest_registers.rflags);
    log::error!(
        "RAX={:#x} RBX={:#x} RCX={:#x} RDX={:#x}",
        vm.guest_registers.rax,
        vm.guest_registers.rbx,
        vm.guest_registers.rcx,
        vm.guest_registers.rdx
    );
    log::error!("RSI={:#x} RDI={:#x} RBP={:#x}", vm.guest_registers.rsi, vm.guest_registers.rdi, vm.guest_registers.rbp);
    log::error!(
        "R8={:#x} R9={:#x} R10={:#x} R11={:#x}",
        vm.guest_registers.r8,
        vm.guest_registers.r9,
        vm.guest_registers.r10,
        vm.guest_registers.r11
    );
    log::error!(
        "R12={:#x} R13={:#x} R14={:#x} R15={:#x}",
        vm.guest_registers.r12,
        vm.guest_registers.r13,
        vm.guest_registers.r14,
        vm.guest_registers.r15
    );
    log::error!(
        "CS={:#x} SS={:#x} DS={:#x} ES={:#x}",
        vmread(vmcs::guest::CS_SELECTOR),
        vmread(vmcs::guest::SS_SELECTOR),
        vmread(vmcs::guest::DS_SELECTOR),
        vmread(vmcs::guest::ES_SELECTOR)
    );
    log::error!("CR0={:#x} CR3={:#x} CR4={:#x}", vmread(vmcs::guest::CR0), vmread(vmcs::guest::CR3), vmread(vmcs::guest::CR4));
    log::error!("GDTR base={:#x} limit={:#x}", vmread(vmcs::guest::GDTR_BASE), vmread(vmcs::guest::GDTR_LIMIT));
    log::error!("IDTR base={:#x} limit={:#x}", vmread(vmcs::guest::IDTR_BASE), vmread(vmcs::guest::IDTR_LIMIT));

    // NOTE: We cannot safely read bytes at RIP here!
    // The RIP is a GUEST virtual address, but we're in the hypervisor.
    // To read guest memory, we'd need to:
    // 1. Walk the guest page tables (CR3) to translate RIP to physical
    // 2. Then access that physical address
    // For now, just log that we can't read it
    if rip >= 0xFFFF800000000000 {
        log::error!("RIP is in kernel space - would need EPT walk to read");
    } else if rip > 0x1000 {
        log::error!("RIP is in user space ({:#x}) - cannot read from hypervisor", rip);
        log::error!("This #UD is from user-mode code, not kernel");
    } else {
        log::error!("RIP is in low memory ({:#x}) - likely invalid", rip);
    }
}

/// Handles undefined opcode (`#UD`) exceptions.
pub fn handle_undefined_opcode_exception() -> ExitType {
    log::debug!("Undefined Opcode Exception");

    EventInjection::vmentry_inject_ud();

    log::debug!("Undefined Opcode Exception handled successfully!");

    ExitType::Continue
}
