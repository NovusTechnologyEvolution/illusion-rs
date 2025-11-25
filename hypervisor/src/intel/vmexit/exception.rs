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
/// * `guest_registers` - A mutable reference to the guest's register state.
/// * `vmx` - A mutable reference to the Vmx structure representing the current VM.
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

                    // Re-inject to guest - it may have its own handler
                    EventInjection::vmentry_inject_gp(interruption_error_code_value as u32);
                }
                ExceptionInterrupt::Breakpoint => {
                    EventInjection::vmentry_inject_bp();
                }
                ExceptionInterrupt::InvalidOpcode => {
                    log::error!("=== #UD (Invalid Opcode) EXCEPTION DETECTED ===");

                    // Check what caused the VM-exit
                    let exit_intr_info = vmread(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
                    let exit_intr_err = vmread(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE);
                    let exit_qual = vmread(vmcs::ro::EXIT_QUALIFICATION);
                    let instr_len = vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
                    log::error!("VM-exit interruption info: {:#x}", exit_intr_info);
                    log::error!("VM-exit interruption err:  {:#x}", exit_intr_err);
                    log::error!("Exit qualification:        {:#x}", exit_qual);
                    log::error!("Instruction length:        {:#x}", instr_len);

                    // Check IDT vectoring info (tells us if an event was in progress)
                    let idt_vec_info = vmread(vmcs::ro::IDT_VECTORING_INFO);
                    let idt_vec_err = vmread(vmcs::ro::IDT_VECTORING_ERR_CODE);
                    log::error!("IDT vectoring info:        {:#x}", idt_vec_info);
                    log::error!("IDT vectoring err code:    {:#x}", idt_vec_err);

                    log::error!("RIP: {:#x}, RSP: {:#x}", vm.guest_registers.rip, vm.guest_registers.rsp);
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

                    // Try to read the first few IDT entries to see if they're valid
                    let idtr_base = vmread(vmcs::guest::IDTR_BASE) as *const u64;
                    log::error!("First 4 IDT entries (raw 128-bit each):");
                    for i in 0..4 {
                        let low = unsafe { core::ptr::read_volatile(idtr_base.add(i * 2)) };
                        let high = unsafe { core::ptr::read_volatile(idtr_base.add(i * 2 + 1)) };
                        // Extract the handler address from 64-bit IDT entry
                        let offset_low = (low & 0xFFFF) as u64;
                        let offset_mid = ((low >> 48) & 0xFFFF) as u64;
                        let offset_high = (high & 0xFFFFFFFF) as u64;
                        let handler = offset_low | (offset_mid << 16) | (offset_high << 32);
                        let selector = ((low >> 16) & 0xFFFF) as u16;
                        let ist = ((low >> 32) & 0x7) as u8;
                        let type_attr = ((low >> 40) & 0xFF) as u8;
                        log::error!("  IDT[{}]: handler={:#x}, sel={:#x}, IST={}, type={:#x}", i, handler, selector, ist, type_attr);
                    }

                    // Check if RIP is on stack (indicates corrupted return address)
                    let rip = vm.guest_registers.rip;
                    let rsp = vm.guest_registers.rsp;
                    if rip >= rsp && rip < rsp + 0x1000 {
                        log::error!("!!! RIP ({:#x}) appears to be on the stack (RSP={:#x}) !!!", rip, rsp);
                        log::error!("This suggests a corrupted return address was popped");
                    }

                    // Try to read bytes at RIP for #UD analysis
                    log::error!("Attempting to read bytes at RIP...");
                    let rip_ptr = rip as *const u8;
                    if rip < 0x100000000 {
                        let bytes: [u8; 8] = unsafe { core::ptr::read_volatile(rip_ptr as *const [u8; 8]) };
                        log::error!(
                            "Bytes at RIP: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                            bytes[0],
                            bytes[1],
                            bytes[2],
                            bytes[3],
                            bytes[4],
                            bytes[5],
                            bytes[6],
                            bytes[7]
                        );

                        // Check for common VMX instructions that would cause #UD in guest
                        // VMCALL = 0F 01 C1, VMLAUNCH = 0F 01 C2, VMRESUME = 0F 01 C3, VMXOFF = 0F 01 C4
                        if bytes[0] == 0x0F && bytes[1] == 0x01 {
                            match bytes[2] {
                                0xC1 => log::error!("!!! Detected VMCALL instruction - guest trying to use VMX !!!"),
                                0xC2 => log::error!("!!! Detected VMLAUNCH instruction - guest trying to use VMX !!!"),
                                0xC3 => log::error!("!!! Detected VMRESUME instruction - guest trying to use VMX !!!"),
                                0xC4 => log::error!("!!! Detected VMXOFF instruction - guest trying to use VMX !!!"),
                                _ => {}
                            }
                        }
                        // VMREAD = 0F 78, VMWRITE = 0F 79
                        if bytes[0] == 0x0F && bytes[1] == 0x78 {
                            log::error!("!!! Detected VMREAD instruction - guest trying to use VMX !!!");
                        }
                        if bytes[0] == 0x0F && bytes[1] == 0x79 {
                            log::error!("!!! Detected VMWRITE instruction - guest trying to use VMX !!!");
                        }
                        // VMXON = F3 0F C7, VMCLEAR = 66 0F C7
                        if (bytes[0] == 0xF3 || bytes[0] == 0x66) && bytes[1] == 0x0F && bytes[2] == 0xC7 {
                            log::error!("!!! Detected VMX memory instruction (VMXON/VMCLEAR) !!!");
                        }
                        // VMPTRLD/VMPTRST = 0F C7
                        if bytes[0] == 0x0F && bytes[1] == 0xC7 {
                            log::error!("!!! Detected VMPTRLD/VMPTRST instruction !!!");
                        }
                    }

                    // Dump some stack contents
                    log::error!("Stack contents around RSP:");
                    let stack_ptr = rsp as *const u64;
                    for i in 0..16 {
                        let val = unsafe { core::ptr::read_volatile(stack_ptr.add(i)) };
                        log::error!("  [RSP+{:#x}] = {:#x}", i * 8, val);
                    }

                    // Also dump stack above RSP (previously pushed data)
                    log::error!("Stack contents ABOVE RIP (0xffca8b0):");
                    let rip_as_stack = (rip as *const u64).wrapping_sub(4); // Look before RIP
                    for i in 0..8 {
                        let addr = unsafe { rip_as_stack.add(i) };
                        let val = unsafe { core::ptr::read_volatile(addr) };
                        log::error!("  [{:#x}] = {:#x}", addr as u64, val);
                    }

                    panic!("#UD exception - halting for analysis");
                }
                _ => {
                    panic!("Unhandled exception: {:?}", exception_interrupt);
                }
            }
        } else {
            panic!("Invalid Exception Interrupt Vector: {}", interruption_info.vector);
        }
    } else {
        panic!("Invalid VM Exit Interruption Information");
    }

    log::debug!("Exception Handled successfully!");

    ExitType::Continue
}

/*
/// Handles breakpoint (`#BP`) exceptions specifically.
///
/// When a breakpoint exception occurs, this function checks for a registered hook
/// at the current instruction pointer (RIP). If a hook is found, it transfers control
/// to the hook's handler. Otherwise, it injects a breakpoint exception into the VM.
///
/// # Arguments
///
/// * `guest_registers` - A mutable reference to the guest's current register state.
/// * `vmx` - A mutable reference to the Vmx structure.
fn handle_breakpoint_exception(guest_registers: &mut GuestRegisters, vm: &mut Vm) {
    log::debug!("Breakpoint Exception");

    let hook_manager = vm.hook_manager.as_mut();

    log::trace!("Finding hook for RIP: {:#x}", guest_registers.rip);

    // Find the handler address for the current instruction pointer (RIP) and
    // transfer the execution to it. If we couldn't find a hook, we inject the
    // #BP exception.
    //
    if let Some(Some(handler)) =
        hook_manager
            .find_hook_by_address(guest_registers.rip)
            .map(|hook| {
                log::trace!("Found hook for RIP: {:#x}", guest_registers.rip);
                if let HookType::Function { inline_hook } = &hook.hook_type {
                    log::trace!("Getting handler address");
                    Some(inline_hook.handler_address())
                } else {
                    None
                }
            })
    {
        // Call our hook handle function (it will automatically call trampoline).
        log::trace!("Transferring execution to handler: {:#x}", handler);
        guest_registers.rip = handler;
        vmwrite(vmcs::guest::RIP, guest_registers.rip);

        log::debug!("Breakpoint (int3) hook handled successfully!");
    } else {
        EventInjection::vmentry_inject_bp();
        log::debug!("Breakpoint exception handled successfully!");
    };
}
*/

/// Handles undefined opcode (`#UD`) exceptions.
///
/// This function is invoked when the VM attempts to execute an invalid or undefined
/// opcode. It injects an undefined opcode exception into the VM.
///
/// # Returns
///
/// * `ExitType::Continue` - Indicating that VM execution should continue.
pub fn handle_undefined_opcode_exception() -> ExitType {
    log::debug!("Undefined Opcode Exception");

    EventInjection::vmentry_inject_ud();

    log::debug!("Undefined Opcode Exception handled successfully!");

    ExitType::Continue
}
