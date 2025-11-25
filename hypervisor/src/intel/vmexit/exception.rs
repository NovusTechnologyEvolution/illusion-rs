//! Module handling VM exits due to exceptions or non-maskable interrupts (NMIs).

use {
    crate::intel::{
        events::EventInjection,
        support::vmread,
        vm::Vm,
        vmerror::{ExceptionInterrupt, VmExitInterruptionInformation},
        vmexit::ExitType,
    },
    x86::vmx::vmcs,
};

/// Handles exceptions and NMIs that occur during VM execution.
///
/// NOTE: With EXCEPTION_BITMAP set to 0, we should NOT receive exception VM-exits
/// except for NMIs and certain architectural exceptions. If we do receive one,
/// we log it and re-inject it to the guest.
pub fn handle_exception(_vm: &mut Vm) -> ExitType {
    let interruption_info_value = vmread(vmcs::ro::VMEXIT_INTERRUPTION_INFO);
    let interruption_error_code_value = vmread(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE);
    let guest_rip = vmread(vmcs::guest::RIP);

    if let Some(interruption_info) = VmExitInterruptionInformation::from_u32(interruption_info_value as u32) {
        let vector = interruption_info.vector;

        log::debug!("Exception VM-exit: vector={}, RIP={:#x}, error_code={:#x}", vector, guest_rip, interruption_error_code_value);

        if let Some(exception_interrupt) = ExceptionInterrupt::from_u32(vector.into()) {
            match exception_interrupt {
                ExceptionInterrupt::NonMaskableInterrupt => {
                    // NMIs - just log and continue, the guest will handle it
                    log::debug!("NMI received at RIP {:#x}", guest_rip);
                    return ExitType::Continue;
                }
                ExceptionInterrupt::InvalidOpcode => {
                    // #UD - shouldn't happen with bitmap=0, but if it does, re-inject
                    log::warn!("#UD at RIP {:#x} - re-injecting to guest", guest_rip);
                    EventInjection::vmentry_inject_ud();
                    return ExitType::Continue;
                }
                ExceptionInterrupt::GeneralProtectionFault => {
                    // #GP - shouldn't happen with bitmap=0, but if it does, re-inject
                    log::warn!("#GP at RIP {:#x}, error={:#x} - re-injecting to guest", guest_rip, interruption_error_code_value);
                    EventInjection::vmentry_inject_gp(interruption_error_code_value as u32);
                    return ExitType::Continue;
                }
                ExceptionInterrupt::PageFault => {
                    // #PF - CR2 (faulting address) is in EXIT_QUALIFICATION for #PF
                    let exit_qualification = vmread(vmcs::ro::EXIT_QUALIFICATION);
                    log::warn!(
                        "#PF at RIP {:#x}, fault_addr={:#x}, error={:#x} - re-injecting to guest",
                        guest_rip,
                        exit_qualification,
                        interruption_error_code_value
                    );
                    EventInjection::vmentry_inject_pf(interruption_error_code_value as u32);
                    return ExitType::Continue;
                }
                ExceptionInterrupt::Breakpoint => {
                    // #BP - re-inject to guest
                    log::debug!("#BP at RIP {:#x} - re-injecting to guest", guest_rip);
                    EventInjection::vmentry_inject_bp();
                    return ExitType::Continue;
                }
                _ => {
                    // Other exceptions - log and continue (let guest handle via its IDT)
                    log::warn!("Exception {:?} (vector {}) at RIP {:#x} - continuing", exception_interrupt, vector, guest_rip);
                    return ExitType::Continue;
                }
            }
        } else {
            log::error!("Invalid exception vector: {}", vector);
        }
    } else {
        log::error!("Invalid VM Exit Interruption Information: {:#x}", interruption_info_value);
    }

    ExitType::Continue
}

/// Handles undefined opcode (`#UD`) exceptions for VMX instructions.
pub fn handle_undefined_opcode_exception() -> ExitType {
    EventInjection::vmentry_inject_ud();
    ExitType::Continue
}
