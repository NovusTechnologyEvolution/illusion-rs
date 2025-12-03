//! This module provides utilities and structures to manage event injection in VMX.
//! It handles the representation, manipulation, and injection of various types of events.

#![allow(dead_code)]

use {
    crate::intel::{
        support::{vmread, vmwrite},
        vmerror::{ExceptionInterrupt, InterruptionType},
    },
    bitfield::bitfield,
    x86::vmx::vmcs,
};

bitfield! {
    /// Represents the VM-Entry Interruption-Information Field.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: Table 25-17. Format of the VM-Entry Interruption-Information Field
    pub struct EventInjection(u32);

    impl Debug;

    /// Vector of interrupt or exception
    pub get_vector, set_vector: 7, 0;

    /// Interruption type:
    /// 0: External interrupt
    /// 1: Reserved
    /// 2: Non-maskable interrupt (NMI)
    /// 3: Hardware exception (e.g,. #PF)
    /// 4: Software interrupt (INT n)
    /// 5: Privileged software exception (INT1)
    /// 6: Software exception (INT3 or INTO)
    /// 7: Other event
    pub get_type, set_type: 10, 8;

    /// Deliver error code (0 = do not deliver; 1 = deliver)
    pub get_deliver_error_code, set_deliver_error_code: 11, 11;

    // Reserved: 30:12

    /// Valid
    pub get_valid, set_valid: 31, 31;
}

const VALID: u32 = 1;
const INVALID: u32 = 0;

/// Provides methods for event injection in VMX.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 27.6 EVENT INJECTION
impl EventInjection {
    /// Inject General Protection (#GP) to the guest (Event Injection).
    fn general_protection() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::GeneralProtectionFault as u32);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_deliver_error_code(1);
        event.set_valid(VALID);

        event.0
    }

    /// Inject Breakpoint (#BP) to the guest (Event Injection).
    fn breakpoint() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::Breakpoint as u32);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_valid(VALID);

        event.0
    }

    /// Inject Page Fault (#PF) to the guest (Event Injection).
    fn page_fault() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::PageFault as u32);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_deliver_error_code(1);
        event.set_valid(VALID);

        event.0
    }

    /// Inject Undefined Opcode (#UD) to the guest (Event Injection).
    fn undefined_opcode() -> u32 {
        let mut event = EventInjection(0);

        event.set_vector(ExceptionInterrupt::InvalidOpcode as u32);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_valid(VALID);

        event.0
    }

    /// Injects a general protection fault into the guest.
    ///
    /// This function is used to signal to the guest that a protection violation
    /// has occurred, typically due to accessing a reserved MSR.
    ///
    /// # Arguments
    ///
    /// * `error_code` - The error code to be associated with the fault.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    /// and Table 25-17. Format of the VM-Entry Interruption-Information Field.
    pub fn vmentry_inject_gp(error_code: u32) {
        let event = EventInjection::general_protection();
        log::info!("[EVENT] Injecting #GP: info={:#x} error_code={:#x}", event, error_code);

        vmwrite(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, error_code);
        vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, event);

        // Verify the write
        let readback = vmread(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD);
        log::info!("[EVENT] #GP injection readback: {:#x}", readback);
    }

    /// Injects a page fault into the guest.
    ///
    /// This function is used to signal to the guest that a page fault has occurred.
    /// It's typically used in response to a memory access violation.
    ///
    /// # Arguments
    ///
    /// * `error_code` - The error code to be associated with the page fault.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    /// and Table 25-17. Format of the VM-Entry Interruption-Information Field.
    pub fn vmentry_inject_pf(error_code: u32) {
        let event = EventInjection::page_fault();
        log::trace!("[EVENT] Injecting #PF: info={:#x} error_code={:#x}", event, error_code);

        vmwrite(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, error_code);
        vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, event);
    }

    /// Injects a breakpoint exception into the guest.
    ///
    /// This function is used to signal to the guest that a breakpoint exception
    /// has occurred, typically used for debugging purposes.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    /// and Table 25-17. Format of the VM-Entry Interruption-Information Field.
    pub fn vmentry_inject_bp() {
        let event = EventInjection::breakpoint();
        log::info!("[EVENT] Injecting #BP: info={:#x}", event);

        vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, event);
    }

    /// Injects an undefined opcode exception into the guest.
    ///
    /// This function is used to signal to the guest that an invalid or undefined opcode
    /// has been encountered, typically indicating an error in the guest's execution.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    /// and Table 25-17. Format of the VM-Entry Interruption-Information Field.
    pub fn vmentry_inject_ud() {
        let event = EventInjection::undefined_opcode();

        // Log the injection details
        log::error!("[EVENT] === INJECTING #UD EXCEPTION ===");
        log::error!("[EVENT] Event info to write: {:#x}", event);
        log::error!("[EVENT]   Vector: {} (#UD)", event & 0xFF);
        log::error!("[EVENT]   Type: {} (HardwareException)", (event >> 8) & 0x7);
        log::error!("[EVENT]   Valid: {}", (event >> 31) & 0x1);

        // Log current guest state before injection
        let guest_rip = vmread(vmcs::guest::RIP);
        let guest_rsp = vmread(vmcs::guest::RSP);
        let guest_rflags = vmread(vmcs::guest::RFLAGS);
        let guest_cs = vmread(vmcs::guest::CS_SELECTOR);
        let guest_ss = vmread(vmcs::guest::SS_SELECTOR);
        let guest_cpl = vmread(vmcs::guest::SS_ACCESS_RIGHTS) & 0x3; // CPL from SS DPL

        log::error!("[EVENT] Guest state before injection:");
        log::error!("[EVENT]   RIP={:#x} RSP={:#x} RFLAGS={:#x}", guest_rip, guest_rsp, guest_rflags);
        log::error!("[EVENT]   CS={:#x} SS={:#x} CPL={}", guest_cs, guest_ss, guest_cpl);

        // Check interruptibility state
        let interruptibility = vmread(vmcs::guest::INTERRUPTIBILITY_STATE);
        let activity_state = vmread(vmcs::guest::ACTIVITY_STATE);
        log::error!("[EVENT]   Interruptibility={:#x} Activity={:#x}", interruptibility, activity_state);

        // Check if there's already a pending event
        let current_event = vmread(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD);
        if current_event & 0x80000000 != 0 {
            log::error!("[EVENT] WARNING: There's already a pending event: {:#x}", current_event);
        }

        // Perform the injection
        vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, event);

        // Verify the write succeeded
        let readback = vmread(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD);
        log::error!("[EVENT] Injection readback: {:#x} (expected {:#x})", readback, event);

        if readback != event as u64 {
            log::error!("[EVENT] !!! VMWRITE FAILED - value mismatch !!!");
        }

        // Check IDT vectoring info - if valid, we may have interrupted exception delivery
        let idt_vectoring = vmread(vmcs::ro::IDT_VECTORING_INFO);
        if idt_vectoring & 0x80000000 != 0 {
            log::error!("[EVENT] WARNING: IDT vectoring is valid: {:#x}", idt_vectoring);
            log::error!("[EVENT] This means we interrupted exception delivery - may need special handling");
        }

        log::error!("[EVENT] === #UD INJECTION COMPLETE ===");
    }

    // =========================================================================
    // Generic injection functions for all exception types
    // =========================================================================

    /// Injects a generic hardware exception into the guest.
    ///
    /// This is a generic function that can inject any hardware exception.
    /// Use this for exceptions that don't have a dedicated helper function.
    ///
    /// # Arguments
    /// * `vector` - The exception vector number (0-31 for standard exceptions)
    /// * `error_code` - Optional error code for exceptions that require one
    ///
    /// # Exception Vectors with Error Codes
    /// The following exceptions push an error code: #DF(8), #TS(10), #NP(11),
    /// #SS(12), #GP(13), #PF(14), #AC(17)
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    pub fn inject_hw_exception(vector: u32, error_code: Option<u32>) {
        let mut event = EventInjection(0);

        event.set_vector(vector);
        event.set_type(InterruptionType::HardwareException as u32);
        event.set_valid(VALID);

        if let Some(err) = error_code {
            event.set_deliver_error_code(1);
            vmwrite(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, err);
        }

        log::info!("[EVENT] Injecting HW exception vector={} info={:#x} error={:?}", vector, event.0, error_code);

        vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, event.0);
    }

    /// Injects a Non-Maskable Interrupt (NMI) into the guest.
    ///
    /// NMIs are type 2 interrupts with vector 2.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    pub fn inject_nmi() {
        let mut event = EventInjection(0);

        event.set_vector(2); // NMI is vector 2
        event.set_type(InterruptionType::NonMaskableInterrupt as u32);
        event.set_valid(VALID);

        log::info!("[EVENT] Injecting NMI: info={:#x}", event.0);

        vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, event.0);
    }

    /// Injects an external interrupt into the guest.
    ///
    /// # Arguments
    /// * `vector` - The interrupt vector number (32-255 for external interrupts)
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    pub fn inject_external_interrupt(vector: u32) {
        let mut event = EventInjection(0);

        event.set_vector(vector);
        event.set_type(InterruptionType::ExternalInterrupt as u32);
        event.set_valid(VALID);

        log::info!("[EVENT] Injecting external interrupt vector={}: info={:#x}", vector, event.0);

        vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, event.0);
    }

    /// Injects a software interrupt (INT n) into the guest.
    ///
    /// # Arguments
    /// * `vector` - The interrupt vector number
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 25.8.3 VM-Entry Controls for Event Injection
    pub fn inject_software_interrupt(vector: u32) {
        let mut event = EventInjection(0);

        event.set_vector(vector);
        event.set_type(InterruptionType::SoftwareInterrupt as u32);
        event.set_valid(VALID);

        log::info!("[EVENT] Injecting software interrupt vector={}: info={:#x}", vector, event.0);

        vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, event.0);
    }
}
