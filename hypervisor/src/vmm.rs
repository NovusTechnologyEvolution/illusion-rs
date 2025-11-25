//! Manages hypervisor startup and VM exit handling.
//!
//! Provides the infrastructure for starting a hypervisor, including checking CPU support and enabling VMX.
//! Also, handles various VM exit reasons, ensuring that the guest VM can be efficiently managed and controlled.
//! This crate is essential for hypervisor operation, facilitating VM execution and interaction with the physical CPU.

use {
    crate::{
        error::HypervisorError,
        intel::{
            bitmap::MsrAccessType,
            capture::GuestRegisters,
            support::{rdmsr, vmread, vmwrite},
            vm::Vm,
            vmerror::VmxBasicExitReason,
            vmexit::{
                ExitType,
                cpuid::handle_cpuid,
                cr::handle_cr_reg_access,
                ept_misconfiguration::handle_ept_misconfiguration,
                ept_violation::handle_ept_violation,
                exception::{handle_exception, handle_undefined_opcode_exception},
                halt::handle_halt,
                init::handle_init_signal,
                invd::handle_invd,
                invept::handle_invept,
                invvpid::handle_invvpid,
                msr::handle_msr_access,
                mtf::handle_monitor_trap_flag,
                rdtsc::handle_rdtsc,
                sipi::handle_sipi_signal,
                vmcall::handle_vmcall,
                vmxon::handle_vmxon,
                xsetbv::handle_xsetbv,
            },
        },
    },
    alloc::boxed::Box,
    log::*,
    x86::{
        msr::IA32_VMX_EPT_VPID_CAP,
        vmx::vmcs::{guest, ro},
    },
};

/// Initiates the hypervisor, activating VMX and setting up the initial VM state.
///
/// Validates CPU compatibility and VMX support, then proceeds to enable VMX operation.
/// Initializes a VM instance and activates its VMCS, handling VM exits in a continuous loop.
///
/// # Arguments
///
/// - `guest_registers`: The initial state of the guest's general-purpose registers.
///
/// # Panics
///
/// Panics if the CPU is not supported, VMX cannot be enabled, VM or VMCS activation fails,
/// or an unhandled VM exit reason is encountered.
pub fn start_hypervisor(guest_registers: &GuestRegisters) -> ! {
    debug!("Starting hypervisor");

    match check_supported_cpu() {
        Ok(_) => debug!("CPU is supported"),
        Err(e) => panic!("CPU is not supported: {:?}", e),
    };

    // CRITICAL FIX: Allocate VM on heap instead of stack to prevent stack overflow
    // The Vm structure is ~4.2MB which is way too large for stack allocation
    debug!("Allocating VM structure on heap (size: ~4.2MB)");
    let mut vm = unsafe {
        let boxed = Box::<Vm>::new_zeroed();
        boxed.assume_init()
    };

    debug!("VM structure allocated successfully");

    match vm.init(guest_registers) {
        Ok(_) => debug!("VM initialized"),
        Err(e) => panic!("Failed to initialize VM: {:?}", e),
    };

    match vm.activate_vmxon() {
        Ok(_) => debug!("VMX enabled"),
        Err(e) => panic!("Failed to enable VMX: {:?}", e),
    };

    match vm.activate_vmcs() {
        Ok(_) => debug!("VMCS activated"),
        Err(e) => panic!("Failed to activate VMCS: {:?}", e),
    };

    // Enable EPT to hide hypervisor memory
    #[cfg(feature = "hide_hv_with_ept")]
    match hide_hv_with_ept(&mut vm) {
        Ok(_) => debug!("Hypervisor hidden from guest"),
        Err(e) => panic!("Failed to hide hypervisor: {:?}", e),
    };

    // Counter to limit logging spam
    static mut EXIT_COUNT: u64 = 0;
    static mut LAST_EXIT_REASON: u64 = 0;
    static mut LAST_RIP: u64 = 0;

    info!("Launching the VM until a vmexit occurs...");

    loop {
        if let Ok(basic_exit_reason) = vm.run() {
            // Increment exit counter
            let count = unsafe {
                EXIT_COUNT += 1;
                EXIT_COUNT
            };

            let current_rip = vmread(guest::RIP);

            // Track last exit for debugging crashes
            unsafe {
                LAST_EXIT_REASON = basic_exit_reason as u64;
                LAST_RIP = current_rip;
            }

            // Log only milestones to reduce output
            if count == 10 {
                info!("VM-exit milestone: 10 exits");
            } else if count == 100 {
                info!("VM-exit milestone: 100 exits");
            } else if count == 1000 {
                info!("VM-exit milestone: 1,000 exits");
            } else if count == 10000 {
                info!("VM-exit milestone: 10,000 exits");
            } else if count % 100000 == 0 {
                info!("VM-exit milestone: {} exits (last: {:?} @ {:#x})", count, basic_exit_reason, current_rip);
            }

            let exit_type = match basic_exit_reason {
                // 0
                VmxBasicExitReason::ExceptionOrNmi => {
                    // Get exception info
                    let intr_info = vmread(ro::VMEXIT_INTERRUPTION_INFO);
                    let vector = intr_info & 0xFF;
                    let error_code = if (intr_info & (1 << 11)) != 0 {
                        Some(vmread(ro::VMEXIT_INTERRUPTION_ERR_CODE))
                    } else {
                        None
                    };

                    // Log important exceptions
                    match vector {
                        0 => debug!("Exception: #DE (Divide Error) at RIP={:#x}", current_rip),
                        6 => debug!("Exception: #UD (Invalid Opcode) at RIP={:#x}", current_rip),
                        8 => error!("Exception: #DF (Double Fault) at RIP={:#x}, error={:?}", current_rip, error_code),
                        13 => {
                            error!("Exception: #GP (General Protection) at RIP={:#x}, error={:#x?}", current_rip, error_code);
                            error!("  SS={:#x}, CS={:#x}, RSP={:#x}", vmread(guest::SS_SELECTOR), vmread(guest::CS_SELECTOR), vmread(guest::RSP));
                        }
                        14 => debug!(
                            "Exception: #PF (Page Fault) at RIP={:#x}, error={:?}, CR2={:#x}",
                            current_rip,
                            error_code,
                            vmread(ro::EXIT_QUALIFICATION)
                        ),
                        _ => debug!("Exception: vector {} at RIP={:#x}", vector, current_rip),
                    }

                    handle_exception(&mut vm)
                }
                // 1
                VmxBasicExitReason::ExternalInterrupt => {
                    // Should not happen with external interrupt exiting disabled
                    log::warn!("Unexpected external interrupt exit!");
                    ExitType::Continue
                }
                // 2
                VmxBasicExitReason::TripleFault => {
                    error!("=== TRIPLE FAULT ===");
                    error!("Exit count: {}", count);
                    error!("Guest RIP: {:#x}", current_rip);
                    error!("Guest RSP: {:#x}", vmread(guest::RSP));
                    error!("Guest CR0: {:#x}", vmread(guest::CR0));
                    error!("Guest CR3: {:#x}", vmread(guest::CR3));
                    error!("Guest CR4: {:#x}", vmread(guest::CR4));
                    error!("Guest RFLAGS: {:#x}", vmread(guest::RFLAGS));
                    error!("Guest CS: {:#x}", vmread(guest::CS_SELECTOR));
                    error!("Guest SS: {:#x}", vmread(guest::SS_SELECTOR));
                    error!("Guest TR: {:#x}", vmread(guest::TR_SELECTOR));
                    error!("Guest TR base: {:#x}", vmread(guest::TR_BASE));
                    error!("Guest GDTR base: {:#x}", vmread(guest::GDTR_BASE));
                    error!("Guest GDTR limit: {:#x}", vmread(guest::GDTR_LIMIT));
                    error!("Guest IDTR base: {:#x}", vmread(guest::IDTR_BASE));
                    error!("Guest IDTR limit: {:#x}", vmread(guest::IDTR_LIMIT));
                    error!("Interruptibility: {:#x}", vmread(guest::INTERRUPTIBILITY_STATE));
                    error!("Activity state: {:#x}", vmread(guest::ACTIVITY_STATE));
                    panic!("Triple fault VM exit!");
                }
                // 3
                VmxBasicExitReason::InitSignal => handle_init_signal(&mut vm.guest_registers),
                // 4
                VmxBasicExitReason::StartupIpi => handle_sipi_signal(&mut vm.guest_registers),
                // 10
                VmxBasicExitReason::Cpuid => handle_cpuid(&mut vm).expect("Failed to handle CPUID"),
                // 11
                VmxBasicExitReason::Getsec => handle_undefined_opcode_exception(),
                // 12
                VmxBasicExitReason::Hlt => handle_halt(),
                // 13
                VmxBasicExitReason::Invd => handle_invd(&mut vm.guest_registers),
                // 18
                VmxBasicExitReason::Vmcall => handle_vmcall(&mut vm).expect("Failed to handle VMCALL"),
                // 19
                VmxBasicExitReason::Vmclear => handle_undefined_opcode_exception(),
                // 20
                VmxBasicExitReason::Vmlaunch => handle_undefined_opcode_exception(),
                // 21
                VmxBasicExitReason::Vmptrld => handle_undefined_opcode_exception(),
                // 22
                VmxBasicExitReason::Vmptrst => handle_undefined_opcode_exception(),
                // 23
                VmxBasicExitReason::Vmread => handle_undefined_opcode_exception(),
                // 24
                VmxBasicExitReason::Vmresume => handle_undefined_opcode_exception(),
                // 25
                VmxBasicExitReason::Vmwrite => handle_undefined_opcode_exception(),
                // 26
                VmxBasicExitReason::Vmxoff => handle_undefined_opcode_exception(),
                // 27
                VmxBasicExitReason::Vmxon => handle_vmxon(),
                // 28
                VmxBasicExitReason::ControlRegisterAccesses => handle_cr_reg_access(&mut vm).expect("Failed to handle CR access"),
                // 31
                VmxBasicExitReason::Rdmsr => handle_msr_access(&mut vm, MsrAccessType::Read).expect("Failed to handle RDMSR"),
                // 32
                VmxBasicExitReason::Wrmsr => handle_msr_access(&mut vm, MsrAccessType::Write).expect("Failed to handle WRMSR"),
                // 37
                VmxBasicExitReason::MonitorTrapFlag => handle_monitor_trap_flag(&mut vm).expect("Failed to handle MTF"),
                // 48
                VmxBasicExitReason::EptViolation => handle_ept_violation(&mut vm).expect("Failed to handle EPT violation"),
                // 49
                VmxBasicExitReason::EptMisconfiguration => handle_ept_misconfiguration(&mut vm).expect("Failed to handle EPT misconfiguration"),
                // 50
                VmxBasicExitReason::Invept => handle_invept(),
                // 51
                VmxBasicExitReason::Rdtsc => handle_rdtsc(&mut vm.guest_registers),
                // 53
                VmxBasicExitReason::Invvpid => handle_invvpid(),
                // 55
                VmxBasicExitReason::Xsetbv => handle_xsetbv(&mut vm),
                other => {
                    error!("=== UNHANDLED VM EXIT ===");
                    error!("Exit reason: {:?} ({})", other, other as u64);
                    error!("Exit count: {}", count);
                    error!("Guest RIP: {:#x}", current_rip);
                    error!("Guest RSP: {:#x}", vmread(guest::RSP));
                    error!("Guest RAX: {:#x}", vm.guest_registers.rax);
                    error!("Exit qualification: {:#x}", vmread(ro::EXIT_QUALIFICATION));
                    panic!("Unhandled VM exit reason: {:?}", other);
                }
            };

            if exit_type == ExitType::IncrementRIP {
                advance_guest_rip(&mut vm.guest_registers);
            }
        } else {
            error!("vm.run() failed! Last known RIP: {:#x}", vm.guest_registers.rip);
            panic!("Failed to run the VM");
        }
    }
}

/// Advances the guest's instruction pointer after handling a VM exit.
///
/// Ensures the guest VM does not re-execute the instruction causing the VM exit
/// by moving the instruction pointer to the next instruction.
///
/// # Arguments
///
/// - `guest_registers`: A mutable reference to the guest's general-purpose registers.
fn advance_guest_rip(guest_registers: &mut GuestRegisters) {
    let old_rip = vmread(guest::RIP);
    let len = vmread(ro::VMEXIT_INSTRUCTION_LEN);
    let new_rip = old_rip + len;

    trace!("Advancing RIP: {:#x} + {} = {:#x}", old_rip, len, new_rip);

    guest_registers.rip = new_rip;
    vmwrite(guest::RIP, new_rip);

    // Verify the write worked
    let verify_rip = vmread(guest::RIP);
    if verify_rip != new_rip {
        error!("CRITICAL: RIP write failed! Wrote {:#x}, read back {:#x}", new_rip, verify_rip);
    }
}

/// Checks if the CPU is supported for hypervisor operation.
///
/// Verifies the CPU is Intel with VMX support and Memory Type Range Registers (MTRRs) support.
///
/// # Returns
///
/// * `Ok(())` - If the CPU is supported.
/// * `Err(HypervisorError)` - If the CPU is not supported.
fn check_supported_cpu() -> Result<(), HypervisorError> {
    // Check if the CPU is Intel ("GenuineIntel")
    let cpuid_info = x86::cpuid::CpuId::new();
    let vendor_info = cpuid_info.get_vendor_info();

    let is_intel = vendor_info.map(|v| v.as_str() == "GenuineIntel").unwrap_or(false);

    if is_intel {
        info!("CPU is Intel");
    } else {
        return Err(HypervisorError::CPUUnsupported);
    }

    // Check if the CPU supports VMX
    let cpuid_feature_info = cpuid_info.get_feature_info();

    if let Some(ref feature_info) = cpuid_feature_info {
        if feature_info.has_vmx() {
            info!("Virtual Machine Extension (VMX) technology is supported");
        } else {
            return Err(HypervisorError::VMXUnsupported);
        }
    } else {
        return Err(HypervisorError::CPUUnsupported);
    }

    // Check if the CPU supports MTRRs (Memory Type Range Registers)
    if let Some(ref feature_info) = cpuid_feature_info {
        if feature_info.has_mtrr() {
            info!("Memory Type Range Registers (MTRRs) are supported");
        } else {
            return Err(HypervisorError::MTRRUnsupported);
        }
    } else {
        return Err(HypervisorError::CPUUnsupported);
    }

    // Check if the CPU supports EPT (Extended Page Tables)
    let vmx_ept_vpid_cap = rdmsr(IA32_VMX_EPT_VPID_CAP);
    let ept_supported = (vmx_ept_vpid_cap & (1 << 6)) != 0; // Bit 6: EPT support
    if ept_supported {
        info!("Extended Page Tables (EPT) are supported");
    } else {
        return Err(HypervisorError::EPTUnsupported);
    }

    Ok(())
}
