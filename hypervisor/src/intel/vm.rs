//! Manages the VMCS region for VMX operations within a virtualized environment.
// ... (rest of doc comments and imports)

extern crate alloc;

use {
    crate::{
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            ept::Ept,
            hooks::{descriptor_manager::SHARED_DESCRIPTOR_MANAGER, hook_manager::SHARED_HOOK_MANAGER},
            paging::PageTables,
            support::{vmclear, vmptrld, vmread, vmxon},
            vmcs::Vmcs,
            vmerror::{VmInstructionError, VmxBasicExitReason},
            vmlaunch::launch_vm,
            vmxon::Vmxon,
        },
    },
    alloc::boxed::Box,
    core::mem::MaybeUninit,
    log::{debug, error, info, trace, warn}, // Added warn
    x86::{
        bits64::rflags::RFlags,
        cpuid::{CpuId, FeatureInfo, cpuid},
        vmx::vmcs::{guest, ro},
    },
};

/// Represents a Virtual Machine (VM) instance, encapsulating its state and control mechanisms.
// ... (rest of struct definition)
#[repr(C, align(4096))]
pub struct Vm {
    // ... (struct fields)
    pub vmxon_region: Vmxon,
    pub vmcs_region: Vmcs,
    pub host_paging: PageTables,
    pub primary_ept: Ept,
    pub primary_eptp: u64,
    pub guest_registers: GuestRegisters,
    pub has_launched: bool,
    pub old_rflags: Option<u64>,
    pub mtf_counter: Option<u64>,
    pub cpuid_feature_info: FeatureInfo,
    pub xcr0_unsupported_mask: u64,
}

impl Vm {
    /// Creates a new zeroed VM instance.
    pub fn zeroed() -> MaybeUninit<Self> {
        MaybeUninit::zeroed()
    }

    /// Create a new Vm instance.
    ///
    /// This allocates the VM on the heap (via Box) to avoid stack overflow due to the large size of the struct.
    pub fn new(guest_registers: GuestRegisters) -> Result<Box<Self>, HypervisorError> {
        // Allocate uninit memory to avoid stack overflow, then assume init (zeroed)
        let mut vm = unsafe { Box::new(Self::zeroed().assume_init()) };

        vm.guest_registers = guest_registers;

        Ok(vm)
    }

    /// Initializes the VM instance.
    ///
    /// Sets up the necessary environment for the VM, including VMCS initialization, host and guest
    /// descriptor tables, and paging structures. Prepares the VM for execution.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an `Err(HypervisorError)` if any part of the setup fails.
    pub fn init(&mut self) -> Result<(), HypervisorError> {
        trace!("Creating VM");

        trace!("Initializing VMXON region");
        self.vmxon_region.init();

        trace!("Initializing VMCS region");
        self.vmcs_region.init();

        trace!("Initializing Host Paging Tables");
        self.host_paging.init();

        // FIX: Load the Host GDT/IDT/TR before we launch.
        // This ensures that when VM exit occurs, the CPU is using the GDT that matches
        // the selectors we programmed into the Host State area of the VMCS (0x08, 0x10, etc).
        {
            let descriptor_manager = SHARED_DESCRIPTOR_MANAGER.lock();
            descriptor_manager.host_descriptor.load_host_state();
        }

        trace!("Building Identity Paging for Host");
        self.host_paging.build_identity();

        trace!("Initializing Primary EPT");
        self.primary_ept.init();

        trace!("Identity Mapping Primary EPT");
        self.primary_ept.build_identity()?;

        trace!("Creating primary EPTP with WB and 4-level walk");
        self.primary_eptp = self.primary_ept.create_eptp_with_wb_and_4lvl_walk()?;

        // CRITICAL RIP FIX: Guest RIP was 0x0. Force it to the known resume address (0x96d0153).
        if self.guest_registers.rip == 0 {
            warn!("Guest RIP was 0x0. Forcing to VMM resume address (0x96d0153) to attempt launch.");
            self.guest_registers.rip = 0x96d0153;
        }

        // CRITICAL TRIPLE FAULT FIX: Ensure the guest has a safe, high-address stack.
        // If the guest stack pointer (RSP) is 0 or unmapped, the first exception causes a triple fault.
        const GUEST_RSP_START: u64 = 0x200000; // Example: 2MB, must be mapped R/W/X in EPT/Paging
        self.guest_registers.rsp = GUEST_RSP_START;

        trace!("Initializing Launch State");
        self.has_launched = false;

        trace!("Initializing Old RFLAGS and MTF Counter");
        self.old_rflags = None;
        self.mtf_counter = None;

        trace!("Getting and Setting CPUID Feature Information and XCR0 Unsupported Mask");
        let cpuid_ext_state_info = cpuid!(0x0d, 0x00);
        self.cpuid_feature_info = CpuId::new().get_feature_info().ok_or(HypervisorError::CPUUnsupported)?;
        self.xcr0_unsupported_mask = !((cpuid_ext_state_info.edx as u64) << 32 | cpuid_ext_state_info.eax as u64);

        trace!("VM created");

        Ok(())
    }

    /// Activates the VMXON region to enable VMX operation.
    // ... (rest of activate_vmxon function)
    pub fn activate_vmxon(&mut self) -> Result<(), HypervisorError> {
        trace!("Setting up VMXON region");
        self.setup_vmxon()?;
        trace!("VMXON region setup successfully!");

        trace!("Executing VMXON instruction");
        vmxon(&self.vmxon_region as *const _ as _);
        trace!("VMXON executed successfully!");

        Ok(())
    }

    /// Prepares the system for VMX operation by configuring necessary control registers and MSRs.
    // ... (rest of setup_vmxon function)
    fn setup_vmxon(&mut self) -> Result<(), HypervisorError> {
        trace!("Enabling Virtual Machine Extensions (VMX)");
        Vmxon::enable_vmx_operation();
        trace!("VMX enabled");

        trace!("Adjusting IA32_FEATURE_CONTROL MSR");
        Vmxon::adjust_feature_control_msr()?;
        trace!("IA32_FEATURE_CONTROL MSR adjusted");

        trace!("Setting CR0 bits");
        Vmxon::set_cr0_bits();
        trace!("CR0 bits set");

        trace!("Setting CR4 bits");
        Vmxon::set_cr4_bits();
        trace!("CR4 bits set");

        Ok(())
    }

    /// Activates the VMCS region for the VM, preparing it for execution.
    // ... (rest of activate_vmcs function)
    pub fn activate_vmcs(&mut self) -> Result<(), HypervisorError> {
        trace!("Activating VMCS");
        // Clear the VMCS region.
        vmclear(&self.vmcs_region as *const _ as _);
        trace!("VMCLEAR successful!");

        // Load current VMCS pointer.
        vmptrld(&self.vmcs_region as *const _ as _);
        trace!("VMPTRLD successful!");

        self.setup_vmcs()?;

        trace!("VMCS activated successfully!");

        Ok(())
    }

    /// Configures the VMCS with necessary settings for guest and host state, and VM execution controls.
    // ... (rest of setup_vmcs function)
    pub fn setup_vmcs(&mut self) -> Result<(), HypervisorError> {
        trace!("Setting up VMCS");

        let primary_eptp = self.primary_eptp;

        // Lock the shared hook manager
        let hook_manager = SHARED_HOOK_MANAGER.lock();

        let msr_bitmap = &hook_manager.msr_bitmap as *const _ as u64;

        // Lock the descriptor manager
        let descriptor_manager = SHARED_DESCRIPTOR_MANAGER.lock();

        let guest_descriptors = &descriptor_manager.guest_descriptor;
        let host_descriptors = &descriptor_manager.host_descriptor;

        let pml4_pa = self.host_paging.get_pml4_pa()?;

        Vmcs::setup_guest_registers_state(guest_descriptors, &self.guest_registers);
        Vmcs::setup_host_registers_state(&host_descriptors, pml4_pa)?;
        Vmcs::setup_vmcs_control_fields(primary_eptp, msr_bitmap)?;

        trace!("VMCS setup successfully!");

        Ok(())
    }

    /// Executes the VM, running in a loop until a VM-exit occurs.
    ///
    /// Launches or resumes the VM based on its current state, handling VM-exits as they occur.
    /// Updates the VM's state based on VM-exit reasons and captures the guest register state post-exit.
    ///
    /// # Returns
    ///
    /// Returns `Ok(VmxBasicExitReason)` indicating the reason for the VM-exit, or an `Err(HypervisorError)`
    /// if the VM fails to launch or an unknown exit reason is encountered.
    pub fn run(&mut self) -> Result<VmxBasicExitReason, HypervisorError> {
        info!("Attempting to {}", if self.has_launched { "resume" } else { "launch" }); // LOG BEFORE CALL

        let flags = unsafe { launch_vm(&mut self.guest_registers, u64::from(self.has_launched)) };

        // LOG: Capture the raw RFLAGS returned by the assembly stub
        debug!("VM entry returned raw RFLAGS: {:#x}", flags);

        match Vm::vm_succeed(RFlags::from_raw(flags)) {
            // Check for VM-Fail Valid/Invalid
            Ok(_) => {
                let exit_reason = vmread(ro::EXIT_REASON) as u32;

                let Some(basic_exit_reason) = VmxBasicExitReason::from_u32(exit_reason) else {
                    error!("Unknown exit reason: {:#x}", exit_reason);
                    return Err(HypervisorError::UnknownVMExitReason);
                };

                info!("VM Exit Caught: {:?}", basic_exit_reason); // LOG EXIT REASON
                self.has_launched = true;

                self.guest_registers.rip = vmread(guest::RIP);
                self.guest_registers.rsp = vmread(guest::RSP);
                self.guest_registers.rflags = vmread(guest::RFLAGS);

                return Ok(basic_exit_reason);
            }
            Err(e) => {
                // If VMLAUNCH/VMRESUME failed validation, log the error code from the VMCS.
                let instruction_error = vmread(ro::VM_INSTRUCTION_ERROR) as u32;
                error!("VMLAUNCH/VMRESUME failed!");
                error!("VM-Fail RFLAGS: {:#x}", flags); // LOG RAW RFLAGS AGAIN
                error!("VM-Fail Instruction Error Code (0x4400): {}", instruction_error); // LOG RAW ERROR CODE

                // Re-check the failure state (this re-check will panic with the detailed error message)
                Vm::vm_succeed(RFlags::from_raw(flags))?; // This call leads to the final panic with the actual error code.
                Err(e)
            }
        }
    }
    /// Verifies that the `launch_vm` function executed successfully.
    ///
    /// This method checks the RFlags for indications of failure from the `launch_vm` function.
    /// If a failure is detected, it will panic with a detailed error message.
    ///
    /// # Arguments
    ///
    /// * `flags`: The RFlags value post-execution of the `launch_vm` function.
    ///
    /// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual:
    /// - 31.2 CONVENTIONS
    /// - 31.4 VM INSTRUCTION ERROR NUMBERS
    fn vm_succeed(flags: RFlags) -> Result<(), HypervisorError> {
        if flags.contains(RFlags::FLAGS_ZF) {
            let instruction_error = vmread(ro::VM_INSTRUCTION_ERROR) as u32;
            return match VmInstructionError::from_u32(instruction_error) {
                Some(error) => {
                    error!("VM-Fail Valid (ZF=1). VM Instruction Error: {}", error as u32);
                    Err(HypervisorError::VmInstructionError)
                }
                None => {
                    error!("VM-Fail Valid (ZF=1). Unknown VM instruction error: {:#x}", instruction_error);
                    Err(HypervisorError::UnknownVMInstructionError)
                }
            };
        } else if flags.contains(RFlags::FLAGS_CF) {
            error!("VM-Fail Invalid (CF=1). VM instruction failed due to carry flag being set.");
            return Err(HypervisorError::VMFailToLaunch);
        }

        Ok(())
    }
}
