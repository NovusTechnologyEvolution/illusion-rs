//! High-level VM execution helpers for Intel VMX.

use {
    crate::{
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            ept::Ept,
            hooks::{descriptor_manager::SHARED_DESCRIPTOR_MANAGER, hook_manager::SHARED_HOOK_MANAGER},
            paging::PageTables,
            support::{vmclear, vmptrld, vmread, vmwrite, vmxon},
            vmcs::Vmcs,
            vmerror::{VmInstructionError, VmxBasicExitReason},
            vmlaunch::launch_vm,
            vmlaunch_diagnostics::{diagnose_guest_state_validity, diagnose_host_state_validity},
            vmxon::Vmxon,
        },
    },
    log::{error, info, trace},
    x86::{
        cpuid::{CpuId, cpuid},
        current::rflags::RFlags,
        vmx::vmcs,
    },
};

/// Minimal wrapper for CPU feature flags used by the hypervisor.
///
/// Other modules only need to know whether the processor supports SMX.
/// The concrete representation isn't important as long as the `has_smx`
/// query is available.
#[derive(Debug, Clone, Copy)]
pub struct CpuidFeatureInfo {
    has_smx: bool,
}

impl CpuidFeatureInfo {
    pub fn new() -> Self {
        let cpuid = CpuId::new();
        let has_smx = cpuid.get_feature_info().map(|fi| fi.has_smx()).unwrap_or(false);

        Self { has_smx }
    }

    #[inline]
    pub fn has_smx(&self) -> bool {
        self.has_smx
    }
}

/// Per-vCPU virtual machine state.
///
/// Several other modules access extra fields on `Vm` (EPT, monitor-trap
/// state, etc.). Those fields live here so their code can compile
/// unchanged.
pub struct Vm {
    /// The VMXON (Virtual Machine Extensions On) region for the VM.
    pub vmxon_region: Vmxon,

    /// The VMCS (Virtual Machine Control Structure) for the VM.
    pub vmcs_region: Vmcs,

    /// Paging tables for the host.
    pub host_paging: PageTables,

    /// The primary EPT (Extended Page Tables) for the VM.
    pub primary_ept: Ept,

    /// The primary EPTP (Extended Page Tables Pointer) for the VM.
    pub primary_eptp: u64,

    /// General-purpose registers saved/restored by the VM-entry/exit assembly stubs.
    pub guest_registers: GuestRegisters,

    /// Whether this VM has already executed at least one successful VM-entry.
    pub has_launched: bool,

    /// Optional single-step / MTF instruction counter.
    pub mtf_counter: Option<u64>,

    /// Previous RFLAGS value used by the MTF logic.
    pub old_rflags: Option<u64>,

    /// Mask of XCR0 bits that are *not* supported by the host.
    pub xcr0_unsupported_mask: u64,

    /// Cached CPUID feature information.
    pub cpuid_feature_info: CpuidFeatureInfo,
}

impl Vm {
    /// Create a new VM context from a captured register set.
    pub fn new(guest_registers: GuestRegisters) -> Self {
        // It is safe to zero these plain-old-data structures before
        // calling their own initialisers.
        let vmxon_region: Vmxon = unsafe { core::mem::zeroed() };
        let vmcs_region: Vmcs = unsafe { core::mem::zeroed() };
        let host_paging: PageTables = unsafe { core::mem::zeroed() };
        let primary_ept: Ept = unsafe { core::mem::zeroed() };

        Self {
            vmxon_region,
            vmcs_region,
            host_paging,
            primary_ept,
            primary_eptp: 0,
            guest_registers,
            has_launched: false,
            mtf_counter: None,
            old_rflags: None,
            xcr0_unsupported_mask: 0,
            cpuid_feature_info: CpuidFeatureInfo::new(),
        }
    }

    /// One-time initialisation hook used by the higher-level VMM code.
    ///
    /// This wires up the EPT identity map and initialises the VMCS
    /// revision ID.  More advanced configuration (VMXON, VMCS
    /// activation, etc.) is handled in dedicated helpers so that the
    /// call-sites in `vmm.rs` can remain unchanged.
    pub fn init(&mut self, guest_registers: &GuestRegisters) -> Result<(), HypervisorError> {
        trace!("Creating VM");

        trace!("Initializing VMXON region");
        self.vmxon_region.init();

        trace!("Initializing VMCS region");
        self.vmcs_region.init();

        trace!("Initializing Host Paging Tables");
        self.host_paging.init();

        trace!("Building Identity Paging for Host");
        self.host_paging.build_identity();

        trace!("Initializing Primary EPT");
        self.primary_ept.init();

        trace!("Identity Mapping Primary EPT");
        self.primary_ept.build_identity()?;

        trace!("Creating primary EPTP with WB and 4-level walk");
        self.primary_eptp = self.primary_ept.create_eptp_with_wb_and_4lvl_walk()?;

        trace!("Initializing Guest Registers");
        self.guest_registers = *guest_registers;

        trace!("Initializing Launch State");
        self.has_launched = false;

        trace!("Initializing Old RFLAGS and MTF Counter");
        self.old_rflags = None;
        self.mtf_counter = None;

        trace!("Getting and Setting CPUID Feature Information and XCR0 Unsupported Mask");
        let cpuid_ext_state_info = cpuid!(0x0d, 0x00);
        self.cpuid_feature_info = CpuidFeatureInfo::new();
        self.xcr0_unsupported_mask = !((cpuid_ext_state_info.edx as u64) << 32 | cpuid_ext_state_info.eax as u64);

        trace!("VM created");

        Ok(())
    }

    /// Activates the VMXON region to enable VMX operation.
    ///
    /// Sets up the VMXON region and executes the VMXON instruction. This involves configuring control registers,
    /// adjusting the IA32_FEATURE_CONTROL MSR, and validating the VMXON region's revision ID to ensure the CPU is ready
    /// for VMX operation mode.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful activation, or an `Err(HypervisorError)` if any step in the activation process fails.
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
    ///
    /// Ensures that the system meets all prerequisites for VMX operation as defined by Intel's specifications.
    /// This includes enabling VMX operation through control register modifications, setting the lock bit in
    /// IA32_FEATURE_CONTROL MSR, and adjusting mandatory CR0 and CR4 bits.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all configurations are successfully applied, or an `Err(HypervisorError)` if adjustments fail.
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
    ///
    /// Clears and loads the VMCS region, setting it as the current VMCS for VMX operations.
    /// Calls `setup_vmcs` to configure the VMCS with guest, host, and control settings.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful activation, or an `Err(HypervisorError)` if activation fails.
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
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if VMCS setup is successful, or an `Err(HypervisorError)` for setup failures.
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

        Vmcs::setup_guest_registers_state(guest_descriptors, &self.guest_registers, pml4_pa);
        Vmcs::setup_host_registers_state(&host_descriptors, pml4_pa)?;
        Vmcs::setup_vmcs_control_fields(primary_eptp, msr_bitmap)?;

        trace!("VMCS setup successfully!");

        Ok(())
    }

    /// Executes the VM, running until the next VM-exit.
    ///
    /// Returns the decoded basic VM-exit reason if VM-entry succeeded.
    pub fn run(&mut self) -> Result<VmxBasicExitReason, HypervisorError> {
        // Set Host RSP to current stack pointer for diagnostics
        // The assembly stub will set it again right before VMLAUNCH
        let current_rsp: u64;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, nostack, preserves_flags));
        }
        vmwrite(vmcs::host::RSP, current_rsp);

        // For the first launch, dump BOTH guest and host state *before* VM-entry.
        if !self.has_launched {
            error!("=== Pre-VMLAUNCH diagnostics ===");
            diagnose_guest_state_validity();
            diagnose_host_state_validity();

            // Verify EPT translation for guest RIP
            let guest_rip = vmread(vmcs::guest::RIP);
            error!("=== EPT TRANSLATION CHECK ===");
            error!("Verifying EPT translation for guest RIP: {:#x}", guest_rip);

            // Extract EPT PML4 base from EPTP (bits 51:12)
            let ept_pml4_base = self.primary_eptp & !0xFFF;
            error!("EPT PML4 base: {:#x}", ept_pml4_base);

            match unsafe { Ept::translate_guest_pa_to_host_pa(ept_pml4_base, guest_rip) } {
                Ok(host_pa) => {
                    error!("  SUCCESS: EPT translates guest PA {:#x} -> host PA {:#x}", guest_rip, host_pa);
                    // Try to read the first few bytes at this address
                    let ptr = host_pa as *const u8;
                    let bytes = unsafe { core::slice::from_raw_parts(ptr, 16) };
                    error!("  First 16 bytes at host PA: {:02x?}", bytes);
                    error!("  Expected HLT instruction (0xF4) at start");
                }
                Err(e) => {
                    error!("  ERROR: EPT translation failed: {:?}", e);
                    error!("  This means the EPT doesn't have a valid mapping for guest RIP!");
                }
            }
        }

        // Run the VM until the VM-exit occurs (or VM-instruction failure).
        error!("=== ABOUT TO CALL launch_vm ===");
        error!("launch_vm function address: {:#x}", launch_vm as usize);
        error!("guest_registers address: {:#x}", &self.guest_registers as *const _ as usize);
        error!("has_launched value: {}", self.has_launched);

        // Sanity check: verify VMCS is loaded by reading a field
        let test_read = vmread(vmcs::guest::RIP);
        error!("Sanity check - can read VMCS, Guest RIP: {:#x}", test_read);

        let flags_raw = unsafe { launch_vm(&mut self.guest_registers, u64::from(self.has_launched)) };

        // Log immediately after launch_vm returns
        error!("=== POST-VMLAUNCH: launch_vm returned ===");
        error!("Returned RFLAGS: 0x{:016x}", flags_raw);

        trace!("VM-entry: launch_vm returned RFLAGS = 0x{:x}", flags_raw);

        // Interpret RFLAGS returned by the vmlaunch/vmresume stub.
        let flags = RFlags::from_bits_truncate(flags_raw);

        // Check whether the VM-entry instruction succeeded.
        Self::vm_succeed(flags)?;

        // VM-entry succeeded; this VM has now been launched at least once.
        self.has_launched = true;

        // Refresh cached guest architectural state from the VMCS.
        self.guest_registers.rip = vmread(vmcs::guest::RIP);
        self.guest_registers.rsp = vmread(vmcs::guest::RSP);
        self.guest_registers.rflags = vmread(vmcs::guest::RFLAGS);

        // Decode and return the basic exit reason.
        let exit_reason = vmread(vmcs::ro::EXIT_REASON) as u32;
        trace!("VM-exit: raw EXIT_REASON = 0x{:x}", exit_reason);

        let Some(basic_exit_reason) = VmxBasicExitReason::from_u32(exit_reason) else {
            error!("Unknown exit reason: 0x{:x}", exit_reason);
            return Err(HypervisorError::UnknownVMExitReason);
        };

        info!("VM-exit: {:?}", basic_exit_reason);

        Ok(basic_exit_reason)
    }

    /// Verifies that the `launch_vm` function executed successfully.
    ///
    /// This method checks the RFlags for indications of failure from the `launch_vm` function.
    /// If a failure is detected, it will return an error with details.
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
            let instruction_error = vmread(vmcs::ro::VM_INSTRUCTION_ERROR) as u32;
            return match VmInstructionError::from_u32(instruction_error) {
                Some(error) => {
                    error!("VM instruction error: {:?}", error);
                    Err(HypervisorError::VmInstructionError)
                }
                None => {
                    error!("Unknown VM instruction error: {:#x}", instruction_error);
                    Err(HypervisorError::UnknownVMInstructionError)
                }
            };
        } else if flags.contains(RFlags::FLAGS_CF) {
            error!("VM instruction failed due to carry flag being set");
            return Err(HypervisorError::VMFailToLaunch);
        }

        Ok(())
    }
}
