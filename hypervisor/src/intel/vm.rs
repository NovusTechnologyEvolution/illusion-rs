//! Manages the VMCS region for VMX operations within a virtualized environment.
//!
//! Offers functionality to configure and activate the VMCS (Virtual Machine Control Structure),
//! which is essential for executing and managing VMX operations on Intel CPUs. This includes
//! setting up guest and host states, managing memory with EPT (Extended Page Tables), and
//! handling VM-exit reasons for debugging and control purposes.

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
            vmlaunch_diagnostics::diagnose_guest_state_validity,
            vmxon::Vmxon,
        },
    },
    core::mem::MaybeUninit,
    log::*,
    x86::{
        bits64::rflags::RFlags,
        cpuid::{CpuId, FeatureInfo, cpuid},
        vmx::vmcs,
    },
};

/// Represents a Virtual Machine (VM) instance, encapsulating its state and control mechanisms.
///
/// This structure manages the VM's lifecycle, including setup, execution, and handling of VM-exits.
/// It holds the VMCS region, and paging information
/// and the state of guest registers. Additionally, it tracks whether the VM has been launched.
///
/// # Size
/// - Total size in bytes: 4,204,969 bytes (0x4010B9)
/// - Total size in pages: 1027 pages (0x403)
///
/// # Important Note
/// This structure is very large (~4.2MB) and MUST be allocated on the heap, never on the stack.
/// Use `Box::new_zeroed()` or an equivalent heap allocation method to allocate it safely.
pub struct Vm {
    /// The VMXON (Virtual Machine Extensions On) region for the VM.
    /// - Aligned to 4096 bytes (0x1000)
    pub vmxon_region: Vmxon,

    /// The VMCS (Virtual Machine Control Structure) for the VM.
    /// - Aligned to 4096 bytes (0x1000)
    pub vmcs_region: Vmcs,

    /// Paging tables for the host.
    /// - Pml4: 4096 bytes (0x1000)
    /// - Pdpt: 4096 bytes (0x1000)
    /// - Pd: 512 * 4096 bytes (since each Pd is 4096 bytes) (0x200000)
    /// - Total: 4096 + 4096 + (512 * 4096) = 2,096,128 bytes (0x200800)
    pub host_paging: PageTables,

    /// The primary EPT (Extended Page Tables) for the VM.
    /// - Pml4: 4096 bytes (0x1000)
    /// - Pdpt: 4096 bytes (0x1000)
    /// - Pd: 512 * 4096 bytes (0x200000)
    /// - Pt: 4096 bytes (0x1000)
    /// - Total: 4096 + 4096 + (512 * 4096) + 4096 = 2,100,224 bytes (0x201000)
    pub primary_ept: Ept,

    /// The primary EPTP (Extended Page Tables Pointer) for the VM.
    /// - Size: 8 bytes (0x8)
    pub primary_eptp: u64,

    /// State of guest general-purpose registers.
    /// - Size: 400 bytes (0x190)
    pub guest_registers: GuestRegisters,

    /// Flag indicating if the VM has been launched.
    /// - Size: 1 byte (0x1)
    pub has_launched: bool,

    /// The old RFLAGS value before turning off the interrupt flag.
    /// Used for restoring the RFLAGS register after handling the Monitor Trap Flag (MTF) VM exit.
    /// - Size: 8 bytes (Option<u64>) (0x8)
    pub old_rflags: Option<u64>,

    /// The number of times the MTF (Monitor Trap Flag) should be triggered before disabling it for restoring overwritten instructions.
    /// - Size: 8 bytes (Option<u64>) (0x8)
    pub mtf_counter: Option<u64>,

    /// The CPUID feature information for the VM.
    pub cpuid_feature_info: FeatureInfo,

    /// The CPUID extended feature information for the VM.
    pub xcr0_unsupported_mask: u64,
}

impl Vm {
    /// Creates a new zeroed VM instance.
    pub fn zeroed() -> MaybeUninit<Self> {
        MaybeUninit::zeroed()
    }

    /// Initializes a new VM instance with specified guest registers.
    ///
    /// Sets up the necessary environment for the VM, including VMCS initialization, host and guest
    /// descriptor tables, and paging structures. Prepares the VM for execution.
    ///
    /// # Arguments
    ///
    /// - `guest_registers`: The initial state of guest registers for the VM.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an `Err(HypervisorError)` if any part of the setup fails.
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
        self.guest_registers = guest_registers.clone();

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
    pub fn activate_vmxon(&mut self) -> Result<(), HypervisorError> {
        trace!("Setting up VMXON region");
        self.setup_vmxon()?;
        trace!("VMXON region setup successfully!");

        trace!("Executing VMXON instruction");
        vmxon(&self.vmxon_region as *const _ as _);
        trace!("VMXON executed successfully!");

        Ok(())
    }

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
    pub fn activate_vmcs(&mut self) -> Result<(), HypervisorError> {
        trace!("Activating VMCS");
        vmclear(&self.vmcs_region as *const _ as _);
        trace!("VMCLEAR successful!");

        vmptrld(&self.vmcs_region as *const _ as _);
        trace!("VMPTRLD successful!");

        self.setup_vmcs()?;
        trace!("VMCS activated successfully!");

        Ok(())
    }

    /// Configures the VMCS with necessary settings for guest and host state, and VM execution controls.
    pub fn setup_vmcs(&mut self) -> Result<(), HypervisorError> {
        trace!("Setting up VMCS");

        let primary_eptp = self.primary_eptp;

        let hook_manager = SHARED_HOOK_MANAGER.lock();
        let msr_bitmap = &hook_manager.msr_bitmap as *const _ as u64;

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
    pub fn run(&mut self) -> Result<VmxBasicExitReason, HypervisorError> {
        // For the first launch, dump guest state *before* VM-entry.
        if !self.has_launched {
            error!("=== Pre-VMLAUNCH guest state dump ===");
            diagnose_guest_state_validity();
        }

        // Run the VM until the VM-exit occurs (or VM-instruction failure).
        let flags_raw = unsafe { launch_vm(&mut self.guest_registers, u64::from(self.has_launched)) };
        trace!("VM-entry: launch_vm returned RFLAGS = 0x{:x}", flags_raw);

        let flags = RFlags::from_raw(flags_raw);

        if let Err(e) = Self::vm_succeed(flags) {
            error!("VM-entry failed; dumping guest state for diagnostics");
            diagnose_guest_state_validity();

            let vm_error = unsafe { vmread(vmcs::ro::VM_INSTRUCTION_ERROR) as u32 };
            error!("VM-instruction error code (raw): 0x{:x}", vm_error);

            return Err(e);
        }

        self.has_launched = true;
        // trace!("VM-exit occurred!");

        // VM-exit occurred. Copy the guest register values from VMCS so that
        // `self.guest_registers` is complete and up to date.
        self.guest_registers.rip = vmread(vmcs::guest::RIP);
        self.guest_registers.rsp = vmread(vmcs::guest::RSP);
        self.guest_registers.rflags = vmread(vmcs::guest::RFLAGS);

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
    fn vm_succeed(flags: RFlags) -> Result<(), HypervisorError> {
        if flags.contains(RFlags::FLAGS_ZF) {
            let instruction_error = vmread(vmcs::ro::VM_INSTRUCTION_ERROR) as u32;
            return match VmInstructionError::from_u32(instruction_error) {
                Some(error) => {
                    error!("VM instruction error: {:?}", error);
                    Err(HypervisorError::VmInstructionError)
                }
                None => {
                    error!("Unknown VM instruction error: 0x{:x}", instruction_error);
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
