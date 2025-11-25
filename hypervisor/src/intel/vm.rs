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
            vmlaunch::vmlaunch,
            vmxon::Vmxon,
        },
    },
    alloc::boxed::Box,
    log::{debug, error, trace},
    x86::{
        cpuid::{CpuId, cpuid},
        current::rflags::RFlags,
        vmx::vmcs,
    },
};

/// Minimal wrapper for CPU feature flags used by the hypervisor.
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

    /// I/O bitmap A (ports 0x0000-0x7FFF), 4KB aligned
    pub io_bitmap_a: Box<[u8; 4096]>,

    /// I/O bitmap B (ports 0x8000-0xFFFF plus one extra byte), 4KB aligned  
    pub io_bitmap_b: Box<[u8; 4096]>,
}

impl Vm {
    /// Create a new VM context from a captured register set.
    pub fn new(guest_registers: GuestRegisters) -> Self {
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
            io_bitmap_a: Box::new([0u8; 4096]),
            io_bitmap_b: Box::new([0u8; 4096]),
        }
    }

    /// One-time initialisation hook used by the higher-level VMM code.
    pub fn init(&mut self, guest_registers: &GuestRegisters) -> Result<(), HypervisorError> {
        trace!("Creating VM");

        trace!("Initializing VMXON region");
        self.vmxon_region.init();

        trace!("Initializing VMCS region");
        self.vmcs_region.init();

        trace!("Initializing Host Paging Tables");
        self.host_paging.init();

        trace!("Building Identity Paging for Host");
        debug!("Building identity map for page tables");
        self.host_paging.build_identity();
        debug!("Identity map built successfully");

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
        debug!("VM initialized");

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

        let io_bitmap_a = self.io_bitmap_a.as_ptr() as u64;
        let io_bitmap_b = self.io_bitmap_b.as_ptr() as u64;

        let descriptor_manager = SHARED_DESCRIPTOR_MANAGER.lock();

        let guest_descriptors = &descriptor_manager.guest_descriptor;
        let host_descriptors = &descriptor_manager.host_descriptor;

        let pml4_pa = self.host_paging.get_pml4_pa()?;

        Vmcs::setup_guest_registers_state(guest_descriptors, &self.guest_registers, pml4_pa);
        Vmcs::setup_host_registers_state(&host_descriptors, pml4_pa)?;
        Vmcs::setup_vmcs_control_fields(primary_eptp, msr_bitmap, io_bitmap_a, io_bitmap_b)?;

        trace!("VMCS setup successfully!");

        Ok(())
    }

    /// Executes the VM, running until the next VM-exit.
    ///
    /// Returns the decoded basic VM-exit reason if VM-entry succeeded.
    pub fn run(&mut self) -> Result<VmxBasicExitReason, HypervisorError> {
        // Set HOST_RSP dynamically before each VM-entry
        // Stack layout: CALL pushes return address (-8), launch_vm pushes 8 registers (-64)
        // Total: current_rsp - 72
        unsafe {
            let current_rsp: u64;
            core::arch::asm!(
                "mov {}, rsp",
                out(reg) current_rsp,
                options(nomem, nostack, preserves_flags)
            );

            let host_rsp_value = current_rsp - 72;
            vmwrite(vmcs::host::RSP, host_rsp_value);
        }

        // Clear VM-entry interrupt-information field if set (can cause issues)
        let vm_entry_intr_info = vmread(0x4016);
        if vm_entry_intr_info != 0 {
            vmwrite(0x4016, 0u32);
        }

        // Execute VMLAUNCH or VMRESUME
        let launched_value = if self.has_launched { 1u64 } else { 0u64 };
        let flags_raw = vmlaunch(&mut self.guest_registers, launched_value);

        // Interpret RFLAGS returned by the vmlaunch/vmresume stub
        let flags = RFlags::from_bits_truncate(flags_raw);

        // Check for VMLAUNCH/VMRESUME failure
        if flags.contains(RFlags::FLAGS_ZF) {
            let instruction_error = vmread(vmcs::ro::VM_INSTRUCTION_ERROR) as u32;
            error!("VMLAUNCH failed with VM instruction error: {:#x}", instruction_error);
            return match VmInstructionError::from_u32(instruction_error) {
                Some(error_enum) => {
                    error!("VM instruction error details: {:?}", error_enum);
                    Err(HypervisorError::VmInstructionError)
                }
                None => {
                    error!("Unknown VM instruction error code");
                    Err(HypervisorError::UnknownVMInstructionError)
                }
            };
        } else if flags.contains(RFlags::FLAGS_CF) {
            error!("VMLAUNCH failed with carry flag set (VMCS not loaded or corrupted)");
            return Err(HypervisorError::VMFailToLaunch);
        }

        // VM-entry succeeded; this VM has now been launched at least once
        self.has_launched = true;

        // Refresh cached guest architectural state from the VMCS
        self.guest_registers.rip = vmread(vmcs::guest::RIP);
        self.guest_registers.rsp = vmread(vmcs::guest::RSP);
        self.guest_registers.rflags = vmread(vmcs::guest::RFLAGS);

        // Decode and return the basic exit reason
        let exit_reason = vmread(vmcs::ro::EXIT_REASON) as u32;

        // DEBUG: Log every exit reason to diagnose hangs
        log::debug!("VM-exit reason: {:#x}, RIP: {:#x}", exit_reason, self.guest_registers.rip);

        let Some(basic_exit_reason) = VmxBasicExitReason::from_u32(exit_reason) else {
            error!("Unknown exit reason: 0x{:x}", exit_reason);
            return Err(HypervisorError::UnknownVMExitReason);
        };

        // Check if this is a VM-entry failure (exit reasons with bit 31 set)
        if (exit_reason & 0x80000000) != 0 {
            error!("VM-entry failure detected! Exit reason: {:#x}", exit_reason);
            let exit_qualification = vmread(vmcs::ro::EXIT_QUALIFICATION);
            error!("EXIT_QUALIFICATION: {:#x}", exit_qualification);
            return Err(HypervisorError::VMFailToLaunch);
        }

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
