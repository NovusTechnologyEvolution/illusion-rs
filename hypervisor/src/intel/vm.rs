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

        // Lock the hook manager and configure MSR interception
        {
            let mut hook_manager = SHARED_HOOK_MANAGER.lock();

            // CRITICAL: Since VMware doesn't support LOAD_IA32_EFER on VM-entry,
            // we must intercept EFER writes to maintain proper guest EFER state.
            // We only intercept WRITES - not reads. Reading EFER directly from
            // the hardware is fine since we keep the actual MSR in sync with
            // what the guest expects via write interception.
            //
            // NOTE: Do NOT intercept EFER reads - the bootloader reads EFER
            // thousands of times and intercepting would cause massive VM-exit
            // overhead and boot stalls.
            use crate::intel::bitmap::{MsrAccessType, MsrOperation};
            hook_manager
                .msr_bitmap
                .modify_msr_interception(x86::msr::IA32_EFER, MsrAccessType::Write, MsrOperation::Hook);
            trace!("EFER MSR write interception enabled");
        }

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

    /// Dumps comprehensive guest state for debugging VM-entry failures.
    fn dump_vmentry_failure_diagnostics(&self) {
        error!("=== VM-ENTRY FAILURE DIAGNOSTICS ===");

        // VM instruction error (if ZF was set)
        let vm_instr_error = vmread(vmcs::ro::VM_INSTRUCTION_ERROR);
        error!("VM_INSTRUCTION_ERROR: {:#x}", vm_instr_error);

        // Exit qualification
        let exit_qual = vmread(vmcs::ro::EXIT_QUALIFICATION);
        error!("EXIT_QUALIFICATION: {:#x}", exit_qual);

        // VM-entry interruption info (was an event being injected?)
        let entry_intr_info = vmread(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD);
        error!("VMENTRY_INTERRUPTION_INFO: {:#x}", entry_intr_info);
        if (entry_intr_info & 0x80000000) != 0 {
            let vector = entry_intr_info & 0xFF;
            let intr_type = (entry_intr_info >> 8) & 0x7;
            let deliver_error = (entry_intr_info >> 11) & 0x1;
            error!("  Valid=1, Vector={}, Type={}, DeliverErrorCode={}", vector, intr_type, deliver_error);
            if deliver_error != 0 {
                let error_code = vmread(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE);
                error!("  VMENTRY_EXCEPTION_ERROR_CODE: {:#x}", error_code);
            }
        }

        error!("--- Guest Control Registers ---");
        let guest_cr0 = vmread(vmcs::guest::CR0);
        let guest_cr3 = vmread(vmcs::guest::CR3);
        let guest_cr4 = vmread(vmcs::guest::CR4);
        error!("Guest CR0: {:#x}", guest_cr0);
        error!("  PE={} PG={} WP={} NE={}", (guest_cr0 >> 0) & 1, (guest_cr0 >> 31) & 1, (guest_cr0 >> 16) & 1, (guest_cr0 >> 5) & 1);
        error!("Guest CR3: {:#x}", guest_cr3);
        error!("Guest CR4: {:#x}", guest_cr4);
        error!(
            "  PAE={} PSE={} VMXE={} PCIDE={} CET={}",
            (guest_cr4 >> 5) & 1,
            (guest_cr4 >> 4) & 1,
            (guest_cr4 >> 13) & 1,
            (guest_cr4 >> 17) & 1,
            (guest_cr4 >> 23) & 1
        );

        // CR0/CR4 shadows and masks
        let cr0_shadow = vmread(vmcs::control::CR0_READ_SHADOW);
        let cr4_shadow = vmread(vmcs::control::CR4_READ_SHADOW);
        let cr0_mask = vmread(vmcs::control::CR0_GUEST_HOST_MASK);
        let cr4_mask = vmread(vmcs::control::CR4_GUEST_HOST_MASK);
        error!("CR0 Shadow: {:#x}, Mask: {:#x}", cr0_shadow, cr0_mask);
        error!("CR4 Shadow: {:#x}, Mask: {:#x}", cr4_shadow, cr4_mask);

        error!("--- Guest EFER and RFLAGS ---");
        let guest_efer = vmread(vmcs::guest::IA32_EFER_FULL);
        let guest_rflags = vmread(vmcs::guest::RFLAGS);
        error!("Guest EFER: {:#x}", guest_efer);
        error!("  LME={} LMA={} NXE={} SCE={}", (guest_efer >> 8) & 1, (guest_efer >> 10) & 1, (guest_efer >> 11) & 1, (guest_efer >> 0) & 1);
        error!("Guest RFLAGS: {:#x}", guest_rflags);
        error!("  IF={} TF={} VM={} RF={}", (guest_rflags >> 9) & 1, (guest_rflags >> 8) & 1, (guest_rflags >> 17) & 1, (guest_rflags >> 16) & 1);

        error!("--- Guest RIP/RSP ---");
        let guest_rip = vmread(vmcs::guest::RIP);
        let guest_rsp = vmread(vmcs::guest::RSP);
        error!("Guest RIP: {:#x}", guest_rip);
        error!("Guest RSP: {:#x}", guest_rsp);

        error!("--- Guest Segment State ---");
        // CS
        let cs_sel = vmread(vmcs::guest::CS_SELECTOR);
        let cs_base = vmread(vmcs::guest::CS_BASE);
        let cs_limit = vmread(vmcs::guest::CS_LIMIT);
        let cs_ar = vmread(vmcs::guest::CS_ACCESS_RIGHTS);
        error!("CS: sel={:#x} base={:#x} limit={:#x} ar={:#x}", cs_sel, cs_base, cs_limit, cs_ar);
        error!(
            "  Type={} S={} DPL={} P={} L={} D/B={} G={} Unusable={}",
            cs_ar & 0xF,
            (cs_ar >> 4) & 1,
            (cs_ar >> 5) & 3,
            (cs_ar >> 7) & 1,
            (cs_ar >> 13) & 1,
            (cs_ar >> 14) & 1,
            (cs_ar >> 15) & 1,
            (cs_ar >> 16) & 1
        );

        // SS
        let ss_sel = vmread(vmcs::guest::SS_SELECTOR);
        let ss_base = vmread(vmcs::guest::SS_BASE);
        let ss_limit = vmread(vmcs::guest::SS_LIMIT);
        let ss_ar = vmread(vmcs::guest::SS_ACCESS_RIGHTS);
        error!("SS: sel={:#x} base={:#x} limit={:#x} ar={:#x}", ss_sel, ss_base, ss_limit, ss_ar);
        error!(
            "  Type={} S={} DPL={} P={} L={} D/B={} G={} Unusable={}",
            ss_ar & 0xF,
            (ss_ar >> 4) & 1,
            (ss_ar >> 5) & 3,
            (ss_ar >> 7) & 1,
            (ss_ar >> 13) & 1,
            (ss_ar >> 14) & 1,
            (ss_ar >> 15) & 1,
            (ss_ar >> 16) & 1
        );

        // DS
        let ds_sel = vmread(vmcs::guest::DS_SELECTOR);
        let ds_ar = vmread(vmcs::guest::DS_ACCESS_RIGHTS);
        error!("DS: sel={:#x} ar={:#x} Unusable={}", ds_sel, ds_ar, (ds_ar >> 16) & 1);

        // ES
        let es_sel = vmread(vmcs::guest::ES_SELECTOR);
        let es_ar = vmread(vmcs::guest::ES_ACCESS_RIGHTS);
        error!("ES: sel={:#x} ar={:#x} Unusable={}", es_sel, es_ar, (es_ar >> 16) & 1);

        // FS
        let fs_sel = vmread(vmcs::guest::FS_SELECTOR);
        let fs_base = vmread(vmcs::guest::FS_BASE);
        let fs_ar = vmread(vmcs::guest::FS_ACCESS_RIGHTS);
        error!("FS: sel={:#x} base={:#x} ar={:#x} Unusable={}", fs_sel, fs_base, fs_ar, (fs_ar >> 16) & 1);

        // GS
        let gs_sel = vmread(vmcs::guest::GS_SELECTOR);
        let gs_base = vmread(vmcs::guest::GS_BASE);
        let gs_ar = vmread(vmcs::guest::GS_ACCESS_RIGHTS);
        error!("GS: sel={:#x} base={:#x} ar={:#x} Unusable={}", gs_sel, gs_base, gs_ar, (gs_ar >> 16) & 1);

        // TR (Task Register) - often a source of issues!
        let tr_sel = vmread(vmcs::guest::TR_SELECTOR);
        let tr_base = vmread(vmcs::guest::TR_BASE);
        let tr_limit = vmread(vmcs::guest::TR_LIMIT);
        let tr_ar = vmread(vmcs::guest::TR_ACCESS_RIGHTS);
        error!("TR: sel={:#x} base={:#x} limit={:#x} ar={:#x}", tr_sel, tr_base, tr_limit, tr_ar);
        error!(
            "  Type={} (should be 0xB=Busy TSS) S={} DPL={} P={} Unusable={}",
            tr_ar & 0xF,
            (tr_ar >> 4) & 1,
            (tr_ar >> 5) & 3,
            (tr_ar >> 7) & 1,
            (tr_ar >> 16) & 1
        );

        // LDTR
        let ldtr_sel = vmread(vmcs::guest::LDTR_SELECTOR);
        let ldtr_ar = vmread(vmcs::guest::LDTR_ACCESS_RIGHTS);
        error!("LDTR: sel={:#x} ar={:#x} Unusable={}", ldtr_sel, ldtr_ar, (ldtr_ar >> 16) & 1);

        // GDTR/IDTR
        let gdtr_base = vmread(vmcs::guest::GDTR_BASE);
        let gdtr_limit = vmread(vmcs::guest::GDTR_LIMIT);
        let idtr_base = vmread(vmcs::guest::IDTR_BASE);
        let idtr_limit = vmread(vmcs::guest::IDTR_LIMIT);
        error!("GDTR: base={:#x} limit={:#x}", gdtr_base, gdtr_limit);
        error!("IDTR: base={:#x} limit={:#x}", idtr_base, idtr_limit);

        error!("--- Activity and Interruptibility ---");
        let activity_state = vmread(vmcs::guest::ACTIVITY_STATE);
        let interruptibility = vmread(vmcs::guest::INTERRUPTIBILITY_STATE);
        let pending_dbg = vmread(vmcs::guest::PENDING_DBG_EXCEPTIONS);
        error!("Activity State: {} (0=Active, 1=HLT, 2=Shutdown, 3=Wait-for-SIPI)", activity_state);
        error!("Interruptibility State: {:#x}", interruptibility);
        error!(
            "  STI blocking={} MOV-SS blocking={} SMI blocking={} NMI blocking={}",
            interruptibility & 1,
            (interruptibility >> 1) & 1,
            (interruptibility >> 2) & 1,
            (interruptibility >> 3) & 1
        );
        error!("Pending Debug Exceptions: {:#x}", pending_dbg);

        error!("--- VM-Entry Controls ---");
        let entry_controls = vmread(vmcs::control::VMENTRY_CONTROLS);
        error!("VM-Entry Controls: {:#x}", entry_controls);
        error!(
            "  LOAD_DEBUG_CONTROLS={} IA32E_MODE_GUEST={} LOAD_IA32_EFER={}",
            (entry_controls >> 2) & 1,
            (entry_controls >> 9) & 1,
            (entry_controls >> 15) & 1
        );

        error!("--- Primary/Secondary Proc Controls ---");
        let primary_proc = vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS);
        let secondary_proc = vmread(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS);
        error!("Primary Proc Controls: {:#x}", primary_proc);
        error!("Secondary Proc Controls: {:#x}", secondary_proc);
        error!("  UNRESTRICTED_GUEST={}", (secondary_proc >> 7) & 1);

        error!("--- VMX Preemption Timer ---");
        let preempt_value = vmread(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE);
        error!("VMX Preemption Timer Value: {:#x}", preempt_value);

        error!("=== END VM-ENTRY FAILURE DIAGNOSTICS ===");
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

        // CRITICAL FIX: DO NOT clear VMENTRY_INTERRUPTION_INFO here!
        // The old code was clearing event injection set up by exception handlers:
        //
        //   let vm_entry_intr_info = vmread(0x4016);
        //   if vm_entry_intr_info != 0 {
        //       vmwrite(0x4016, 0u32);  // <-- THIS WAS BREAKING EXCEPTION INJECTION
        //   }
        //
        // When handle_exception() sets up a #PF, #GP, or #UD to be re-injected
        // to the guest, clearing this field prevents the exception from ever
        // being delivered. The guest thinks it was handled but it wasn't,
        // leading to state corruption and eventual triple fault.
        //
        // The hardware automatically clears this field after successful VM-entry,
        // so there's no need for manual clearing.

        // Log if we're about to inject an event (for debugging)
        let pending_injection = vmread(0x4016); // VMENTRY_INTERRUPTION_INFO_FIELD
        if pending_injection & 0x80000000 != 0 {
            let vector = pending_injection & 0xFF;
            let intr_type = (pending_injection >> 8) & 0x7;
            trace!("VM-entry with pending event injection: vector={}, type={}", vector, intr_type);
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
            self.dump_vmentry_failure_diagnostics();
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
            self.dump_vmentry_failure_diagnostics();
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

        let Some(basic_exit_reason) = VmxBasicExitReason::from_u32(exit_reason) else {
            error!("Unknown exit reason: 0x{:x}", exit_reason);
            return Err(HypervisorError::UnknownVMExitReason);
        };

        // Check if this is a VM-entry failure (exit reasons with bit 31 set)
        if (exit_reason & 0x80000000) != 0 {
            error!("VM-entry failure detected! Exit reason: {:#x}", exit_reason);
            self.dump_vmentry_failure_diagnostics();
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
