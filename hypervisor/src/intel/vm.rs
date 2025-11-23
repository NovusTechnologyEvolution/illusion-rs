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
            vmlaunch_diagnostics::{diagnose_guest_state_validity, diagnose_host_state_validity},
            vmxon::Vmxon,
        },
    },
    alloc::boxed::Box,
    log::{debug, error, info, trace},
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

    /// I/O bitmap A (ports 0x0000-0x7FFF), 4KB aligned
    /// Must be all zeros to allow all I/O operations without VM-exit
    pub io_bitmap_a: Box<[u8; 4096]>,

    /// I/O bitmap B (ports 0x8000-0xFFFF plus one extra byte), 4KB aligned  
    /// Must be all zeros to allow all I/O operations without VM-exit
    pub io_bitmap_b: Box<[u8; 4096]>,
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
            // Initialize I/O bitmaps to all zeros (allow all I/O without VM-exit)
            io_bitmap_a: Box::new([0u8; 4096]),
            io_bitmap_b: Box::new([0u8; 4096]),
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

        // Get I/O bitmap addresses
        let io_bitmap_a = self.io_bitmap_a.as_ptr() as u64;
        let io_bitmap_b = self.io_bitmap_b.as_ptr() as u64;

        // Lock the descriptor manager
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
        // CRITICAL: Set HOST_RSP FIRST, before any diagnostics
        // We need to capture RSP and calculate where it will be after launch_vm pushes registers
        //
        // Stack layout analysis:
        // When we're here in run():
        //   [current_rsp] = (whatever is currently on stack)
        //
        // When CALL launch_vm executes:
        //   [new_rsp] = return address (CALL pushes this)
        //   current_rsp becomes (current_rsp - 8)
        //
        // Inside launch_vm, after 8 pushes (rbx, rbp, rdi, rsi, r12, r13, r14, r15):
        //   [rsp_after_pushes] = saved r15
        //   [rsp_after_pushes + 8] = saved r14
        //   ...
        //   [rsp_after_pushes + 56] = saved rbx
        //   [rsp_after_pushes + 64] = return address
        //   rsp_after_pushes = (current_rsp - 8 - 64) = current_rsp - 72
        //
        // So HOST_RSP should be: current_rsp - 72 (8 for return address + 64 for saved registers)
        unsafe {
            let current_rsp: u64;
            core::arch::asm!(
                "mov {}, rsp",
                out(reg) current_rsp,
                options(nomem, nostack, preserves_flags)
            );

            // HOST_RSP should point to where RSP will be AFTER:
            // 1. CALL instruction pushes return address (-8 bytes)
            // 2. launch_vm pushes 8 registers (-64 bytes)
            // Total: current_rsp - 72
            let host_rsp_value = current_rsp - 72;

            debug!("Setting HOST_RSP to {:#x} (current RSP {:#x} - 72 bytes)", host_rsp_value, current_rsp);
            vmwrite(vmcs::host::RSP, host_rsp_value);

            // Verify it was written correctly
            let verify_rsp = vmread(vmcs::host::RSP);
            if verify_rsp != host_rsp_value {
                error!("HOST_RSP verification failed! Wrote {:#x}, read {:#x}", host_rsp_value, verify_rsp);
                return Err(HypervisorError::VMFailToLaunch);
            }
            debug!("HOST_RSP verified: {:#x}", verify_rsp);

            // Also verify HOST_RIP points to vmexit_handler
            let host_rip = vmread(vmcs::host::RIP);
            unsafe extern "C" {
                fn vmexit_handler();
            }
            let expected_host_rip = vmexit_handler as u64;
            debug!("HOST_RIP: {:#x}, vmexit_handler address: {:#x}", host_rip, expected_host_rip);
            if host_rip != expected_host_rip {
                error!("WARNING: HOST_RIP doesn't match vmexit_handler address!");
                error!("  HOST_RIP in VMCS: {:#x}", host_rip);
                error!("  vmexit_handler addr: {:#x}", expected_host_rip);
            }
        }

        // Run diagnostics only on first launch (AFTER setting HOST_RSP so it shows correct value)
        if !self.has_launched {
            debug!("=== Pre-VMLAUNCH diagnostics ===");
            diagnose_guest_state_validity();
            diagnose_host_state_validity();

            // Verify EPT translation for guest RIP
            let guest_rip = vmread(vmcs::guest::RIP);
            let ept_pml4_base = self.primary_eptp & !0xFFF;

            match unsafe { Ept::translate_guest_pa_to_host_pa(ept_pml4_base, guest_rip) } {
                Ok(host_pa) => {
                    debug!("EPT translates guest RIP {:#x} -> host PA {:#x}", guest_rip, host_pa);
                }
                Err(e) => {
                    error!("ERROR: EPT translation failed for guest RIP: {:?}", e);
                    return Err(HypervisorError::VMFailToLaunch);
                }
            }

            // Verify guest stack is mapped
            let guest_rsp = vmread(vmcs::guest::RSP);
            match unsafe { Ept::translate_guest_pa_to_host_pa(ept_pml4_base, guest_rsp) } {
                Ok(_) => {
                    debug!("EPT translates guest RSP {:#x} successfully", guest_rsp);
                }
                Err(e) => {
                    error!("ERROR: EPT translation failed for guest RSP: {:?}", e);
                    return Err(HypervisorError::VMFailToLaunch);
                }
            }

            // ====================================================================
            // CRITICAL: Verify guest IDT is accessible through EPT
            // ====================================================================
            debug!("=== Verifying Guest IDT ===");
            let guest_idtr_base = vmread(vmcs::guest::IDTR_BASE);
            let guest_idtr_limit = vmread(vmcs::guest::IDTR_LIMIT);
            debug!("Guest IDTR: base={:#x}, limit={:#x}", guest_idtr_base, guest_idtr_limit);

            // Check if IDT base is accessible
            if guest_idtr_base != 0 {
                match unsafe { Ept::translate_guest_pa_to_host_pa(ept_pml4_base, guest_idtr_base) } {
                    Ok(host_pa) => {
                        debug!("✓ Guest IDTR base translates to host PA {:#x}", host_pa);
                        // Try to read first IDT entry to verify it's actually accessible
                        unsafe {
                            let idt_ptr = guest_idtr_base as *const u64;
                            let first_idt_entry = core::ptr::read_volatile(idt_ptr);
                            debug!("First IDT entry: {:#x}", first_idt_entry);

                            // Verify we can read multiple IDT entries
                            if guest_idtr_limit >= 16 {
                                let second_idt_entry = core::ptr::read_volatile(idt_ptr.offset(1));
                                debug!("Second IDT entry: {:#x}", second_idt_entry);
                            }
                        }
                    }
                    Err(e) => {
                        error!("WARNING: Guest IDTR base not mapped in EPT: {:?}", e);
                        error!("This will cause triple fault on any exception!");
                        error!("The guest IDT at {:#x} is not accessible through EPT", guest_idtr_base);
                        error!("Possible causes:");
                        error!("  1. IDT is in a memory region not covered by EPT identity mapping");
                        error!("  2. IDT physical address is above the EPT-mapped range");
                        error!("  3. EPT mapping is incomplete or corrupted");
                        return Err(HypervisorError::VMFailToLaunch);
                    }
                }
            } else {
                error!("WARNING: Guest IDTR base is NULL - this will cause triple fault!");
                return Err(HypervisorError::VMFailToLaunch);
            }

            // Final VMCS validation
            let final_tr_ar = vmread(0x4822);
            if final_tr_ar == 0 {
                error!("FATAL: TR access rights is 0!");
                return Err(HypervisorError::VMFailToLaunch);
            }
            if final_tr_ar & (1 << 7) == 0 {
                error!("FATAL: TR Present bit not set (AR={:#x})!", final_tr_ar);
                return Err(HypervisorError::VMFailToLaunch);
            }

            // Check pending debug exceptions one last time
            let guest_pending_debug = vmread(0x6822);
            if guest_pending_debug != 0 {
                debug!("Clearing pending debug exceptions ({:#x})", guest_pending_debug);
                vmwrite(0x6822, 0u64);
            }

            // CRITICAL: Verify guest RIP contains valid instructions
            let guest_rip_ptr = guest_rip as *const u8;
            let first_bytes = unsafe { core::slice::from_raw_parts(guest_rip_ptr, 16) };
            debug!("Guest RIP bytes: {:02x?}", first_bytes);

            // Check if it starts with HLT (0xF4) or common instructions
            if first_bytes[0] == 0xF4 {
                debug!("✓ Guest RIP starts with HLT instruction");
            } else {
                debug!("⚠ Guest RIP first byte: {:#04x} (not HLT)", first_bytes[0]);
            }

            // Verify all mandatory VMCS fields are properly set
            let checks = [
                ("Guest CR0", vmread(vmcs::guest::CR0)),
                ("Guest CR4", vmread(vmcs::guest::CR4)),
                ("Guest RIP", vmread(vmcs::guest::RIP)),
                ("Guest RSP", vmread(vmcs::guest::RSP)),
                ("Guest RFLAGS", vmread(vmcs::guest::RFLAGS)),
                ("Host CR0", vmread(vmcs::host::CR0)),
                ("Host CR3", vmread(vmcs::host::CR3)),
                ("Host CR4", vmread(vmcs::host::CR4)),
                ("Host RIP", vmread(vmcs::host::RIP)),
                ("Host RSP", vmread(vmcs::host::RSP)),
            ];

            for (name, value) in checks {
                if value == 0 && name != "Guest CR3" {
                    error!("CRITICAL: {} is 0!", name);
                    return Err(HypervisorError::VMFailToLaunch);
                }
                debug!("{}: {:#x}", name, value);
            }

            // Verify host GDT contains valid descriptors
            let host_gdtr_base = vmread(vmcs::host::GDTR_BASE);
            let host_cs = vmread(vmcs::host::CS_SELECTOR) as u16;
            let host_tr = vmread(vmcs::host::TR_SELECTOR) as u16;

            debug!("Host GDT check:");
            debug!("  GDTR base: {:#x}", host_gdtr_base);
            debug!("  CS selector: {:#x} (index {})", host_cs, host_cs >> 3);
            debug!("  TR selector: {:#x} (index {})", host_tr, host_tr >> 3);

            // Read actual GDT entries
            let gdt_ptr = host_gdtr_base as *const u64;
            unsafe {
                let cs_desc = *gdt_ptr.offset((host_cs >> 3) as isize);
                let tr_desc_low = *gdt_ptr.offset((host_tr >> 3) as isize);
                let tr_desc_high = *gdt_ptr.offset((host_tr >> 3) as isize + 1);
                debug!("  CS descriptor: {:#018x}", cs_desc);
                debug!("  TR descriptor: {:#018x} {:#018x}", tr_desc_low, tr_desc_high);
            }

            debug!("All pre-VMLAUNCH checks passed!");
            // CRITICAL: Verify guest state consistency for 64-bit mode
            let guest_cr0 = vmread(vmcs::guest::CR0);
            let guest_cr4 = vmread(vmcs::guest::CR4);
            let guest_efer = vmread(vmcs::guest::IA32_EFER_FULL);

            // Check CR0.PG and CR4.PAE are set (required for long mode)
            if (guest_cr0 & (1 << 31)) == 0 {
                error!("FATAL: CR0.PG not set!");
                return Err(HypervisorError::VMFailToLaunch);
            }
            if (guest_cr4 & (1 << 5)) == 0 {
                error!("FATAL: CR4.PAE not set!");
                return Err(HypervisorError::VMFailToLaunch);
            }

            // Check EFER.LME and EFER.LMA are set
            if (guest_efer & (1 << 8)) == 0 {
                error!("FATAL: EFER.LME not set!");
                return Err(HypervisorError::VMFailToLaunch);
            }
            if (guest_efer & (1 << 10)) == 0 {
                error!("FATAL: EFER.LMA not set!");
                return Err(HypervisorError::VMFailToLaunch);
            }

            // Most important: verify guest CR3 points to valid page tables
            let guest_cr3 = vmread(vmcs::guest::CR3);
            debug!("Verifying guest CR3: {:#x}", guest_cr3);

            // Try to read the PML4 entry to verify it's accessible
            let pml4_ptr = guest_cr3 as *const u64;
            let pml4_entry = unsafe { core::ptr::read_volatile(pml4_ptr) };
            debug!("PML4[0] entry: {:#x}", pml4_entry);
            if pml4_entry == 0 {
                error!("FATAL: Guest CR3 points to empty page tables!");
                return Err(HypervisorError::VMFailToLaunch);
            }

            // Verify guest stack
            let guest_rsp = vmread(vmcs::guest::RSP);
            debug!("Verifying guest stack at RSP: {:#x}", guest_rsp);

            if guest_rsp == 0 {
                error!("FATAL: Guest RSP is NULL!");
                return Err(HypervisorError::VMFailToLaunch);
            }

            if guest_rsp & 0x7 != 0 {
                debug!("WARNING: Guest RSP not 8-byte aligned: {:#x}", guest_rsp);
            }

            // Try to verify the stack memory is accessible via EPT
            let ept_pml4_base = self.primary_eptp & !0xFFF;
            match unsafe { Ept::translate_guest_pa_to_host_pa(ept_pml4_base, guest_rsp - 8) } {
                Ok(host_pa) => {
                    debug!("✓ Guest stack-8 ({:#x}) translates to host PA {:#x}", guest_rsp - 8, host_pa);
                    // Try to verify it's actually writable
                    unsafe {
                        let stack_test = (guest_rsp - 8) as *mut u64;
                        core::ptr::write_volatile(stack_test, 0xDEADBEEF);
                        let verify = core::ptr::read_volatile(stack_test);
                        if verify != 0xDEADBEEF {
                            error!("FATAL: Guest stack memory is not writable!");
                            return Err(HypervisorError::VMFailToLaunch);
                        }
                        debug!("✓ Guest stack is accessible and writable");
                    }
                }
                Err(e) => {
                    error!("FATAL: Guest stack not mapped in EPT: {:?}", e);
                    return Err(HypervisorError::VMFailToLaunch);
                }
            }
        }

        // FINAL CHECK: Verify VMCS is loaded and valid
        let test_read = vmread(vmcs::host::RSP);
        if test_read == 0 {
            error!("FATAL: VMCS not properly loaded (HOST_RSP reads as 0)!");
            return Err(HypervisorError::VMFailToLaunch);
        }
        debug!("VMCS is loaded and valid (test read succeeded)");

        // Execute the VM
        debug!("Calling launch_vm...");

        // Save a marker to detect if we return at all
        let pre_launch_marker = 0xDEADBEEF_u64;
        debug!("Pre-launch marker: {:#x}", pre_launch_marker);

        // Add a pre-VMLAUNCH check for TR that might cause silent failure
        let final_tr_check = vmread(0x4822);
        if final_tr_check == 0 || final_tr_check == 0x10000 {
            error!("FATAL: TR AR is invalid ({:#x}) right before VMLAUNCH!", final_tr_check);
            return Err(HypervisorError::VMFailToLaunch);
        }
        // CRITICAL: Verify VM-entry interrupt-information field is properly cleared
        let vm_entry_intr_info = vmread(0x4016);
        if vm_entry_intr_info != 0 {
            error!("WARNING: VM_ENTRY_INTR_INFO is not 0: {:#x}", vm_entry_intr_info);
            error!("This can cause invalid guest state on entry!");
            vmwrite(0x4016, 0u32);
            let verify = vmread(0x4016);
            debug!("VM_ENTRY_INTR_INFO after clearing: {:#x}", verify);
        }
        // CRITICAL: Verify guest RFLAGS has interrupts enabled
        let guest_rflags = vmread(vmcs::guest::RFLAGS);
        debug!("Guest RFLAGS before VMLAUNCH: {:#x}", guest_rflags);
        if (guest_rflags & (1 << 9)) == 0 {
            error!("CRITICAL: Guest RFLAGS.IF is 0 - interrupts are disabled!");
            error!("HLT with IF=0 will cause the guest to hang forever!");
            error!("Setting IF=1 in guest RFLAGS...");
            vmwrite(vmcs::guest::RFLAGS, guest_rflags | (1 << 9));
            let verify = vmread(vmcs::guest::RFLAGS);
            debug!("Guest RFLAGS after fix: {:#x}, IF={}", verify, (verify & (1 << 9)) != 0);
        }
        debug!("=== LAUNCHING VM ===");
        // ============================================================================
        // COMPREHENSIVE ADDRESS DIAGNOSTICS
        // ============================================================================

        // 1. Get all function addresses
        unsafe extern "C" {
            fn resume_from_virtualization();
        }
        let resume_fn_addr = resume_from_virtualization as u64;

        unsafe extern "C" {
            fn launch_vm(registers: *mut GuestRegisters, launched: u64) -> u64;
        }
        let launch_vm_addr = launch_vm as *const () as u64;

        unsafe extern "C" {
            fn vmexit_handler();
        }
        let vmexit_handler_addr = vmexit_handler as u64;

        debug!("=== FUNCTION ADDRESS MAP ===");
        debug!("resume_from_virtualization: {:#x}", resume_fn_addr);
        debug!("launch_vm:                  {:#x}", launch_vm_addr);
        debug!("vmexit_handler:             {:#x}", vmexit_handler_addr);
        debug!("Guest RIP (from VMCS):      {:#x}", vmread(vmcs::guest::RIP));

        // 2. Read bytes at each address
        let resume_bytes = unsafe { core::slice::from_raw_parts(resume_fn_addr as *const u8, 32) };
        debug!("Bytes at resume_from_virtualization: {:02x?}", resume_bytes);

        let launch_vm_bytes = unsafe { core::slice::from_raw_parts(launch_vm_addr as *const u8, 32) };
        debug!("Bytes at launch_vm:                  {:02x?}", launch_vm_bytes);

        let vmexit_bytes = unsafe { core::slice::from_raw_parts(vmexit_handler_addr as *const u8, 32) };
        debug!("Bytes at vmexit_handler:             {:02x?}", vmexit_bytes);

        // 3. Check what Guest RIP actually points to
        let guest_rip_value = vmread(vmcs::guest::RIP);
        let guest_rip_bytes = unsafe { core::slice::from_raw_parts(guest_rip_value as *const u8, 32) };
        debug!("Bytes at Guest RIP:                  {:02x?}", guest_rip_bytes);

        // 4. Compare and identify what Guest RIP points to
        debug!("=== ADDRESS ANALYSIS ===");
        if guest_rip_value == resume_fn_addr {
            debug!("✓ Guest RIP points to resume_from_virtualization");
        } else if guest_rip_value == launch_vm_addr {
            error!("❌ CRITICAL: Guest RIP points to launch_vm!");
        } else if guest_rip_value == vmexit_handler_addr {
            error!("❌ CRITICAL: Guest RIP points to vmexit_handler!");
        } else {
            debug!("Guest RIP is at a different address");
            debug!("  Distance from resume_fn: {} bytes", (guest_rip_value as i64 - resume_fn_addr as i64).abs());
            debug!("  Distance from launch_vm: {} bytes", (guest_rip_value as i64 - launch_vm_addr as i64).abs());
        }

        // 5. Check if bytes match (most important!)
        debug!("=== BYTE PATTERN ANALYSIS ===");
        let matches_resume = &guest_rip_bytes[0..16] == &resume_bytes[0..16];
        let matches_launch = &guest_rip_bytes[0..16] == &launch_vm_bytes[0..16];
        let matches_vmexit = &guest_rip_bytes[0..16] == &vmexit_bytes[0..16];

        debug!("Guest RIP bytes match resume_from_virtualization: {}", matches_resume);
        debug!("Guest RIP bytes match launch_vm:                  {}", matches_launch);
        debug!("Guest RIP bytes match vmexit_handler:             {}", matches_vmexit);

        if matches_launch {
            error!("❌❌❌ FATAL: Guest RIP contains launch_vm code!");
            error!("The guest will try to execute the hypervisor's launch_vm function!");
            error!("This will cause a triple fault or incorrect behavior!");
        } else if matches_vmexit {
            error!("❌❌❌ FATAL: Guest RIP contains vmexit_handler code!");
        } else if !matches_resume {
            error!("⚠ WARNING: Guest RIP bytes don't match any known function!");
            error!("Expected resume_from_virtualization pattern but got something else.");
        }

        // 6. Analyze the actual instruction bytes at Guest RIP
        debug!("=== INSTRUCTION ANALYSIS ===");
        if guest_rip_bytes[0] == 0xF4 && guest_rip_bytes[1] == 0xF4 {
            debug!("✓ Starts with HLT HLT");
            if guest_rip_bytes[2] == 0xEB && guest_rip_bytes[3] == 0xFD {
                debug!("✓ Followed by JMP -3 (correct HLT loop)");
            }

            // Check what comes after the HLT loop
            if guest_rip_bytes[4] == 0x48 && guest_rip_bytes[5] == 0x8D && guest_rip_bytes[6] == 0x05 {
                error!("❌ After HLT: LEA RAX, [RIP+...] - This is launch_vm!");
            } else if guest_rip_bytes[4] == 0x50 {
                debug!("✓ After HLT: PUSH RAX - Looks like register save code");
            } else {
                debug!("After HLT: Unknown instruction: {:02x} {:02x} {:02x}", guest_rip_bytes[4], guest_rip_bytes[5], guest_rip_bytes[6]);
            }
        }

        // 7. Check GuestRegisters structure location
        debug!("=== GUEST REGISTERS STRUCTURE ===");
        debug!("GuestRegisters pointer: {:p}", &self.guest_registers);
        debug!("  RIP in struct: {:#x}", self.guest_registers.rip);
        debug!("  RIP in VMCS:   {:#x}", vmread(vmcs::guest::RIP));
        if self.guest_registers.rip != vmread(vmcs::guest::RIP) {
            error!("❌ MISMATCH: RIP in GuestRegisters != RIP in VMCS");
        }

        // ============================================================================
        // END DIAGNOSTICS
        // ============================================================================
        debug!("Diagnostics complete. Proceeding with vmlaunch...");
        debug!("has_launched = {}", self.has_launched);
        let launched_value = if self.has_launched { 1u64 } else { 0u64 };
        debug!("launched_value being passed to asm = {:#x}", launched_value);
        // Emergency serial debug - prove we're about to call vmlaunch
        unsafe {
            core::arch::asm!(
                "mov dx, 0x3F8",
                "mov al, 0x4C",  // 'L'
                "out dx, al",
                "mov al, 0x41",  // 'A'
                "out dx, al",
                "mov al, 0x55",  // 'U'
                "out dx, al",
                "mov al, 0x4E",  // 'N'
                "out dx, al",
                out("dx") _,
                out("al") _,
            );
        }
        let flags_raw = vmlaunch(&mut self.guest_registers, launched_value);

        debug!("🎉 launch_vm RETURNED! flags_raw = {:#x}", flags_raw);

        debug!("launch_vm returned, RFLAGS = {:#x}", flags_raw);

        // Interpret RFLAGS returned by the vmlaunch/vmresume stub
        let flags = RFlags::from_bits_truncate(flags_raw);

        // CRITICAL: Check for VMLAUNCH/VMRESUME failure BEFORE doing anything else
        if flags.contains(RFlags::FLAGS_ZF) {
            // VM instruction error - read the error code
            let instruction_error = vmread(vmcs::ro::VM_INSTRUCTION_ERROR) as u32;
            error!("VMLAUNCH failed with VM instruction error: {:#x}", instruction_error);

            // Dump more VMCS state to help diagnose
            error!("Additional VMCS diagnostics:");
            error!("  Guest RIP: {:#x}", vmread(vmcs::guest::RIP));
            error!("  Guest RSP: {:#x}", vmread(vmcs::guest::RSP));
            error!("  Host RIP: {:#x}", vmread(vmcs::host::RIP));
            error!("  Host RSP: {:#x}", vmread(vmcs::host::RSP));

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

        debug!("VMLAUNCH succeeded! VM entered and exited successfully.");

        // Check whether the VM-entry instruction succeeded
        Self::vm_succeed(flags)?;

        // VM-entry succeeded; this VM has now been launched at least once
        self.has_launched = true;

        // Refresh cached guest architectural state from the VMCS
        self.guest_registers.rip = vmread(vmcs::guest::RIP);
        self.guest_registers.rsp = vmread(vmcs::guest::RSP);
        self.guest_registers.rflags = vmread(vmcs::guest::RFLAGS);

        // Decode and return the basic exit reason
        let exit_reason = vmread(vmcs::ro::EXIT_REASON) as u32;
        debug!("VM-exit: raw EXIT_REASON = 0x{:x}", exit_reason);

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
