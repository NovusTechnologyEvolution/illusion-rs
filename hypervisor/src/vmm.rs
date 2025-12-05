//! Manages hypervisor startup and VM exit handling.
//!
//! Provides the infrastructure for starting a hypervisor, including checking CPU support and enabling VMX.
//! Also, handles various VM exit reasons, ensuring that the guest VM can be efficiently managed and controlled.
//! This crate is essential for hypervisor operation, facilitating VM execution and interaction with the physical CPU.
//!
//! In nested-VMX environments (e.g. VMware), some exits (such as WBINVD/INVD) are emulated
//! instead of executing the real instructions to avoid confusing the L0 hypervisor.

use {
    crate::{
        error::HypervisorError,
        intel::{
            capture::GuestRegisters,
            support::{rdmsr, vmread, vmwrite},
            vm::Vm,
            vmerror::VmxBasicExitReason,
            vmexit::{
                ExitType,
                cr::handle_cr_reg_access,
                ept_misconfiguration::handle_ept_misconfiguration,
                ept_violation::handle_ept_violation,
                exception::{handle_exception, handle_undefined_opcode_exception},
                halt::handle_halt,
                init::handle_init_signal,
                invd::handle_invd,
                invept::handle_invept,
                invvpid::handle_invvpid,
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

/// VMCS field encodings not provided by the `ro` module in this crate version.
const VM_EXIT_INTR_INFO: u32 = 0x4404;
const VM_EXIT_INSTRUCTION_LEN: u32 = 0x440C;

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

    // VM structure will be recorded for EPT hiding in hide_hv_with_ept()
    debug!("VM structure allocated at {:#x} ({} bytes)", &*vm as *const _ as u64, core::mem::size_of::<Vm>());

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
    // This uses the ranges recorded in SHARED_HOOK_MANAGER:
    //   - protected heap allocations
    //   - host stacks
    //   - VM structure (added below)
    #[cfg(feature = "hide_hv_with_ept")]
    match hide_hv_with_ept(&mut vm) {
        Ok(_) => debug!("Hypervisor hidden from guest"),
        Err(e) => panic!("Failed to hide hypervisor: {:?}", e),
    };

    // Counter to limit logging spam
    static mut EXIT_COUNT: u64 = 0;
    static mut LAST_EXIT_REASON: u64 = 0;
    static mut LAST_RIP: u64 = 0;
    static mut WARNED_ABOUT_IDT: bool = false;

    // Heartbeat tracking - detect long gaps between VM-exits
    static mut LAST_EXIT_TSC: u64 = 0;
    static mut MAX_GAP_TSC: u64 = 0;

    // Memory corruption detection: store VM pointer and magic value
    static mut VM_PTR_CHECK: u64 = 0;
    const VM_MAGIC: u64 = 0xDEADBEEF_CAFEBABE;

    // Store the VM address for corruption checking
    let vm_addr = &vm as *const _ as u64;
    unsafe {
        VM_PTR_CHECK = vm_addr ^ VM_MAGIC;
    }

    info!("Launching the VM until a vmexit occurs...");
    info!("VM structure at {:#x}", vm_addr);

    // Write canary values at known offsets for corruption detection
    static mut CANARY_1: u64 = 0xCAFEBABE_DEADBEEF;
    static mut CANARY_2: u64 = 0x12345678_9ABCDEF0;

    loop {
        // Check canaries before running VM
        let canary1 = unsafe { core::ptr::read_volatile(&raw const CANARY_1) };
        let canary2 = unsafe { core::ptr::read_volatile(&raw const CANARY_2) };
        let exit_count = unsafe { core::ptr::read_volatile(&raw const EXIT_COUNT) };

        if canary1 != 0xCAFEBABE_DEADBEEF || canary2 != 0x12345678_9ABCDEF0 {
            error!("!!! MEMORY CORRUPTION DETECTED (canaries) !!!");
            error!("CANARY_1: {:#x} (expected 0xCAFEBABE_DEADBEEF)", canary1);
            error!("CANARY_2: {:#x} (expected 0x12345678_9ABCDEF0)", canary2);
            error!("Exit count: {}", exit_count);
            unsafe {
                core::ptr::write_volatile(&raw mut CANARY_1, 0xCAFEBABE_DEADBEEF);
                core::ptr::write_volatile(&raw mut CANARY_2, 0x12345678_9ABCDEF0);
            }
        }

        // Check VM structure integrity - EPTP should have specific format
        let eptp = vm.primary_eptp;
        let eptp_type = eptp & 0x3F; // lower 6 bits
        if eptp == 0 || (eptp_type != 0x06 && eptp_type != 0x1E && eptp_type != 0x5E) {
            error!("!!! VM STRUCTURE CORRUPTION DETECTED !!!");
            error!("primary_eptp: {:#x} (invalid format)", eptp);
            error!("Expected EPTP with type 0x06, 0x1E, or 0x5E, got {:#x}", eptp_type);
            error!("Exit count: {}", exit_count);
            error!("This indicates Windows overwrote our hypervisor heap memory!");
        }

        if exit_count > 10 && !vm.has_launched {
            error!("!!! VM STRUCTURE CORRUPTION: has_launched is false after {} exits !!!", exit_count);
        }

        if let Ok(basic_exit_reason) = vm.run() {
            // IMMEDIATELY check VMCS sanity after VM-exit
            let exit_reason_raw = vmread(ro::EXIT_REASON);
            let decoded_reason = exit_reason_raw & 0xFFFF;
            if decoded_reason != basic_exit_reason as u64 {
                error!(
                    "!!! VMCS CORRUPTION: exit_reason mismatch! raw={:#x} decoded={} expected={:?} !!!",
                    exit_reason_raw, decoded_reason, basic_exit_reason
                );
            }

            let count = unsafe {
                EXIT_COUNT += 1;
                EXIT_COUNT
            };

            let current_rip = vmread(guest::RIP);

            // Heartbeat tracking
            let current_tsc = unsafe { core::arch::x86_64::_rdtsc() };
            let gap_tsc = unsafe {
                let gap = if LAST_EXIT_TSC > 0 { current_tsc - LAST_EXIT_TSC } else { 0 };
                LAST_EXIT_TSC = current_tsc;
                if gap > MAX_GAP_TSC {
                    MAX_GAP_TSC = gap;
                }
                gap
            };

            if gap_tsc > 1_000_000_000 && count > 1000 {
                let gap_ms = gap_tsc / 3_000_000; // ~3GHz
                warn!("Long gap detected! Exit #{}: gap={} TSC ticks (~{}ms at 3GHz)", count, gap_tsc, gap_ms);
                warn!("  After gap: reason={:?}, RIP={:#x}", basic_exit_reason, current_rip);
            }

            if count == 100 || count == 1000 || count == 2000 || count % 1000 == 0 {
                let max_gap_ms = unsafe { MAX_GAP_TSC / 3_000_000 };
                info!("VM-exit milestone: {} exits (RIP={:#x}, max_gap={}ms)", count, current_rip, max_gap_ms);
            }

            let (last_reason, last_rip) = unsafe { (LAST_EXIT_REASON, LAST_RIP) };
            if basic_exit_reason as u64 == last_reason && current_rip == last_rip {
                if count > 2000 && count % 100 == 0 {
                    debug!("Exit #{}: {:?} @ RIP={:#x} (repeated)", count, basic_exit_reason, current_rip);
                }
            } else if count <= 5 {
                info!("Exit #{}: {:?} @ RIP={:#x}", count, basic_exit_reason, current_rip);
            } else if count % 1000 == 0 {
                debug!("Exit #{}: {:?} @ RIP={:#x}", count, basic_exit_reason, current_rip);
            }

            unsafe {
                LAST_EXIT_REASON = basic_exit_reason as u64;
                LAST_RIP = current_rip;
            }

            let idtr_base = vmread(guest::IDTR_BASE);
            if idtr_base == 0 || (idtr_base > 0 && idtr_base < 0x10000) {
                let warned = unsafe { WARNED_ABOUT_IDT };
                if !warned {
                    warn!("Guest IDT is empty at base {:#x} - bootloader transition in progress", idtr_base);
                    warn!("Exit #{}, RIP={:#x}, reason={:?}", count, current_rip, basic_exit_reason);
                    unsafe {
                        WARNED_ABOUT_IDT = true;
                    }
                }
            }

            let exit_type = handle_vmexit(&mut vm, basic_exit_reason);

            match exit_type {
                ExitType::IncrementRIP => {
                    advance_guest_rip(&mut vm.guest_registers);
                }
                ExitType::Continue => {
                    // no RIP adjustment
                }
                ExitType::ExitHypervisor => {
                    error!("ExitHypervisor requested from VM-exit handler");
                    // For now, keep looping; proper teardown can be added later.
                }
            }
        } else {
            error!("VM execution failed - attempting to continue");
        }
    }
}

/// Central VM-exit dispatcher.
///
/// Routes each exit reason to its specialized handler and returns whether
/// to advance guest RIP or not.
fn handle_vmexit(vm: &mut Vm, basic_exit_reason: VmxBasicExitReason) -> ExitType {
    use crate::intel::{
        bitmap::MsrAccessType,
        vmexit::{cpuid::handle_cpuid, msr::handle_msr_access},
    };

    match basic_exit_reason {
        VmxBasicExitReason::ExceptionOrNmi => {
            let intr_info = vmread(VM_EXIT_INTR_INFO);
            let vector = intr_info & 0xFF;
            let intr_type = (intr_info >> 8) & 0x7;

            // Type 6, vector 6 = #UD
            if intr_type == 6 && vector == 6 {
                return handle_undefined_opcode_exception();
            }

            handle_exception(vm)
        }

        VmxBasicExitReason::Cpuid => match handle_cpuid(vm) {
            Ok(exit_type) => exit_type,
            Err(err) => {
                error!("CPUID handler failed: {:?}", err);
                ExitType::Continue
            }
        },

        VmxBasicExitReason::Invd => handle_invd(&mut vm.guest_registers),

        // Treat WBINVD/WBNOINVD the same as INVD in a nested-VMX environment:
        // the L0 hypervisor (e.g. VMware) emulates the cache flush, so we just
        // maintain guest state and advance according to the INVD handler.
        VmxBasicExitReason::WbinvdOrWbnoinvd => handle_invd(&mut vm.guest_registers),

        VmxBasicExitReason::Vmcall => match handle_vmcall(vm) {
            Ok(exit_type) => exit_type,
            Err(err) => {
                error!("VMCALL handler failed: {:?}", err);
                ExitType::Continue
            }
        },

        // Group VMX instruction exits with no dedicated handler: treat generically.
        VmxBasicExitReason::Vmclear
        | VmxBasicExitReason::Vmlaunch
        | VmxBasicExitReason::Vmresume
        | VmxBasicExitReason::Vmptrld
        | VmxBasicExitReason::Vmptrst
        | VmxBasicExitReason::Vmread
        | VmxBasicExitReason::Vmwrite => handle_exception(vm),

        // Vmxon has its own small handler
        VmxBasicExitReason::Vmxon => handle_vmxon(),

        // Vmxoff currently handled generically
        VmxBasicExitReason::Vmxoff => handle_exception(vm),

        // CR access handler: takes &mut Vm and returns Result<ExitType, HypervisorError>
        VmxBasicExitReason::ControlRegisterAccesses => match handle_cr_reg_access(vm) {
            Ok(exit_type) => exit_type,
            Err(err) => {
                error!("CR access handler failed: {:?}", err);
                ExitType::Continue
            }
        },

        // MSR handlers
        VmxBasicExitReason::Rdmsr => match handle_msr_access(vm, MsrAccessType::Read) {
            Ok(exit_type) => exit_type,
            Err(err) => {
                error!("RDMSR handler failed: {:?}", err);
                ExitType::Continue
            }
        },

        VmxBasicExitReason::Wrmsr => match handle_msr_access(vm, MsrAccessType::Write) {
            Ok(exit_type) => exit_type,
            Err(err) => {
                error!("WRMSR handler failed: {:?}", err);
                ExitType::Continue
            }
        },

        VmxBasicExitReason::MonitorTrapFlag => match handle_monitor_trap_flag(vm) {
            Ok(exit_type) => exit_type,
            Err(err) => {
                error!("MonitorTrapFlag handler failed: {:?}", err);
                ExitType::Continue
            }
        },

        // EPT violation handler now returns Result<ExitType, HypervisorError>
        VmxBasicExitReason::EptViolation => match handle_ept_violation(vm) {
            Ok(exit_type) => exit_type,
            Err(err) => {
                error!("EPT violation handler failed: {:?}", err);
                ExitType::Continue
            }
        },

        // EPT misconfiguration also returns a Result in this crate
        VmxBasicExitReason::EptMisconfiguration => match handle_ept_misconfiguration(vm) {
            Ok(exit_type) => exit_type,
            Err(err) => {
                error!("EPT misconfiguration handler failed: {:?}", err);
                ExitType::Continue
            }
        },

        VmxBasicExitReason::Invept => handle_invept(),

        VmxBasicExitReason::Rdtsc => handle_rdtsc(&mut vm.guest_registers),

        VmxBasicExitReason::Invvpid => handle_invvpid(),

        VmxBasicExitReason::Xsetbv => handle_xsetbv(vm),

        // INIT/SIPI take &mut GuestRegisters
        VmxBasicExitReason::InitSignal => handle_init_signal(&mut vm.guest_registers),

        // Name changed from SipiSignal -> StartupIpi in newer enum
        VmxBasicExitReason::StartupIpi => handle_sipi_signal(&mut vm.guest_registers),

        VmxBasicExitReason::Hlt => handle_halt(),

        // Everything else: log and continue without advancing RIP
        _ => {
            let exit_reason = vmread(ro::EXIT_REASON);
            let exit_qualification = vmread(ro::EXIT_QUALIFICATION);
            let guest_rip = vmread(guest::RIP);
            let guest_rsp = vmread(guest::RSP);
            error!("Unhandled VM exit: {:#x} ({:?})", exit_reason, basic_exit_reason);
            error!("  Exit qualification: {:#x}", exit_qualification);
            error!("  Guest RIP: {:#x}", guest_rip);
            error!("  Guest RSP: {:#x}", guest_rsp);

            ExitType::Continue
        }
    }
}

/// Advances the guest's RIP past the current instruction.
fn advance_guest_rip(guest_registers: &mut GuestRegisters) {
    // Use our own VMCS field constant
    let instruction_length = vmread(VM_EXIT_INSTRUCTION_LEN);

    // Sanity check: instruction length should be 1–15 bytes
    if instruction_length == 0 || instruction_length > 15 {
        error!("Invalid instruction length {} at RIP {:#x} - defaulting to 1", instruction_length, guest_registers.rip);
    }

    let delta = if instruction_length > 0 && instruction_length <= 15 {
        instruction_length
    } else {
        1
    };

    let new_rip = guest_registers.rip.wrapping_add(delta);

    guest_registers.rip = new_rip;
    vmwrite(guest::RIP, new_rip);

    let verify_rip = vmread(guest::RIP);
    if verify_rip != new_rip {
        error!("CRITICAL: RIP write failed! Wrote {:#x}, read back {:#x}", new_rip, verify_rip);
    }
}

#[cfg(feature = "hide_hv_with_ept")]
fn hide_hv_with_ept(vm: &mut Vm) -> Result<(), HypervisorError> {
    use {
        crate::intel::{ept::AccessType, hooks::hook_manager::SHARED_HOOK_MANAGER},
        alloc::vec::Vec,
        core::mem::size_of,
        x86::vmx::vmcs::guest,
    };

    debug!("=== Hiding hypervisor memory via EPT ===");

    let mut hook_manager = SHARED_HOOK_MANAGER.lock();

    // Check if dummy page is set up
    if hook_manager.dummy_page_pa == 0 {
        error!("Dummy page not initialized!");
        return Ok(());
    }
    let dummy_page_pa = hook_manager.dummy_page_pa;
    debug!("Dummy page PA: {:#x}", dummy_page_pa);

    // Get VM structure address and size
    let vm_start = vm as *const _ as u64;
    let vm_size = size_of::<Vm>() as u64;
    let vm_end = vm_start + vm_size;

    debug!("VM structure: {:#x} - {:#x} ({} bytes, {} pages)", vm_start, vm_end, vm_size, (vm_size + 0xFFF) / 0x1000);

    // Add the VM structure to the existing set of allocations
    // (keep previously recorded heap + host stacks).
    hook_manager.record_allocation(vm_start as usize, vm_size as usize);

    // Calculate addresses of critical VM components that CANNOT be hidden
    let vmxon_addr = &vm.vmxon_region as *const _ as u64;
    let vmcs_addr = &vm.vmcs_region as *const _ as u64;
    let host_paging_addr = &vm.host_paging as *const _ as u64;
    let primary_ept_addr = &vm.primary_ept as *const _ as u64;

    debug!("VMXON region: {:#x} (size: {})", vmxon_addr, size_of::<crate::intel::vmxon::Vmxon>());
    debug!("VMCS region: {:#x} (size: {})", vmcs_addr, size_of::<crate::intel::vmcs::Vmcs>());
    debug!("Host paging: {:#x} (size: {})", host_paging_addr, size_of::<crate::intel::paging::PageTables>());
    debug!("Primary EPT: {:#x} (size: {})", primary_ept_addr, size_of::<crate::intel::ept::Ept>());

    // Calculate which 2MB regions need page tables (for the VM struct range)
    let first_2mb = vm_start & !0x1FFFFF;
    let last_2mb = (vm_end - 1) & !0x1FFFFF;
    let num_2mb_regions = ((last_2mb - first_2mb) / 0x200000) + 1;
    debug!("Spans {} 2MB regions ({:#x} to {:#x})", num_2mb_regions, first_2mb, last_2mb);

    // PRE-ALLOCATE page tables for all 2MB regions BEFORE the loop (VM struct range)
    debug!("Pre-allocating {} page tables...", num_2mb_regions);
    for i in 0..num_2mb_regions {
        let large_page_pa = first_2mb + i * 0x200000;
        if let Err(e) = hook_manager.memory_manager.map_large_page_to_pt(large_page_pa) {
            error!("Failed to pre-allocate page table for {:#x}: {:?}", large_page_pa, e);
            return Err(e);
        }
    }
    debug!("Page tables pre-allocated successfully");

    // Build exclusion list - pages we CANNOT hide
    let mut exclude_pages: Vec<u64> = Vec::new();

    // Exclude dummy page (it's the swap target)
    exclude_pages.push(dummy_page_pa & !0xFFF);
    debug!("Excluding dummy page: {:#x}", dummy_page_pa & !0xFFF);

    // VMXON region (1 page)
    let vmxon_page = vmxon_addr & !0xFFF;
    exclude_pages.push(vmxon_page);
    debug!("Excluding VMXON page: {:#x}", vmxon_page);

    // VMCS region (1 page)
    let vmcs_page = vmcs_addr & !0xFFF;
    exclude_pages.push(vmcs_page);
    debug!("Excluding VMCS page: {:#x}", vmcs_page);

    // Host paging structures
    let host_paging_size = size_of::<crate::intel::paging::PageTables>();
    let host_paging_pages = (host_paging_size + 0xFFF) / 0x1000;
    for i in 0..host_paging_pages {
        let page = (host_paging_addr & !0xFFF) + (i as u64 * 0x1000);
        exclude_pages.push(page);
    }
    debug!("Excluding {} host paging pages starting at {:#x}", host_paging_pages, host_paging_addr & !0xFFF);

    // EPT structure (~2MB)
    let ept_size = size_of::<crate::intel::ept::Ept>();
    let ept_pages = (ept_size + 0xFFF) / 0x1000;
    for i in 0..ept_pages {
        let page = (primary_ept_addr & !0xFFF) + (i as u64 * 0x1000);
        exclude_pages.push(page);
    }
    debug!("Excluding {} EPT pages starting at {:#x}", ept_pages, primary_ept_addr & !0xFFF);

    // Exclude guest RIP region (±2 pages)
    let rip_page = vmread(guest::RIP) & !0xFFF;
    for offset in [-0x2000i64, -0x1000, 0, 0x1000, 0x2000].iter() {
        let page = (rip_page as i64 + offset) as u64;
        if page > 0 {
            exclude_pages.push(page);
        }
    }
    debug!("Excluding guest RIP region around {:#x}", rip_page);

    // Exclude guest stack (16 pages)
    let rsp_page = vmread(guest::RSP) & !0xFFF;
    for i in 0..16u64 {
        exclude_pages.push(rsp_page.saturating_sub(i * 0x1000));
    }
    debug!("Excluding guest stack pages around {:#x}", rsp_page);

    // Exclude CR3 page table root
    let cr3_page = vmread(guest::CR3) & !0xFFF;
    exclude_pages.push(cr3_page);
    debug!("Excluding guest CR3 page: {:#x}", cr3_page);

    exclude_pages.sort();
    exclude_pages.dedup();
    debug!("Total excluded pages: {}", exclude_pages.len());

    // At this point, allocated_memory_ranges contains:
    //  - protected heap ranges (if any)
    //  - host stack ranges (BSP + APs)
    //  - VM struct range (added above)
    let total_pages: u64 = hook_manager
        .allocated_memory_ranges
        .iter()
        .map(|(_, size)| ((size + 0xFFF) / 0x1000) as u64)
        .sum();

    let permissions = AccessType::READ_WRITE_EXECUTE;

    info!("Hiding hypervisor pages via EPT: total recorded pages ~{}, exclusions {}", total_pages, exclude_pages.len());

    match hook_manager.hide_hypervisor_memory_except(vm, &exclude_pages, permissions) {
        Ok(_) => {
            info!("Successfully hid hypervisor pages from guest via EPT");
            Ok(())
        }
        Err(e) => {
            error!("Failed to hide hypervisor memory: {:?}", e);
            Err(e)
        }
    }
}

/// Checks if the CPU is supported for hypervisor operation.
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

    // Check if the CPU supports MTRRs
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
