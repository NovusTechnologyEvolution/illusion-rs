// uefi/src/processor.rs
//! UEFI-side processor startup helpers.
//!
//! This module is responsible for starting the hypervisor on all logical
//! processors using the UEFI MP Services protocol. The Bootstrap Processor
//! (BSP) and all Application Processors (APs) take the same path:
//!   1) Capture guest registers via `capture_registers`
//!   2) Bounce into `virtualize::virtualize_system`
//!   3) Land in the shared `landing` trampoline and enter the hypervisor.

use {
    crate::virtualize,
    core::{ffi::c_void, mem, ptr},
    hypervisor::intel::capture::{GuestRegisters, capture_registers},
    log::{debug, info},
    uefi::{Result, boot, proto::pi::mp::MpServices},
};

/// Start the hypervisor on all logical processors (BSP + APs).
///
/// This:
///   * Locates the MP Services protocol
///   * Logs processor counts
///   * Requests hypervisor startup on all APs
///   * Finally virtualizes the BSP as well
pub fn start_hypervisor_on_all_processors() -> Result<()> {
    info!("start_hypervisor_on_all_processors: ENTRY");

    // Locate MP Services
    let mp_handle = boot::get_handle_for_protocol::<MpServices>()?;
    let mp = boot::open_protocol_exclusive::<MpServices>(mp_handle)?;

    let counts = mp.get_number_of_processors()?;
    info!("Total processors: {}, enabled: {}", counts.total, counts.enabled);

    // If we have APs, request the APs to enter the same virtualization path.
    if counts.enabled > 1 {
        let ap_count = counts.enabled.saturating_sub(1);
        info!("Starting hypervisor on {} AP(s)", ap_count);

        // Run the AP procedure on all enabled APs. Each AP will call
        // `start_hypervisor_on_this_cpu` from `start_hypervisor_on_ap`.
        if let Err(e) = mp.startup_all_aps(
            false,                  // single_thread: run APs in parallel
            start_hypervisor_on_ap, // procedure
            ptr::null_mut(),        // procedure_argument
            None,                   // event (blocking call)
            None,                   // timeout (None = wait forever)
        ) {
            // Firmware can be quirky; if this fails we still virtualize the BSP,
            // so you at least get a single-CPU hypervisor.
            info!("MpServices::startup_all_aps failed: {:?} (continuing with BSP only)", e);
        }
    } else {
        info!("Single-processor system detected (no APs to start)");
    }

    // Finally, virtualize the BSP as well.
    start_hypervisor_on_this_cpu();

    // Note: control flow here is a bit non-obvious because `capture_registers`
    // and the hypervisor path cause this function to be "re-entered" after
    // virtualization. By the time we get here, the hypervisor has already
    // been started on this CPU.
    info!("Hypervisor start requested on all processors (including BSP)");

    Ok(())
}

/// AP entry function used by `MpServices::startup_all_aps`.
///
/// All APs take the exact same path as the BSP: we capture registers and
/// jump into `virtualize::virtualize_system`.
extern "efiapi" fn start_hypervisor_on_ap(_arg: *mut c_void) {
    start_hypervisor_on_this_cpu();
}

/// Per-CPU hypervisor entry.
///
/// This is called on:
///   * The BSP from `start_hypervisor_on_all_processors`
///   * Each AP from `start_hypervisor_on_ap`
fn start_hypervisor_on_this_cpu() {
    debug!("start_hypervisor_on_this_cpu: ENTRY");

    // `capture_registers` returns twice:
    //   * First time: returns `false` and fills `regs` with the guest state.
    //   * Second time: returns `true` after the guest resumes from virtualization.
    let mut regs: GuestRegisters = unsafe { mem::zeroed() };
    let already = unsafe { capture_registers(&mut regs) };

    if !already {
        debug!("virtualizing CPU, RIP={:#x}, RSP={:#x}->{:#x}", regs.rip, regs.rsp, regs.rsp + 8);

        // Adjust RSP to simulate the 'ret' that would have returned from
        // the original call site of `capture_registers`.
        regs.rsp += 8;

        // Set RAX to 1 so that, from the guest's perspective, the original
        // `capture_registers` call appears to have returned `true`.
        regs.rax = 1;

        // Hand control off to the virtualization trampoline. This allocates
        // a host stack, switches stacks, and eventually calls into the
        // hypervisor's `start_hypervisor` implementation.
        virtualize::virtualize_system(&regs, landing_ptr());
    }

    // If `already == true`, we've already gone through virtualization and
    // resumed execution in the guest; nothing more to do on this CPU.
}

/// Returns the address of the landing trampoline used by `virtualize_system`.
fn landing_ptr() -> usize {
    crate::virtualize::landing as usize
}
