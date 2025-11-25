// uefi/src/processor.rs
use {
    crate::virtualize,
    core::{ffi::c_void, mem, ptr},
    hypervisor::intel::capture::{GuestRegisters, capture_registers},
    log::{debug, info},
    uefi::{Result, boot, proto::pi::mp::MpServices},
};

pub fn start_hypervisor_on_all_processors() -> Result<()> {
    info!("start_hypervisor_on_all_processors: ENTRY");
    let mp_handle = boot::get_handle_for_protocol::<MpServices>()?;
    let mp = boot::open_protocol_exclusive::<MpServices>(mp_handle)?;
    let counts = mp.get_number_of_processors()?;
    info!("Total processors: {}, enabled: {}", counts.total, counts.enabled);

    // Virtualize the BSP (Bootstrap Processor)
    start_hypervisor_on_this_cpu();

    // TODO: AP initialization is disabled until per-CPU structures are implemented.
    // Currently all CPUs would share the same GDT/TSS which causes crashes.
    // Each CPU needs:
    //   - Its own TSS (Task State Segment)
    //   - Its own GDT with that TSS
    //   - Its own VMCS
    //   - Atomic exit counter or per-CPU counters

    info!("Hypervisor installed on BSP (AP support pending per-CPU structures)");
    Ok(())
}

extern "efiapi" fn start_hypervisor_on_ap(_arg: *mut c_void) {
    start_hypervisor_on_this_cpu();
}

fn start_hypervisor_on_this_cpu() {
    debug!("start_hypervisor_on_this_cpu: ENTRY");
    let mut regs: GuestRegisters = unsafe { mem::zeroed() };
    let already = unsafe { capture_registers(&mut regs) };

    if !already {
        debug!("virtualizing CPU, RIP={:#x}, RSP={:#x}->{:#x}", regs.rip, regs.rsp, regs.rsp + 8);

        // Adjust RSP to simulate the 'ret' instruction having executed
        regs.rsp += 8;

        // Set RAX to 1 so guest thinks capture_registers returned true
        regs.rax = 1;

        virtualize::virtualize_system(&regs, landing_ptr());
    }
    // If already==true, we've returned from virtualization - just continue
}

/// CORRECT PATH – and landing is now pub(crate)
fn landing_ptr() -> usize {
    crate::virtualize::landing as usize
}
