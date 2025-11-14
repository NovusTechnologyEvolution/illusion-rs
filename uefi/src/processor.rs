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

    start_hypervisor_on_this_cpu();

    if counts.enabled > 1 {
        debug!("Starting hypervisor on {} APs", counts.enabled - 1);

        mp.startup_all_aps(true, start_hypervisor_on_ap as _, ptr::null_mut(), None, None)?;
    }

    info!("HV installed successfully!");
    Ok(())
}

extern "efiapi" fn start_hypervisor_on_ap(_arg: *mut c_void) {
    start_hypervisor_on_this_cpu();
}

fn start_hypervisor_on_this_cpu() {
    debug!("start_hypervisor_on_this_cpu: ENTRY");

    let mut regs: GuestRegisters = unsafe { mem::zeroed() };

    let already = unsafe { capture_registers(&mut regs) };
    regs.rax = 1;

    debug!("capture_registers → already = {}", already);

    if !already {
        debug!("virtualizing CPU …");
        virtualize::virtualize_system(&regs, landing_ptr());
    } else {
        debug!("CPU already virtualized");
    }
}

/// CORRECT PATH — and landing is now pub(crate)
fn landing_ptr() -> usize {
    crate::virtualize::landing as usize
}
