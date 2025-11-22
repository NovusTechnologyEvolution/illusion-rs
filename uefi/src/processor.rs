// uefi/src/processor.rs
use {
    crate::virtualize,
    core::{arch::global_asm, ffi::c_void, mem, ptr},
    hypervisor::intel::{
        capture::{GuestRegisters, capture_registers},
        paging::virtual_to_physical,
    },
    log::{debug, error, info},
    uefi::{Result, boot, proto::pi::mp::MpServices},
};

// Assembly stub for guest resume point
global_asm!(
    r#"
    .globl resume_from_virtualization
resume_from_virtualization:
    // Simplest possible code: just HLT immediately
    // HLT will cause a VM-exit which we can handle
    hlt
    
    // If we return from the HLT (after VMRESUME), loop forever
2:
    hlt
    jmp 2b
    "#
);

unsafe extern "C" {
    fn resume_from_virtualization() -> !;
}

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

    debug!("capture_registers → already = {}", already);

    if !already {
        debug!("virtualizing CPU …");

        // CRITICAL FIX: Convert virtual address to physical address
        // With guest paging disabled, guest RIP must be a guest physical address
        let resume_virt = resume_from_virtualization as u64;
        let resume_phys = unsafe { virtual_to_physical(resume_virt) };

        debug!("resume_from_virtualization virtual: {:#x}", resume_virt);
        debug!("resume_from_virtualization physical: {:#x}", resume_phys);

        // Set guest RIP to the PHYSICAL address
        regs.rip = resume_phys;

        // Set RAX to 0 for the initial launch
        regs.rax = 0;

        debug!("Guest will resume at RIP (physical): {:#x}", regs.rip);

        virtualize::virtualize_system(&regs, landing_ptr());
    } else {
        debug!("CPU already virtualized (returned from VM-exit)");
        // At this point, the hypervisor is running and we've returned from a VM-exit
        // This code path is reached after start_hypervisor() returns, which never happens
        // because start_hypervisor() has an infinite loop
    }
}

/// CORRECT PATH – and landing is now pub(crate)
fn landing_ptr() -> usize {
    crate::virtualize::landing as usize
}
