// uefi/src/processor.rs
use {
    crate::virtualize,
    core::{arch::global_asm, ffi::c_void, mem, ptr},
    hypervisor::intel::capture::{GuestRegisters, capture_registers},
    log::{debug, error, info},
    uefi::{Result, boot, proto::pi::mp::MpServices},
};

// Assembly stub for guest resume point - ONLY used for debugging now
// The actual guest will resume at the original captured RIP
global_asm!(
    r#"
    .globl resume_from_virtualization
    
    // Align to ensure this function doesn't get merged with others
    .align 64
    
resume_from_virtualization:
    // UD2 (undefined instruction) causes immediate #UD exception VM-exit
    // This is more reliable than HLT for testing
    ud2
    
    // If we somehow continue past UD2, infinite loop with HLT
    hlt
    hlt
    jmp resume_from_virtualization
    
    // Add padding to ensure this function is isolated
    .align 64
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    "#
);

unsafe extern "C" {
    fn resume_from_virtualization() -> !;
}

/// Converts a virtual address to a physical address using CR3.
/// Performs a page table walk to find the physical address.
unsafe fn virtual_to_physical(virt_addr: u64) -> u64 {
    // Read CR3 to get the page table base
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }

    // Page table walk
    const BASE_PAGE_SHIFT: u64 = 12;

    // Extract indices from virtual address
    let pml4_index = (virt_addr >> 39) & 0x1FF;
    let pdpt_index = (virt_addr >> 30) & 0x1FF;
    let pd_index = (virt_addr >> 21) & 0x1FF;
    let pt_index = (virt_addr >> 12) & 0x1FF;

    // PML4 entry
    let pml4_base = (cr3 >> BASE_PAGE_SHIFT) << BASE_PAGE_SHIFT;
    let pml4_table = pml4_base as *const u64;
    let pml4_entry = unsafe { *pml4_table.add(pml4_index as usize) };

    if (pml4_entry & 1) == 0 {
        error!("PML4 entry not present for vaddr {:#x}", virt_addr);
        return virt_addr; // Fallback to identity mapping assumption
    }

    // PDPT entry
    let pdpt_base = (pml4_entry >> BASE_PAGE_SHIFT) << BASE_PAGE_SHIFT;
    let pdpt_table = pdpt_base as *const u64;
    let pdpt_entry = unsafe { *pdpt_table.add(pdpt_index as usize) };

    if (pdpt_entry & 1) == 0 {
        error!("PDPT entry not present for vaddr {:#x}", virt_addr);
        return virt_addr;
    }

    // Check if it's a 1GB page
    if (pdpt_entry & (1 << 7)) != 0 {
        let offset = virt_addr & 0x3FFF_FFFF; // 1GB offset (bits 0-29)
        let phys_base = (pdpt_entry >> BASE_PAGE_SHIFT) << BASE_PAGE_SHIFT;
        return phys_base + offset;
    }

    // PD entry
    let pd_base = (pdpt_entry >> BASE_PAGE_SHIFT) << BASE_PAGE_SHIFT;
    let pd_table = pd_base as *const u64;
    let pd_entry = unsafe { *pd_table.add(pd_index as usize) };

    if (pd_entry & 1) == 0 {
        error!("PD entry not present for vaddr {:#x}", virt_addr);
        return virt_addr;
    }

    // Check if it's a 2MB page
    if (pd_entry & (1 << 7)) != 0 {
        let offset = virt_addr & 0x1F_FFFF; // 2MB offset (bits 0-20)
        let phys_base = (pd_entry >> BASE_PAGE_SHIFT) << BASE_PAGE_SHIFT;
        return phys_base + offset;
    }

    // PT entry (4KB page)
    let pt_base = (pd_entry >> BASE_PAGE_SHIFT) << BASE_PAGE_SHIFT;
    let pt_table = pt_base as *const u64;
    let pt_entry = unsafe { *pt_table.add(pt_index as usize) };

    if (pt_entry & 1) == 0 {
        error!("PT entry not present for vaddr {:#x}", virt_addr);
        return virt_addr;
    }

    let offset = virt_addr & 0xFFF; // 4KB offset (bits 0-11)
    let phys_base = (pt_entry >> BASE_PAGE_SHIFT) << BASE_PAGE_SHIFT;
    phys_base + offset
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

        // The original RIP captured by capture_registers is the return address
        // from whoever called start_hypervisor_on_this_cpu. This is where the
        // guest should resume after virtualization.
        let original_rip = regs.rip;
        debug!("Original captured RIP (return address): {:#x}", original_rip);

        // IMPORTANT: We keep the original RIP! The guest will resume exactly
        // where it was when capture_registers was called.
        //
        // Previously we were overwriting regs.rip with resume_from_virtualization
        // which caused problems because after the UD2 test stub, the guest would
        // try to execute hypervisor code.
        //
        // Now the guest resumes at the original UEFI return address.

        // CRITICAL: Set RAX to 1 so that when the guest resumes, capture_registers
        // appears to return `true` (already virtualized). This prevents the guest
        // from trying to virtualize again.
        //
        // The capture_registers function returns bool via RAX:
        //   - 0 = not yet virtualized (first call)
        //   - 1 = already virtualized (returning from VM)
        regs.rax = 1;

        debug!("Guest will resume at RIP: {:#x}", regs.rip);
        debug!("Guest RSP: {:#x}", regs.rsp);

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
