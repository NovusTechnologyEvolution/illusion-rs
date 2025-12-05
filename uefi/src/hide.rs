use {
    log::{debug, trace, warn},
    uefi::{
        boot::{self, AllocateType, MemoryType},
        mem::memory_map::MemoryMap, // Import the trait for .entries()
        proto::loaded_image::LoadedImage,
    },
};

/// UEFI-side memory inspection and protected allocation helpers.
///
/// This module is **not** responsible for actually building the EPT
/// hiding view itself – that is done in the hypervisor crate
/// (`hide_hv_with_ept` + `hook_manager.hide_hypervisor_memory_except`).
///
/// Here we:
///   * log what memory types the image occupies
///   * allocate RUNTIME_SERVICES_DATA pages for hypervisor-owned data
///   * (optionally) record those allocations so the hypervisor can
///     decide which pages to hide via EPT later.
///
/// IMPORTANT:
///   - The UEFI image itself is a DXE_RUNTIME_DRIVER (`efi_runtime_driver`),
///     so its code/data should already be in RUNTIME_SERVICES_* memory.
///   - We **do not** record the image range for EPT hiding anymore,
///     because hiding executable code / VMX host state can cause triple
///     faults when the CPU tries to VM-exit into pages that EPT makes
///     non-present / redirected to a dummy page.
///
/// This must be called BEFORE ExitBootServices() is called by the Windows bootloader.
pub fn hide_uefi_memory() -> uefi::Result<()> {
    // Get our own loaded image
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;
    let image_base = loaded_image.info().0 as u64;
    let image_size = loaded_image.info().1 as u64;
    let image_end = image_base + image_size;

    debug!("Hypervisor image range: {:#x} - {:#x} (size {:#x}, {} pages)", image_base, image_end, image_size, (image_size + 0xFFF) / 0x1000);

    // NOTE:
    // We deliberately DO NOT record the image range for EPT hiding.
    //
    // The image contains:
    //   - VMX root code (VM-exit handlers)
    //   - critical data and tables used during host transitions
    //
    // EPT-hiding these pages (mapping them to a dummy page or toggling permissions)
    // can cause the CPU to triple fault when it tries to execute VM-exit code or
    // access host structures that appear "hidden" / non-present from the guest view.
    //
    // Instead, the image is:
    //   - kept in RUNTIME_SERVICES_CODE / DATA (by virtue of being an EFI runtime driver)
    //   - optionally shielded from the OS via memory map tricks elsewhere,
    //   - and *not* part of the regions that EPT will redirect to the dummy page.

    // Verify and log the current memory map entries for our range
    log_memory_map_for_range(image_base, image_end);

    Ok(())
}

/// Logs memory map entries that overlap with our image range for debugging.
fn log_memory_map_for_range(image_base: u64, image_end: u64) {
    // Get a copy of the memory map for inspection.
    // We ask for a LOADER_DATA scratch buffer to hold the map; the contents
    // of the map itself still describe all memory types.
    if let Ok(memory_map) = boot::memory_map(MemoryType::LOADER_DATA) {
        debug!("Checking memory map entries for hypervisor image range:");

        for descriptor in memory_map.entries() {
            let start = descriptor.phys_start;
            let size = descriptor.page_count * 0x1000;
            let end = start + size;

            // Check if this entry overlaps with our image
            if start < image_end && end > image_base {
                debug!("  {:#x}-{:#x} ({} pages): {:?}", start, end, descriptor.page_count, descriptor.ty);

                // Warn if it's not a runtime type
                match descriptor.ty {
                    MemoryType::RUNTIME_SERVICES_CODE | MemoryType::RUNTIME_SERVICES_DATA | MemoryType::RESERVED => {
                        debug!("    ^ Good: This memory type persists after ExitBootServices");
                    }
                    MemoryType::BOOT_SERVICES_CODE | MemoryType::BOOT_SERVICES_DATA | MemoryType::LOADER_CODE | MemoryType::LOADER_DATA => {
                        warn!("    ^ WARNING: This memory type may be reclaimed by Windows!");
                    }
                    _ => {
                        trace!("    ^ Memory type: {:?}", descriptor.ty);
                    }
                }
            }
        }
    }
}

/// Allocate protected memory for hypervisor-owned *data*.
///
/// This memory:
///   - is allocated as RUNTIME_SERVICES_DATA
///   - survives ExitBootServices
///   - is safe to consider for EPT hiding, since it is data, not the VMX
///     host code / control structures themselves.
///
/// We record the allocation in the shared hook manager so the hypervisor
/// can, in principle, decide to hide these pages from the guest view.
///
/// NOTE:
///   In the current wiring, `hide_hv_with_ept` in the hypervisor crate
///   clears `allocated_memory_ranges` and then records the VM structure
///   range explicitly. That means these recorded allocations are mostly
///   for future use / debugging and are *not* actively hidden yet.
pub fn allocate_protected_pages(page_count: usize) -> uefi::Result<u64> {
    // Allocate as RUNTIME_SERVICES_DATA - this memory type persists after ExitBootServices.
    let addr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::RUNTIME_SERVICES_DATA, page_count)?;

    let pa = addr.as_ptr() as u64;
    debug!("Allocated {} protected pages at {:#x}", page_count, pa);

    // Record this allocation for potential EPT hiding.
    {
        use hypervisor::intel::hooks::hook_manager::SHARED_HOOK_MANAGER;
        let mut hook_manager = SHARED_HOOK_MANAGER.lock();
        hook_manager.record_allocation(pa as usize, page_count * 0x1000);
        debug!("Recorded protected allocation for EPT hiding catalog: {:#x} ({} pages)", pa, page_count);
    }

    Ok(pa)
}

/// Allocate protected memory for a large VM structure (legacy helper).
///
/// The VM structure is large and critical – it must survive ExitBootServices.
/// Internally this uses RUNTIME_SERVICES_DATA pages.
///
/// NOTE:
///   In the current design, the hypervisor allocates its `Vm` from its own
///   heap (see `vmm::start_hypervisor`) and then `hide_hv_with_ept` records
///   that contiguous range directly. This function is kept for compatibility
///   / experimentation, but is not required for the main flow.
pub fn allocate_vm_memory(size: usize) -> uefi::Result<u64> {
    let page_count = (size + 0xFFF) / 0x1000;
    allocate_protected_pages(page_count)
}
