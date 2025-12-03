use {
    log::{debug, trace, warn},
    uefi::{
        boot::{self, AllocateType, MemoryType},
        mem::memory_map::MemoryMap, // Import the trait for .entries()
        proto::loaded_image::LoadedImage,
    },
};

/// Hides the hypervisor's memory by logging what memory types it occupies
/// and RECORDING the memory range for later EPT hiding.
///
/// This must be called BEFORE ExitBootServices() is called by the Windows bootloader.
/// For EFI runtime drivers, the memory should already be marked as RuntimeServicesCode/Data.
pub fn hide_uefi_memory() -> uefi::Result<()> {
    // Get our own loaded image
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;
    let image_base = loaded_image.info().0 as u64;
    let image_size = loaded_image.info().1 as u64;
    let image_end = image_base + image_size;

    debug!("Hypervisor image range: {:#x} - {:#x} (size {:#x}, {} pages)", image_base, image_end, image_size, (image_size + 0xFFF) / 0x1000);

    // CRITICAL: Record the hypervisor memory range for EPT hiding later
    // This is what was missing! The hook_manager needs to know what memory to hide.
    {
        use hypervisor::intel::hooks::hook_manager::SHARED_HOOK_MANAGER;
        let mut hook_manager = SHARED_HOOK_MANAGER.lock();
        hook_manager.record_allocation(image_base as usize, image_size as usize);
        debug!("Recorded hypervisor memory range for EPT hiding: {:#x} - {:#x}", image_base, image_end);
    }

    // The image itself should already be marked as RuntimeServicesCode/Data
    // because we're built as efi_runtime_driver.
    //
    // However, let's verify and log the current memory map entries for our range
    log_memory_map_for_range(image_base, image_end);

    Ok(())
}

/// Logs memory map entries that overlap with our image range for debugging
fn log_memory_map_for_range(image_base: u64, image_end: u64) {
    // Get a copy of the memory map for inspection
    if let Ok(memory_map) = boot::memory_map(MemoryType::LOADER_DATA) {
        debug!("Checking memory map entries for hypervisor range:");

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

/// Alternative approach: Allocate protected memory for critical hypervisor structures.
/// Call this to allocate memory that will definitely survive ExitBootServices.
///
/// Returns the physical address of the allocated pages.
pub fn allocate_protected_pages(page_count: usize) -> uefi::Result<u64> {
    // Allocate as RUNTIME_SERVICES_DATA - this memory type persists after ExitBootServices
    let addr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::RUNTIME_SERVICES_DATA, page_count)?;

    let pa = addr.as_ptr() as u64;
    debug!("Allocated {} protected pages at {:#x}", page_count, pa);

    // Also record this allocation for EPT hiding
    {
        use hypervisor::intel::hooks::hook_manager::SHARED_HOOK_MANAGER;
        let mut hook_manager = SHARED_HOOK_MANAGER.lock();
        hook_manager.record_allocation(pa as usize, page_count * 0x1000);
        debug!("Recorded protected allocation for EPT hiding: {:#x} ({} pages)", pa, page_count);
    }

    Ok(pa)
}

/// Allocate protected memory for the VM structure specifically.
/// The VM structure is large (~4MB) and critical - it must survive.
pub fn allocate_vm_memory(size: usize) -> uefi::Result<u64> {
    let page_count = (size + 0xFFF) / 0x1000;
    allocate_protected_pages(page_count)
}
