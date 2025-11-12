//! Provides functionality to nullify the relocation table of a loaded UEFI image,
//! record the image base for later virtualization handoff, and register allocations
//! in the shared hook manager.

use {
    alloc::boxed::Box,
    core::sync::atomic::{AtomicU64, Ordering},
    hypervisor::{
        allocator::box_zeroed,
        intel::{
            hooks::hook_manager::{HookManager, SHARED_HOOK_MANAGER},
            page::Page,
        },
    },
    log::debug,
    uefi::{boot, proto::loaded_image::LoadedImage},
};

/// We remember the image base we discovered during setup so later code
/// (like the processor/virtualization handoff) can jump into it.
static IMAGE_BASE: AtomicU64 = AtomicU64::new(0);

/// Run all setup work that previously needed `&BootServices`.
///
/// With uefi 0.36.x we can reach everything through `uefi::boot`.
pub fn setup() -> uefi::Result<()> {
    // open the currently running image
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;

    // make the base available to other modules and to the shared hook manager
    record_image_base(&loaded_image);

    // allocate a dummy page filled with 0xFF and hand it to the global hook manager
    let dummy_page_pa = create_dummy_page(0xFF);
    HookManager::initialize_shared_hook_manager(dummy_page_pa);

    // also store the base globally for the VM-entry handoff
    let image_base = loaded_image.info().0 as u64;
    IMAGE_BASE.store(image_base, Ordering::Relaxed);

    // stop UEFI / OS from relocating our code
    zap_relocations(image_base);

    Ok(())
}

/// Allow the processor code to grab the image base we found in setup.
pub fn get_recorded_image_base() -> u64 {
    IMAGE_BASE.load(Ordering::Relaxed)
}

/// Records the base address and size of the loaded UEFI image
/// in the shared hook manager.
pub fn record_image_base(loaded_image: &LoadedImage) {
    let (image_base, image_size) = loaded_image.info();
    let image_range = image_base as usize..(image_base as usize + image_size as usize);
    debug!("Loaded image base: {:#x?}", image_range);

    let mut hook_manager = SHARED_HOOK_MANAGER.lock();
    hook_manager.record_allocation(image_base as usize, image_size as usize);
}

/// Creates a dummy page filled with a specific byte value.
pub fn create_dummy_page(fill_byte: u8) -> u64 {
    let mut dummy_page = unsafe { box_zeroed::<Page>() };
    dummy_page.0.iter_mut().for_each(|b| *b = fill_byte);
    Box::into_raw(dummy_page) as u64
}

/// Nullifies the relocation table of the loaded UEFI image to prevent relocation.
pub fn zap_relocations(image_base: u64) {
    unsafe {
        // PE header offsets from the original project
        *((image_base + 0x128) as *mut u32) = 0;
        *((image_base + 0x12c) as *mut u32) = 0;
    }
}
