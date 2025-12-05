//! Provides functionality to nullify the relocation table of a loaded UEFI image,
//! record the image base for later virtualization handoff, and register allocations
//! in the shared hook manager.
//!
//! IMPORTANT: We do NOT record the entire UEFI image as "hypervisor memory".
//! Instead, we only record specific hypervisor allocations that should be hidden
//! (or treated specially) from the guest via EPT:
//!
//! - The dummy page (registered with the hook manager as the swap target)
//! - Host stacks (recorded from the stack allocator via `record_host_stack_for_hiding`)
//! - The VM structure (recorded from the hypervisor side in `hide_hv_with_ept`)
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

    // Log the image base for debugging (but DON'T record entire image for hiding)
    log_image_base(&loaded_image);

    // allocate a dummy page filled with 0xFF and hand it to the global hook manager
    let dummy_page_pa = create_dummy_page(0xFF);
    HookManager::initialize_shared_hook_manager(dummy_page_pa);

    // NOTE:
    // - The dummy page is the SWAP TARGET for EPT hiding.
    // - We do NOT record it in the "allocations to hide", because we want
    //   guest mappings to be redirected *to* this page, not hide it itself.
    debug!("Dummy page created at {:#x} (not recorded as a hidden allocation - it's the swap target)", dummy_page_pa);

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

/// Logs the base address and size of the loaded UEFI image (for debugging).
/// We do NOT record this for EPT hiding because:
/// 1. It's too large (~tens of MB)
/// 2. Most of it is legitimate UEFI runtime code that Windows needs
/// 3. Only specific hypervisor structures (VM, host stacks, etc.) need to be hidden
fn log_image_base(loaded_image: &LoadedImage) {
    let (image_base, image_size) = loaded_image.info();
    let image_range = image_base as usize..(image_base as usize + image_size as usize);
    debug!("Loaded image base: {:#x?} (NOT recorded for EPT hiding - too large / mostly runtime code)", image_range);
    debug!("Only specific allocations (VM, stacks, dummy page as swap target) are tracked by the hook manager");
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

/// Call this from hypervisor-side code after allocating the VM structure
/// to record it for EPT hiding.
///
/// In our current layout, `hide_hv_with_ept` computes the VM range directly
/// and calls `HookManager::record_allocation` itself, but this helper is
/// kept for compatibility / future use.
pub fn record_vm_for_hiding(vm_ptr: u64, vm_size: usize) {
    let mut hook_manager = SHARED_HOOK_MANAGER.lock();
    hook_manager.record_allocation(vm_ptr as usize, vm_size);
    debug!("Recorded VM structure for EPT hiding: {:#x} ({} bytes, {} pages)", vm_ptr, vm_size, (vm_size + 0xFFF) / 0x1000);
}

/// Record the host stack range so the hypervisor can treat it as part of the
/// hypervisor heap to be hidden from the guest via EPT.
///
/// This is called from `stack::allocate_host_stack`, which allocates the stack
/// from `RUNTIME_SERVICES_DATA` so Windows will not reclaim it after
/// `ExitBootServices`.
pub fn record_host_stack_for_hiding(stack_base: u64, stack_size: usize) {
    let mut hook_manager = SHARED_HOOK_MANAGER.lock();
    hook_manager.record_allocation(stack_base as usize, stack_size);
    debug!("Recorded host stack for EPT hiding: {:#x} ({} bytes)", stack_base, stack_size);
}
