#![allow(unsafe_op_in_unsafe_fn)]

use {
    core::{
        alloc::Layout,
        ptr,
        sync::atomic::{AtomicU32, Ordering},
    },
    hypervisor::intel::hooks::hook_manager::SHARED_HOOK_MANAGER,
    uefi::{
        boot::{self, MemoryType},
        proto::loaded_image::LoadedImage,
    },
};

/// The memory type we should use for pool allocations.
/// We initialize it from the currently loaded image.
static MEMORY_TYPE: AtomicU32 = AtomicU32::new(MemoryType::LOADER_DATA.0);

/// Initialize stack / pool allocation bookkeeping.
/// Old code took `&mut SystemTable<Boot>` and fished boot services out of it.
/// With 0.36 we can just open the loaded image directly.
pub fn init() {
    if let Ok(loaded_image) = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()) {
        MEMORY_TYPE.store(loaded_image.data_type().0, Ordering::Release);
    }
}

/// Allocate memory using UEFI pool allocations, but keep the original
/// “can return an aligned stack” behavior from the project.
///
/// This is called by the processor code to get a host stack for the landing
/// code. We keep it `unsafe` just like the original.
pub unsafe fn allocate_host_stack(layout: Layout) -> *mut u8 {
    let size = layout.size();
    let align = layout.align();
    let memory_type = MemoryType(MEMORY_TYPE.load(Ordering::Acquire));

    // result pointer we’ll hand back
    let stack: *mut u8 = if align > 8 {
        // we need better alignment than UEFI promises, so allocate bigger and
        // carve out an aligned sub-region, just like the original file did
        let full_alloc_ptr = match boot::allocate_pool(memory_type, size + align) {
            Ok(ptr) => ptr.as_ptr(),
            Err(_) => ptr::null_mut(),
        };

        if full_alloc_ptr.is_null() {
            ptr::null_mut()
        } else {
            // find an aligned address inside the allocated block
            let mut offset = full_alloc_ptr.align_offset(align);
            if offset == 0 {
                offset = align;
            }

            // aligned pointer we’ll return
            let aligned_ptr = full_alloc_ptr.add(offset);

            // store the original allocation pointer right before the aligned one,
            // so a potential free-path can get back to it (same trick as before)
            aligned_ptr.cast::<*mut u8>().sub(1).write(full_alloc_ptr);

            aligned_ptr
        }
    } else {
        // 8-byte alignment is already guaranteed
        match boot::allocate_pool(memory_type, size) {
            Ok(ptr) => ptr.as_ptr(),
            Err(_) => ptr::null_mut(),
        }
    };

    if !stack.is_null() {
        // track it in the shared hook manager exactly like the old code
        let mut hook_manager = SHARED_HOOK_MANAGER.lock();
        hook_manager.record_allocation(stack as usize, layout.size());
    }

    stack
}
