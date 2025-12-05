#![allow(unsafe_op_in_unsafe_fn)]

use {
    crate::setup::record_host_stack_for_hiding,
    core::{alloc::Layout, ptr},
    uefi::boot::{self, MemoryType},
};

/// Allocate memory using UEFI pool allocations from RUNTIME memory.
///
/// This is critical: We MUST use RUNTIME_SERVICES_DATA (or RUNTIME_SERVICES_CODE)
/// so that Windows doesn't reclaim this memory after ExitBootServices.
///
/// LOADER_DATA/LOADER_CODE gets reclaimed by Windows, causing triple faults
/// when VM-exits try to use the overwritten stack.
///
/// This is called by the processor code to get a host stack for the landing
/// code. We keep it `unsafe` just like the original.
pub unsafe fn allocate_host_stack(layout: Layout) -> *mut u8 {
    let size = layout.size();
    let align = layout.align();

    // CRITICAL: Use RUNTIME memory, not LOADER memory!
    // RUNTIME_SERVICES_DATA persists after ExitBootServices and won't be reclaimed by Windows.
    let memory_type = MemoryType::RUNTIME_SERVICES_DATA;

    // result pointer we'll hand back
    let stack: *mut u8 = if align > 8 {
        // We need better alignment than UEFI promises, so allocate bigger and
        // carve out an aligned sub-region, just like the original file did.
        let full_alloc_ptr = match boot::allocate_pool(memory_type, size + align) {
            Ok(ptr) => ptr.as_ptr(),
            Err(_) => ptr::null_mut(),
        };

        if full_alloc_ptr.is_null() {
            ptr::null_mut()
        } else {
            // Find an aligned address inside the allocated block.
            let mut offset = full_alloc_ptr.align_offset(align);
            if offset == 0 {
                offset = align;
            }

            // Aligned pointer we'll return.
            let aligned_ptr = full_alloc_ptr.add(offset);

            // Store the original allocation pointer right before the aligned one,
            // so a potential free-path can get back to it (same trick as before).
            aligned_ptr.cast::<*mut u8>().sub(1).write(full_alloc_ptr);

            aligned_ptr
        }
    } else {
        // 8-byte alignment is already guaranteed.
        match boot::allocate_pool(memory_type, size) {
            Ok(ptr) => ptr.as_ptr(),
            Err(_) => ptr::null_mut(),
        }
    };

    if !stack.is_null() {
        // Record this host stack in the shared hook manager so the EPT hiding
        // logic can treat it as “hypervisor-owned” memory.
        //
        // NOTE:
        //  - This is the *physical* region backing our VMX-root stack.
        //  - EPT only affects the guest’s view; the host still sees the real page.
        //  - hide_hv_with_ept() will use an exclusion list to avoid doing
        //    anything stupid with critical control structures.
        record_host_stack_for_hiding(stack as u64, size);
    }

    stack
}

/// Optional: Initialize stack / pool allocation bookkeeping.
///
/// Note: We no longer use this to determine memory type since we hardcode
/// RUNTIME_SERVICES_DATA, but keeping it for compatibility if you call it elsewhere.
pub fn init() {
    // No longer needed for stack allocation, but kept for API compatibility.
}
