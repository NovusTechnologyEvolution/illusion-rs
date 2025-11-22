#![allow(static_mut_refs)]
#![allow(unsafe_op_in_unsafe_fn)]
//! This module provides a global allocator using a linked list heap allocation strategy.

use {
    crate::global_const::TOTAL_HEAP_SIZE,
    alloc::boxed::Box,
    core::{
        alloc::{GlobalAlloc, Layout},
        ptr,
    },
    log::{debug, trace},
    spin::Mutex,
};

/// The global heap size used by the allocator.
const HEAP_SIZE: usize = TOTAL_HEAP_SIZE;

/// A statically allocated heap for the entire system.
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

/// A global mutex-protected allocator instance.
static ALLOCATOR_MUTEX: Mutex<()> = Mutex::new(());

/// A global linked list heap allocator instance.
static mut LIST_HEAP: Option<ListHeap<HEAP_SIZE>> = None;

/// A global allocator that uses the custom linked list heap.
pub struct GlobalAllocator;

/// Initializes the global allocator.
pub fn heap_init() {
    init_allocator();
}

/// Initializes the global allocator.
pub fn init_allocator() {
    unsafe {
        LIST_HEAP = Some(ListHeap::new(&mut HEAP));
    }
}

/// A linked list heap allocator.
pub struct ListHeap<const SIZE: usize> {
    memory: *mut u8,
    size: usize,
    free_list_head: *mut Link,
}

#[repr(C)]
struct Link {
    next: *mut Link,
    size: isize, // Positive = free, Negative = allocated
}

impl Link {
    const SIZE: usize = core::mem::size_of::<Link>();
}

impl<const SIZE: usize> ListHeap<SIZE> {
    pub fn new(memory: &mut [u8; SIZE]) -> Self {
        let heap_ptr = memory.as_mut_ptr();
        let free_list_head = heap_ptr as *mut Link;
        unsafe {
            (*free_list_head).next = ptr::null_mut();
            // Entire heap is one big free block initially
            (*free_list_head).size = (SIZE as isize) - (Link::SIZE as isize);
        }

        Self {
            memory: heap_ptr,
            size: SIZE,
            free_list_head,
        }
    }

    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _guard = ALLOCATOR_MUTEX.lock();

        // Ensure alignment for Link header (usually 8 bytes on x64)
        let align = layout.align().max(core::mem::align_of::<Link>());
        let size = layout.size().max(core::mem::size_of::<usize>());

        let mut prev_link: *mut Link = ptr::null_mut();
        let mut curr_link = self.free_list_head;

        while !curr_link.is_null() {
            // Skip allocated blocks (size < 0)
            if (*curr_link).size < 0 {
                prev_link = curr_link;
                curr_link = (*curr_link).next;
                continue;
            }

            // Calculate address for payload
            let curr_addr = curr_link as usize;
            let payload_start = curr_addr + Link::SIZE;

            // Calculate alignment padding needed
            let aligned_payload_start = (payload_start + (align - 1)) & !(align - 1);
            let padding = aligned_payload_start - payload_start;

            // Total size we need to carve out from this block
            let total_needed = padding + size;
            let available_size = (*curr_link).size as usize;

            if available_size >= total_needed {
                // Found a suitable block!

                // 1. Mark current block as allocated
                // We use the requested size (plus padding) as the allocation size
                (*curr_link).size = -(total_needed as isize);

                // 2. Check if we can split the block
                let remaining = available_size - total_needed;

                // We need space for a new Link header + at least 1 byte of data
                if remaining > Link::SIZE {
                    // Calculate address for the new free block header
                    // It starts immediately after the allocated payload
                    let next_link_addr = aligned_payload_start + size;
                    let new_free_link = next_link_addr as *mut Link;

                    // Initialize the new free block
                    (*new_free_link).size = (remaining as isize) - (Link::SIZE as isize);
                    (*new_free_link).next = (*curr_link).next;

                    // Link current block to the new free block
                    (*curr_link).next = new_free_link;
                }

                // Return the aligned payload pointer
                return aligned_payload_start as *mut u8;
            }

            prev_link = curr_link;
            curr_link = (*curr_link).next;
        }

        // Out of memory
        trace!("Allocator: OOM");
        ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let _guard = ALLOCATOR_MUTEX.lock();

        // We need to find the Link header associated with this pointer.
        // Because of alignment padding, the header is not necessarily exactly `Link::SIZE` bytes behind `ptr`.
        // We must walk the list to find the block that *contains* `ptr`.

        let mut curr = self.free_list_head;
        while !curr.is_null() {
            let data_start = (curr as usize) + Link::SIZE;

            // If allocated (size < 0)
            if (*curr).size < 0 {
                let alloc_size = (-(*curr).size) as usize;
                let data_end = data_start + alloc_size;

                // Check if ptr falls within this block's data region
                // (It will be >= data_start because of potential padding)
                if (ptr as usize) >= data_start && (ptr as usize) < data_end {
                    // Found it. Mark as free.
                    (*curr).size = -(*curr).size;
                    // Simple implementation: we don't coalesce here to keep it robust for now.
                    // Since we only allocate once at startup, fragmentation isn't a huge issue.
                    return;
                }
            }
            curr = (*curr).next;
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
        if !new_ptr.is_null() {
            ptr::copy_nonoverlapping(ptr, new_ptr, core::cmp::min(layout.size(), new_size));
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: GlobalAllocator = GlobalAllocator;

unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match LIST_HEAP.as_ref() {
            Some(heap) => heap.alloc(layout),
            None => ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(heap) = LIST_HEAP.as_ref() {
            heap.dealloc(ptr, layout);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if let Some(heap) = LIST_HEAP.as_ref() {
            heap.realloc(ptr, layout, new_size)
        } else {
            ptr::null_mut()
        }
    }
}

pub unsafe fn box_zeroed<T>() -> Box<T> {
    unsafe { Box::<T>::new_zeroed().assume_init() }
}
