#![allow(static_mut_refs)]
#![allow(unsafe_op_in_unsafe_fn)]
//! This module provides a global allocator using a linked list heap allocation strategy.
//!
//! IMPORTANT: Call `init_allocator_with_memory()` with RUNTIME_SERVICES_DATA memory
//! to ensure the heap survives Windows boot. Otherwise, use `heap_init()` for
//! the fallback static heap (which may be reclaimed by Windows).

use {
    crate::global_const::TOTAL_HEAP_SIZE,
    alloc::boxed::Box,
    core::{
        alloc::{GlobalAlloc, Layout},
        ptr,
    },
    log::debug,
    spin::Mutex,
};

/// The global heap size used by the allocator.
const HEAP_SIZE: usize = TOTAL_HEAP_SIZE;

/// A statically allocated heap for the entire system (FALLBACK ONLY).
/// WARNING: This may be in LOADER_DATA memory which Windows reclaims!
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

/// A global mutex-protected allocator instance.
static ALLOCATOR_MUTEX: Mutex<()> = Mutex::new(());

/// A global linked list heap allocator instance.
static mut LIST_HEAP: Option<ListHeap<HEAP_SIZE>> = None;

/// Tracks whether we're using protected memory
static mut USING_PROTECTED_MEMORY: bool = false;

/// A global allocator that uses the custom linked list heap.
pub struct GlobalAllocator;

/// Old name used by the UEFI crate - uses static heap (may be reclaimed!)
pub fn heap_init() {
    init_allocator();
}

/// Initialize with the static heap.
/// WARNING: This memory may be reclaimed by Windows after ExitBootServices!
pub fn init_allocator() {
    unsafe {
        USING_PROTECTED_MEMORY = false;
        LIST_HEAP = Some(ListHeap::new(&mut HEAP));
        debug!("Heap initialized with STATIC memory at {:#x} (WARNING: may be reclaimed by Windows!)", HEAP.as_ptr() as u64);
    }
}

/// Initialize with externally-provided memory.
/// Call this with RUNTIME_SERVICES_DATA memory to survive Windows boot!
///
/// # Safety
/// - `heap_ptr` must point to valid memory of at least `size` bytes
/// - The memory must remain valid for the lifetime of the hypervisor
/// - The memory should be allocated as RUNTIME_SERVICES_DATA
pub unsafe fn init_allocator_with_memory(heap_ptr: *mut u8, size: usize) {
    if heap_ptr.is_null() || size < 0x10000 {
        debug!("Invalid heap parameters, falling back to static heap");
        init_allocator();
        return;
    }

    USING_PROTECTED_MEMORY = true;

    // Zero the memory first
    core::ptr::write_bytes(heap_ptr, 0, size);

    // Initialize the free list head at the start of the memory
    let free_list_head = heap_ptr as *mut Link;
    (*free_list_head).next = ptr::null_mut();
    (*free_list_head).size = size as isize - Link::SIZE as isize;

    // Create a temporary heap structure
    // We need to store this in LIST_HEAP but it expects ListHeap<HEAP_SIZE>
    // Since we're replacing the whole thing, we'll use a workaround
    LIST_HEAP = Some(ListHeap {
        memory: heap_ptr,
        size,
        free_list_head,
    });

    debug!("Heap initialized with PROTECTED memory at {:#x} ({} bytes, {} pages)", heap_ptr as u64, size, (size + 0xFFF) / 0x1000);
}

/// Check if we're using protected memory
pub fn is_using_protected_memory() -> bool {
    unsafe { USING_PROTECTED_MEMORY }
}

/// A linked list heap allocator.
pub struct ListHeap<const SIZE: usize> {
    memory: *mut u8,
    size: usize,
    free_list_head: *mut Link,
}

impl<const SIZE: usize> ListHeap<SIZE> {
    pub fn new(memory: &mut [u8; SIZE]) -> Self {
        let heap_ptr = memory.as_mut_ptr();
        let free_list_head = heap_ptr as *mut Link;
        unsafe {
            (*free_list_head).next = ptr::null_mut();
            (*free_list_head).size = SIZE as isize - Link::SIZE as isize;
        }

        Self {
            memory: heap_ptr,
            size: SIZE,
            free_list_head,
        }
    }

    pub fn reset(&mut self) {
        unsafe {
            let free_list_head = self.memory as *mut Link;
            (*free_list_head).next = ptr::null_mut();
            (*free_list_head).size = self.size as isize - Link::SIZE as isize;
            self.free_list_head = free_list_head;
        }
    }

    fn _debug(&self) {
        unsafe {
            let mut link = self.free_list_head;

            let mut total_allocations = 0usize;
            let mut total_allocation_size = 0usize;
            let total_freespace = 0usize;
            let mut max_freespace = 0usize;
            let mut largest_allocation = 0usize;

            while !link.is_null() {
                total_allocations += 1;
                let used = if (*link).size < 0 {
                    let used = (-(*link).size) as usize;
                    total_allocation_size += used;
                    used
                } else {
                    let free_size = (*link).size as usize;
                    max_freespace = max_freespace.max(free_size);
                    0
                };

                largest_allocation = largest_allocation.max(used);

                link = (*link).next;
            }

            total_allocations -= 1;

            let wasted = (total_allocations + 2) * Link::SIZE;
            debug!("Total Heap Size:                     0x{:X}", self.size);
            debug!("Space wasted on memory management:   0x{wasted:X} bytes");
            debug!("Total memory allocated:              0x{total_allocation_size:X} bytes");
            debug!("Total memory available:              0x{total_freespace:X} bytes");
            debug!("Largest allocated buffer:            0x{largest_allocation:X} bytes");
            debug!("Largest available buffer:            0x{max_freespace:X} bytes");
            debug!("Total allocation count:              0x{total_allocations:X}");
        }
    }
}

#[repr(C, align(0x10))]
struct Link {
    next: *mut Link,
    size: isize,
}

impl Link {
    const SIZE: usize = core::mem::size_of::<Link>();
}

impl<const SIZE: usize> ListHeap<SIZE> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _guard = ALLOCATOR_MUTEX.lock();

        let aligned_size = layout.size().max(core::mem::size_of::<usize>());
        let required_size =
            (aligned_size + (layout.align().max(core::mem::size_of::<usize>()) - 1)) & !(layout.align().max(core::mem::size_of::<usize>()) - 1);

        let mut link = self.free_list_head;

        while !link.is_null() {
            if (*link).size <= 0 {
                link = (*link).next;
                continue;
            }

            let start_of_free = link as usize + Link::SIZE;
            let aligned_pointer = (start_of_free + (layout.align() - 1)) & !(layout.align() - 1);
            let free_start = start_of_free;
            let free_end = free_start + (*link).size as usize;

            if aligned_pointer + required_size <= free_end {
                let remaining_size = free_end - (aligned_pointer + required_size);

                let alloc_link = (aligned_pointer - Link::SIZE) as *mut Link;
                (*alloc_link).next = (*link).next;
                (*alloc_link).size = -(required_size as isize);

                if remaining_size > Link::SIZE {
                    let new_free_link = (aligned_pointer + required_size) as *mut Link;
                    (*new_free_link).next = (*alloc_link).next;
                    (*new_free_link).size = remaining_size as isize - Link::SIZE as isize;
                    (*link).next = new_free_link;
                } else {
                    (*link).next = (*alloc_link).next;
                }

                return aligned_pointer as *mut _;
            }

            link = (*link).next;
        }

        self._debug();
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let _guard = ALLOCATOR_MUTEX.lock();

        let link = (ptr as usize - Link::SIZE) as *mut Link;
        (*link).size = -(*link).size;

        let mut curr = self.free_list_head;
        while !curr.is_null() {
            if curr != link && (*curr).next == link {
                if (*link).next == (*curr).next {
                    (*curr).size += (*link).size + Link::SIZE as isize;
                    (*curr).next = (*link).next;
                }
                break;
            }
            curr = (*curr).next;
        }
    }

    #[allow(dead_code)]
    fn first_link_pos(&self) -> isize {
        self.free_list_head as isize - self.memory as isize
    }
}

unsafe impl<const SIZE: usize> GlobalAlloc for ListHeap<SIZE> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = self.alloc(Layout::from_size_align_unchecked(new_size, old_layout.align()));
        if !new_ptr.is_null() {
            ptr::copy_nonoverlapping(ptr, new_ptr, core::cmp::min(old_layout.size(), new_size));
            self.dealloc(ptr, old_layout);
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
