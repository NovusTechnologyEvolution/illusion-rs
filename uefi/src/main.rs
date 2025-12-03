// UEFI-side illusion entrypoint, updated for uefi 0.36.x

#![no_main]
#![no_std]

extern crate alloc;

use {
    crate::{processor::start_hypervisor_on_all_processors, setup::setup, stack::init},
    hypervisor::{
        allocator::{heap_init, init_allocator_with_memory, is_using_protected_memory},
        global_const::TOTAL_HEAP_SIZE,
        logger::{self, SerialPort},
    },
    log::*,
    uefi::{
        boot::{self, AllocateType, MemoryType},
        prelude::*,
    },
};

pub mod hide;
pub mod processor;
pub mod setup;
pub mod stack;
pub mod virtualize;

#[entry]
fn main() -> Status {
    // init uefi-rs global helpers (0.36 style)
    if let Err(e) = uefi::helpers::init() {
        error!("UEFI init failed: {:?}", e);
        return e.status();
    }

    // Initialize stack management
    init();

    // CRITICAL: Allocate heap memory as RUNTIME_SERVICES_DATA
    // This memory type survives ExitBootServices() and won't be reclaimed by Windows!
    let heap_size = TOTAL_HEAP_SIZE;
    let page_count = (heap_size + 0xFFF) / 0x1000;

    match boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::RUNTIME_SERVICES_DATA, // CRITICAL: Survives Windows boot!
        page_count,
    ) {
        Ok(addr) => {
            let heap_ptr = addr.as_ptr() as *mut u8;

            // Initialize the hypervisor's allocator with our protected memory
            unsafe {
                init_allocator_with_memory(heap_ptr, heap_size);
            }
        }
        Err(_e) => {
            // Fallback to static heap if UEFI allocation fails
            heap_init();
        }
    }

    // initialize serial logger from hypervisor crate
    logger::init(SerialPort::COM1, log::LevelFilter::Debug);

    info!("The Matrix is an illusion");

    // Log whether we're using protected memory
    if is_using_protected_memory() {
        info!("Heap is using RUNTIME_SERVICES_DATA - protected from Windows reclamation");
    } else {
        warn!("Heap is using STATIC memory - MAY BE RECLAIMED BY WINDOWS!");
    }

    #[cfg(feature = "hide_uefi_memory")]
    {
        debug!("Hiding hypervisor memory from UEFI");
        if let Err(e) = crate::hide::hide_uefi_memory() {
            error!("Failed to hide hypervisor memory from UEFI: {:?}", e);
            return Status::ABORTED;
        }
    }

    // set up the hypervisor (record image base, dummy page, shared hook manager, zap relocs)
    debug!("Setting up the hypervisor");
    if let Err(e) = setup() {
        error!("Failed to set up the hypervisor: {:?}", e);
        return Status::ABORTED;
    }

    // start HV
    debug!("Starting hypervisor on all processors");
    if let Err(e) = start_hypervisor_on_all_processors() {
        error!("Failed to start hypervisor on all processors: {:?}", e);
        return Status::ABORTED;
    }

    Status::SUCCESS
}
