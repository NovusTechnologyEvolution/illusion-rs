// UEFI-side illusion entrypoint, updated for uefi 0.36.x

#![no_main]
#![no_std]

extern crate alloc;

use {
    crate::{processor::start_hypervisor_on_all_processors, setup::setup, stack::init},
    hypervisor::{
        allocator::heap_init,
        logger::{self, SerialPort},
    },
    log::*,
    uefi::prelude::*,
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

    // both of these are safe now
    init();
    heap_init();

    // initialize serial logger from hypervisor crate
    // Change Debug to Info to hide the thousands of VM Exit logs
    logger::init(SerialPort::COM1, log::LevelFilter::Debug);

    info!("The Matrix is an illusion");

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
