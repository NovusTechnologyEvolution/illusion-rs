#![no_main]
#![no_std]

mod images;

use {
    core::time::Duration,
    uefi::{
        boot::{self, LoadImageSource},
        prelude::*,
        proto::BootPolicy,
    },
};

#[entry]
fn main() -> Status {
    // 0.36+ style init
    if let Err(error) = uefi::helpers::init() {
        log::error!("Failed to initialize UEFI services ({:?})", error);
        return Status::ABORTED;
    }

    let image_handle = boot::image_handle();

    log::info!("Searching Illusion hypervisor (illusion.efi)..");

    match images::find_hypervisor() {
        Some(hypervisor_device_path) => {
            log::info!("Found! Loading hypervisor into memory..");

            match boot::load_image(
                image_handle,
                LoadImageSource::FromDevicePath {
                    device_path: &hypervisor_device_path,
                    // normal case: load exactly this file
                    boot_policy: BootPolicy::ExactMatch,
                },
            ) {
                Ok(handle) => {
                    log::info!("Loaded hypervisor into memory, starting..");

                    if let Err(error) = boot::start_image(handle) {
                        log::error!("Failed to start hypervisor ({:?})", error);
                        return Status::ABORTED;
                    }
                }
                Err(error) => {
                    log::error!("Failed to load hypervisor ({:?})", error);
                    return Status::ABORTED;
                }
            }
        }
        None => {
            log::info!("Failed to find hypervisor image");
            return Status::ABORTED;
        }
    };

    log::info!("Searching Windows boot manager (bootmgfw.efi)..");

    match images::find_windows_boot_manager() {
        Some(bootmgr_device_path) => {
            log::info!("Found! Loading boot manager into memory..");

            // stall now takes Duration
            boot::stall(Duration::from_micros(3_000_000));

            match boot::load_image(
                image_handle,
                LoadImageSource::FromDevicePath {
                    device_path: &bootmgr_device_path,
                    boot_policy: BootPolicy::ExactMatch,
                },
            ) {
                Ok(handle) => {
                    log::info!("Loaded boot manager into memory, starting..");

                    if let Err(error) = boot::start_image(handle) {
                        log::error!("Failed to start boot manager ({:?})", error);
                        return Status::ABORTED;
                    }
                }
                Err(error) => {
                    log::error!("Failed to load boot manager ({:?})", error);
                    return Status::ABORTED;
                }
            }
        }
        None => {
            log::info!("Failed to find Windows boot manager image");
            return Status::ABORTED;
        }
    }

    Status::SUCCESS
}
