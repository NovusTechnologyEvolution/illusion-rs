extern crate alloc;

use {
    alloc::{borrow::ToOwned, boxed::Box, vec::Vec},
    uefi::{
        CStr16, Identify,
        boot::{self, HandleBuffer, SearchType},
        cstr16,
        proto::{
            device_path::{
                DevicePath,
                build::{DevicePathBuilder, media::FilePath},
            },
            media::{
                file::{File, FileAttribute, FileMode},
                fs::SimpleFileSystem,
            },
        },
    },
};

const WINDOWS_BOOT_MANAGER_PATH: &CStr16 = cstr16!(r"\EFI\Microsoft\Boot\bootmgfw.efi");
const HYPERVISOR_PATH: &CStr16 = cstr16!(r"\EFI\Boot\illusion.efi");

/// Finds the device path for a given file path.
pub(crate) fn find_device_path(path: &CStr16) -> Option<Box<DevicePath>> {
    // Get all handles that implement SimpleFileSystem
    let handles: HandleBuffer = boot::locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID)).ok()?;

    // Look through each handle to see if the file exists on it
    handles.iter().find_map(|handle| {
        // Open the filesystem for this handle
        let mut file_system = boot::open_protocol_exclusive::<SimpleFileSystem>(*handle).ok()?;

        // Open its root directory
        let mut root = file_system.open_volume().ok()?;

        // Try to open the file we care about; if this fails, this handle isn't it
        root.open(path, FileMode::Read, FileAttribute::READ_ONLY).ok()?;

        // We also need the DevicePath protocol for this handle
        let device_path = boot::open_protocol_exclusive::<DevicePath>(*handle).ok()?;

        // Build a new device path that is: <device_path> + <file_path>
        let mut storage = Vec::new();
        let mut builder = DevicePathBuilder::with_vec(&mut storage);

        for node in device_path.node_iter() {
            builder = builder.push(&node).ok()?;
        }

        let boot_path = builder.push(&FilePath { path_name: path }).ok()?.finalize().ok()?;

        Some(boot_path.to_owned())
    })
}

/// Finds the device path of the Windows boot manager.
pub(crate) fn find_windows_boot_manager() -> Option<Box<DevicePath>> {
    find_device_path(WINDOWS_BOOT_MANAGER_PATH)
}

/// Finds the device path of the Illusion hypervisor.
pub(crate) fn find_hypervisor() -> Option<Box<DevicePath>> {
    find_device_path(HYPERVISOR_PATH)
}
