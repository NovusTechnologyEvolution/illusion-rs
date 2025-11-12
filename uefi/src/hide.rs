use {
    log::trace,
    uefi::{
        boot::{self, MemoryType},
        mem::memory_map::MemoryMapMut,
        proto::loaded_image::LoadedImage,
    },
};

/// Hides the hypervisor's memory in the UEFI memory map.
pub fn hide_uefi_memory() -> uefi::Result<()> {
    // get our own loaded image
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;

    let image_base = loaded_image.info().0 as u64;
    let image_size = loaded_image.info().1 as u64;
    let image_end = image_base + image_size;

    trace!("Hypervisor memory range: {:#x?} - {:#x?} (size {:#x?})", image_base, image_end, image_size);

    let mut memory_map = boot::memory_map(MemoryType::LOADER_DATA)?;
    memory_map.sort();

    let mut i = 0;
    loop {
        if let Some(descriptor) = memory_map.get_mut(i) {
            let start = descriptor.phys_start;
            let end = start + descriptor.page_count * 0x1000;

            if (start >= image_base && start < image_end) || (end > image_base && end <= image_end) || (start <= image_base && end >= image_end) {
                descriptor.ty = MemoryType::UNUSABLE;
            }

            i += 1;
        } else {
            break;
        }
    }

    Ok(())
}
