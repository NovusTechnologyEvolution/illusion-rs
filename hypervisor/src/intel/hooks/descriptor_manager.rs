use {crate::intel::descriptor::Descriptors, lazy_static::lazy_static, spin::Mutex};

/// Manages descriptor tables for both guest and host states in a virtualized environment.
///
/// The `DescriptorManager` struct holds descriptor tables for the guest and host,
/// ensuring that each has the necessary configurations for VMX operations. This includes
/// the Global Descriptor Table (GDT) and the Interrupt Descriptor Table (IDT) for both
/// the guest and host.

pub struct DescriptorManager {
    /// Descriptor tables for the guest state.
    pub guest_descriptor: Descriptors,

    /// Descriptor tables for the host state.
    pub host_descriptor: Descriptors,
}

lazy_static! {
    /// A globally shared instance of `DescriptorManager`, protected by a mutex.
    ///
    /// The `SHARED_DESCRIPTOR_MANAGER` ensures that there is a single instance of
    /// `DescriptorManager` accessible throughout the application. It is protected by
    /// a `spin::Mutex` to ensure safe concurrent access. The descriptor tables are
    /// initialized for both guest and host states.
    pub static ref SHARED_DESCRIPTOR_MANAGER: Mutex<DescriptorManager> = Mutex::new({
        // Log the original UEFI GDT before any modifications
        log_original_gdt();

        DescriptorManager {
            guest_descriptor: Descriptors::initialize_for_guest(),
            host_descriptor: Descriptors::initialize_for_host(),
        }
    });
}

/// Logs the original UEFI GDT entries for debugging
fn log_original_gdt() {
    use crate::intel::support::sgdt;

    let gdtr = sgdt();
    // Copy packed fields to local variables to avoid unaligned access
    let gdtr_base = gdtr.base as u64;
    let gdtr_limit = gdtr.limit;

    log::debug!("=== ORIGINAL UEFI GDT (before hypervisor modifications) ===");
    log::debug!("GDTR base: {:#x}, limit: {:#x}", gdtr_base, gdtr_limit);

    let num_entries = (gdtr_limit as usize + 1) / 8;
    log::debug!("Number of GDT entries: {}", num_entries);

    let gdt_slice = unsafe { core::slice::from_raw_parts(gdtr_base as *const u64, num_entries) };

    for (i, &entry) in gdt_slice.iter().enumerate() {
        let selector = i * 8;
        if entry == 0 {
            log::debug!("  Entry {} (sel {:#06x}): NULL", i, selector);
        } else {
            // Decode the descriptor
            let base_low = (entry >> 16) & 0xFFFF;
            let base_mid = (entry >> 32) & 0xFF;
            let base_high = (entry >> 56) & 0xFF;
            let base = base_low | (base_mid << 16) | (base_high << 24);

            let limit_low = entry & 0xFFFF;
            let limit_high = (entry >> 48) & 0xF;
            let limit = limit_low | (limit_high << 16);

            let access = (entry >> 40) & 0xFF;
            let flags = (entry >> 52) & 0xF;

            let type_field = access & 0xF;
            let s_bit = (access >> 4) & 1;
            let dpl = (access >> 5) & 3;
            let p_bit = (access >> 7) & 1;

            let desc_type = if s_bit == 0 {
                // System descriptor
                match type_field {
                    0x9 => "Available 64-bit TSS",
                    0xB => "Busy 64-bit TSS",
                    0x2 => "LDT",
                    _ => "System",
                }
            } else {
                // Code/Data descriptor
                if (type_field & 0x8) != 0 {
                    if (flags & 0x2) != 0 { "64-bit Code" } else { "32-bit Code" }
                } else {
                    "Data"
                }
            };

            log::debug!(
                "  Entry {} (sel {:#06x}): {:#018x} - {} (access={:#04x}, P={}, DPL={}, base={:#x}, limit={:#x})",
                i,
                selector,
                entry,
                desc_type,
                access,
                p_bit,
                dpl,
                base,
                limit
            );
        }
    }
    log::debug!("=== END ORIGINAL UEFI GDT ===");
}
