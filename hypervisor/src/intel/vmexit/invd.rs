//! Manages INVD VM exits to handle guest VM cache invalidation requests securely.

#[cfg(not(feature = "vmware"))]
use crate::intel::support::wbinvd;
use crate::intel::{capture::GuestRegisters, vmexit::ExitType};

/// Manages the INVD instruction VM exit by logging the event and either
/// performing a controlled cache invalidation (bare-metal) or emulating
/// the instruction (nested VMX, e.g. VMware).
///
/// # Arguments
///
/// * `registers` - General-purpose registers of the guest VM at the VM exit.
///
/// # Returns
///
/// * `ExitType::IncrementRIP` - To move past the `INVD` instruction in the VM.

// Nested VMX / VMware path: do NOT execute real INVD/WBINVD, just advance RIP.
#[cfg(feature = "vmware")]
pub fn handle_invd(_guest_registers: &mut GuestRegisters) -> ExitType {
    log::debug!("Handling INVD VM exit under 'vmware' feature - emulating INVD (no real cache flush)");
    // The actual RIP advance is handled by the generic VM-exit logic when
    // this returns ExitType::IncrementRIP.
    ExitType::IncrementRIP
}

// Bare-metal path: execute real WBINVD for cache coherency.
#[cfg(not(feature = "vmware"))]
pub fn handle_invd(_guest_registers: &mut GuestRegisters) -> ExitType {
    log::debug!("Handling INVD VM exit (bare-metal)...");

    // Perform WBINVD to write back and invalidate the hypervisor's caches.
    // This ensures that any modified data is written to memory before cache lines are invalidated.
    wbinvd();

    log::debug!("INVD VMEXIT handled successfully!");

    ExitType::IncrementRIP
}
