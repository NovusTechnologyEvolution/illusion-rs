//! Diagnostic utilities for debugging VM-exits and crashes
//! Add these to your main vmexit handler loop

use core::sync::atomic::{AtomicU64, Ordering};

/// Counter for total VM-exits
pub static VMEXIT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Last N exit reasons for debugging
pub static LAST_EXIT_REASONS: [AtomicU64; 16] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Last N RIP values for debugging
pub static LAST_RIPS: [AtomicU64; 16] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Record a VM-exit for debugging
/// Call this at the start of your vmexit handler
pub fn record_vmexit(exit_reason: u64, rip: u64) {
    let count = VMEXIT_COUNT.fetch_add(1, Ordering::SeqCst);
    let idx = (count % 16) as usize;
    LAST_EXIT_REASONS[idx].store(exit_reason, Ordering::SeqCst);
    LAST_RIPS[idx].store(rip, Ordering::SeqCst);

    // Log milestones
    if count == 10 || count == 100 || count == 1000 || count == 5000 || count % 10000 == 0 {
        log::info!("VM-exit milestone: {} exits", count);
    }

    // Log every CR access (exit reason 28) since those are your last exits before crash
    if exit_reason == 28 {
        log::info!("Exit #{}: ControlRegisterAccesses @ RIP={:#x}", count, rip);
    }
}

/// Dump the last N VM-exits (call this in your panic handler or before BSOD)
pub fn dump_last_vmexits() {
    log::error!("=== LAST 16 VM-EXITS ===");
    let current_count = VMEXIT_COUNT.load(Ordering::SeqCst);

    for i in 0..16 {
        let idx = ((current_count.wrapping_sub(15).wrapping_add(i as u64)) % 16) as usize;
        let reason = LAST_EXIT_REASONS[idx].load(Ordering::SeqCst);
        let rip = LAST_RIPS[idx].load(Ordering::SeqCst);

        let reason_name = match reason {
            0 => "ExceptionOrNmi",
            1 => "ExternalInterrupt",
            10 => "Cpuid",
            12 => "Hlt",
            28 => "ControlRegisterAccesses",
            31 => "Rdmsr",
            32 => "Wrmsr",
            37 => "MonitorTrapFlag",
            48 => "EptViolation",
            49 => "EptMisconfiguration",
            55 => "Xsetbv",
            _ => "Other",
        };

        log::error!("  [{}] Exit reason {} ({}) @ RIP {:#x}", i, reason, reason_name, rip);
    }
    log::error!("Total exits: {}", current_count);
}

/// Macro to add diagnostic recording to your vmexit handler
/// Usage:
/// ```
/// let exit_reason = vm.run()?;
/// record_vmexit_diagnostic!(exit_reason, vm.guest_registers.rip);
/// ```
#[macro_export]
macro_rules! record_vmexit_diagnostic {
    ($reason:expr, $rip:expr) => {
        $crate::intel::vmexit::diagnostics::record_vmexit($reason as u64, $rip);
    };
}

/// Check if we're in a potentially dangerous state
/// Call this after handling each vmexit
pub fn check_vm_state_sanity(guest_cr0: u64, guest_cr3: u64, guest_cr4: u64, guest_rip: u64, guest_rsp: u64) -> bool {
    let mut sane = true;

    // Check CR0 basic requirements for long mode
    if (guest_cr0 & 0x80000001) != 0x80000001 {
        log::error!("INSANE: CR0.PE or CR0.PG not set! CR0={:#x}", guest_cr0);
        sane = false;
    }

    // Check CR3 is not zero (would be very bad)
    if guest_cr3 == 0 {
        log::error!("INSANE: CR3 is zero!");
        sane = false;
    }

    // Check CR4.PAE is set (required for long mode)
    if (guest_cr4 & (1 << 5)) == 0 {
        log::error!("INSANE: CR4.PAE not set! CR4={:#x}", guest_cr4);
        sane = false;
    }

    // Check RIP looks reasonable (in kernel space or user space)
    // Kernel addresses in Windows are typically above 0xFFFF800000000000
    // User addresses are typically below 0x00007FFFFFFFFFFF
    if guest_rip == 0 || guest_rip == 0xFFFFFFFFFFFFFFFF {
        log::error!("INSANE: RIP is invalid! RIP={:#x}", guest_rip);
        sane = false;
    }

    // Check RSP looks reasonable
    if guest_rsp == 0 {
        log::error!("INSANE: RSP is zero!");
        sane = false;
    }

    if !sane {
        dump_last_vmexits();
    }

    sane
}
