// uefi/src/virtualize.rs

#![allow(clippy::missing_safety_doc)]

use {
    alloc::format,
    core::{alloc::Layout, arch::global_asm},
    hypervisor::{
        intel::{capture::GuestRegisters, support::outb},
        vmm::start_hypervisor,
    },
    log::debug,
};

/// Size of the per-CPU host stack used by the hypervisor (16 KiB).
const HOST_STACK_SIZE: usize = 0x4000;
/// Alignment for the host stack. We ask for 16-byte alignment to keep
/// things friendly for SIMD / ABI expectations.
const HOST_STACK_ALIGN: usize = 0x10;

/// Very early, very dumb logging path:
/// writes directly to the 0xE9 "debug port" that some hypervisors /
/// emulators mirror to their logs.
fn emergency_log(msg: &str) {
    for &b in msg.as_bytes() {
        outb(0xE9, b);
    }
    outb(0xE9, b'\n');
}

/// UEFI-side entry into the virtualization path.
///
/// This function:
///   * allocates a host stack from `RUNTIME_SERVICES_DATA` via `stack::allocate_host_stack`
///   * computes the top of that stack
///   * switches to it using the tiny `switch_stack` assembly stub
///   * jumps into the `landing` trampoline, which then calls `start_hypervisor`
///
/// The actual allocation is done in `stack::allocate_host_stack`, which
/// is hard-wired to use `MemoryType::RUNTIME_SERVICES_DATA` so Windows
/// will not reclaim it after `ExitBootServices`.
pub fn virtualize_system(guest: &GuestRegisters, landing_code: usize) -> ! {
    emergency_log("virtualize_system: ENTRY");

    // 16 KiB, 16-byte aligned host stack. All the RUNTIME vs LOADER
    // semantics live inside `stack::allocate_host_stack`.
    let layout = Layout::from_size_align(HOST_STACK_SIZE, HOST_STACK_ALIGN).expect("valid host stack layout");

    let base_ptr = unsafe { crate::stack::allocate_host_stack(layout) };
    if base_ptr.is_null() {
        emergency_log("virtualize_system: FAILED to allocate host stack");
        loop {}
    }

    let host_stack_base = base_ptr as u64;
    let host_stack_top = host_stack_base + HOST_STACK_SIZE as u64;

    emergency_log(&format!(
        "virtualize_system: landing={:#x}, host_stack_base={:#x}, host_stack_top={:#x}",
        landing_code, host_stack_base, host_stack_top
    ));

    debug!("virtualize_system(): landing={:#x}, host_stack_base={:#x}, host_stack_top={:#x}", landing_code, host_stack_base, host_stack_top);

    // IMPORTANT:
    // We do *not* record the host stack for EPT hiding here.
    //
    // The host stack:
    //   * lives in RUNTIME_SERVICES_DATA (so Windows will not reclaim it)
    //   * is used by VMX root on every VM-exit
    //
    // Hiding it via EPT (mapping to a dummy page / toggling permissions)
    // would be a great way to triple-fault the CPU when it tries to use
    // this stack during host transitions. So it remains visible from the
    // guest’s physical view; only selected hypervisor data pages are
    // candidates for EPT hiding.

    unsafe {
        switch_stack(guest, landing_code, host_stack_top);
    }
}

/// Landing trampoline that runs on the freshly-allocated host stack.
///
/// From here we are in VMX root (once `start_hypervisor` does its job),
/// and we stay in the hypervisor until `capture_registers` "returns true"
/// back in the guest.
pub(crate) extern "efiapi" fn landing(guest: &GuestRegisters) -> ! {
    emergency_log("landing: ENTRY (on host stack)");
    debug!("landing(): calling start_hypervisor");

    start_hypervisor(guest)
}

unsafe extern "efiapi" {
    fn switch_stack(guest: &GuestRegisters, landing: usize, new_stack: u64) -> !;
}

global_asm!(
    r#"
.global switch_stack
switch_stack:
    // r8  = new_stack (top of host stack)
    // rdx = landing (GuestRegisters -> ! trampoline)
    // rcx = guest (&GuestRegisters), preserved across the jump

    mov     rsp, r8        // switch to new host stack
    jmp     rdx            // tail-call into landing()
"#
);
