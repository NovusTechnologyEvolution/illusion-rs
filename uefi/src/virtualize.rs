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

fn emergency_log(msg: &str) {
    for &b in msg.as_bytes() {
        outb(0xE9, b);
    }
    outb(0xE9, b'\n');
}

pub fn virtualize_system(guest: &GuestRegisters, landing_code: usize) -> ! {
    emergency_log("virtualize_system: ENTRY");

    let layout = Layout::from_size_align(0x4000, 0x10).expect("valid host stack layout");

    let base_ptr = unsafe { crate::stack::allocate_host_stack(layout) };
    if base_ptr.is_null() {
        emergency_log("virtualize_system: FAILED to allocate host stack");
        loop {}
    }

    let host_stack_top = unsafe { base_ptr.add(0x4000) as u64 };

    emergency_log(&format!("virtualize_system: landing={:#x}, host_stack_top={:#x}", landing_code, host_stack_top));

    debug!("virtualize_system(): landing={:#x}, host_stack_top={:#x}", landing_code, host_stack_top);

    unsafe {
        switch_stack(guest, landing_code, host_stack_top);
    }
}

/// THIS MUST BE pub(crate) SO processor.rs CAN SEE IT
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
    mov rsp, r8
    jmp rdx
"#
);
