// uefi/src/processor.rs

use {
    crate::{setup::get_recorded_image_base, stack, virtualize::virtualize_system},
    core::alloc::Layout,
    hypervisor::intel::capture::{GuestRegisters, capture_registers},
    uefi::{Status, table::boot::BootServices},
};

/// Size of the host stack we give to the hypervisor landing code.
/// Adjust if your landing code expects more.
const HOST_STACK_SIZE: usize = 0x4000;

/// Start the hypervisor on *this* processor.
///
/// Matches `main.rs`:
/// - takes only `&BootServices`
/// - returns `uefi::Result<()>`
///
/// On success this never actually returns (we jump to landing code).
pub fn start_hypervisor_on_all_processors(_boot_services: &BootServices) -> uefi::Result<()> {
    //
    // 1. Allocate a host stack we can switch to
    //
    let layout = Layout::from_size_align(HOST_STACK_SIZE, 0x10).expect("valid stack layout");
    let host_stack_base = unsafe { stack::allocate_host_stack(layout) };
    if host_stack_base.is_null() {
        return Err(Status::OUT_OF_RESOURCES.into());
    }

    // UEFI allocator gives us the base (low) address; stacks grow down,
    // so the "top" is base + size.
    let host_stack_top = unsafe { host_stack_base.add(HOST_STACK_SIZE) } as u64;

    //
    // 2. Capture current guest CPU state into the structure the hypervisor expects.
    //
    let mut guest_regs: GuestRegisters = unsafe { core::mem::zeroed() };
    let ok = unsafe { capture_registers(&mut guest_regs) };
    if !ok {
        return Err(Status::ABORTED.into());
    }

    //
    // 3. Figure out what to jump to.
    //    We recorded the UEFI image base during setup(), so reuse that.
    //
    let landing_code = get_recorded_image_base();
    if landing_code == 0 {
        // setup() didn't run or didn't store it
        return Err(Status::ABORTED.into());
    }

    //
    // 4. Hand off to the common stack-jump + landing-jump code.
    //    This never returns.
    //
    virtualize_system(&guest_regs, landing_code as usize, host_stack_top);
}
