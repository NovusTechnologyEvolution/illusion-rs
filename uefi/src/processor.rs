// uefi/src/processor.rs

use {
    crate::{setup::get_recorded_image_base, stack, virtualize::virtualize_system},
    core::alloc::Layout,
    hypervisor::intel::capture::{GuestRegisters, capture_registers},
    uefi::Status,
};

/// Size of the host stack we give to the hypervisor landing code.
const HOST_STACK_SIZE: usize = 0x4000;

/// Start the hypervisor on *this* processor.
///
/// Old version took `&BootServices` only to match the old entry signature.
/// With uefi 0.36.x we can reach all the UEFI services we need globally,
/// so we drop that argument.
pub fn start_hypervisor_on_all_processors() -> uefi::Result<()> {
    //
    // 1. Allocate a host stack we can switch to
    //
    let layout = Layout::from_size_align(HOST_STACK_SIZE, 0x10).expect("valid stack layout");
    let host_stack_base = unsafe { stack::allocate_host_stack(layout) };
    if host_stack_base.is_null() {
        return Err(Status::OUT_OF_RESOURCES.into());
    }

    // stacks grow down; UEFI gave us the base (lower) address
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
