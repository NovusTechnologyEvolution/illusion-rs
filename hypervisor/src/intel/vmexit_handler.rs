// hypervisor/src/intel/vmexit_handler.rs
//! VM-exit handler assembly stub
//!
//! This assembly function is the target of Host RIP in the VMCS.
//! When a VM-exit occurs, the CPU will jump here.

use core::arch::global_asm;

global_asm!(
    r#"
    .globl vmexit_handler

vmexit_handler:
    // When we arrive here after a VM-exit:
    // - CPU has loaded host CR0, CR3, CR4 from VMCS
    // - CPU has loaded host segments from VMCS
    // - CPU has loaded host RSP from VMCS (set by launch_vm before VMLAUNCH)
    // - CPU has loaded host RIP = this address
    // - CPU is in VMX root mode
    // - CPU is in 64-bit mode (because we set HOST_ADDRESS_SPACE_SIZE in exit controls)
    //
    // The guest state is saved in VMCS, and we can access it via VMREAD.
    //
    // Our job here:
    // 1. The stack (RSP) is already set correctly by launch_vm before VMLAUNCH
    // 2. Just return to the Rust code (launch_vm) which will then return to vm.run()
    // 3. vm.run() reads the exit reason and the main dispatcher (vmm.rs) handles it
    
    // Simply return - the launch_vm assembly set up the stack so we can return
    // directly back to the Rust code that called launch_vm
    ret
    "#
);
