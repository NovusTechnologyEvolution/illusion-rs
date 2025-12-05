//! CPUID VM-exit handler.
//!
//! For now this implementation keeps things deliberately simple and conservative:
//! we mostly *pass through* the host CPUID values back to the guest. This is
//! the safest behaviour in a nested-virtualization environment (e.g. VMware)
//! and matches what the guest OS already expects from bare metal / L0.
//!
//! If you want to re-introduce Illusion-style CPUID virtualisation (hiding
//! the hypervisor, Hyper-V friendly leaves, etc.), this is the right file to
//! extend, but the current implementation focuses on correctness and stability
//! first.

use {
    crate::{
        error::HypervisorError,
        intel::{capture::GuestRegisters, vm::Vm, vmexit::ExitType},
    },
    log::*,
    // Import `cpuid` to bring the `cpuid!` macro into scope, and `CpuIdResult`
    // for the returned registers.
    x86::cpuid::{CpuIdResult, cpuid},
};

/// Convenience helper: run the real CPUID instruction for the given leaf/sub-leaf.
fn host_cpuid(eax: u32, ecx: u32) -> CpuIdResult {
    // The x86 crate exposes a `cpuid!` macro which accepts (eax, ecx) and
    // returns a `CpuIdResult { eax, ebx, ecx, edx }`.
    //
    // We call it here so all host-CPUID usage is centralized.
    unsafe { cpuid!(eax, ecx) }
}

/// Handle a CPUID VM-exit.
///
/// This reads the guest's requested leaf/sub-leaf from RAX/RCX, executes CPUID
/// on the host CPU, writes the results back into the guest register snapshot,
/// and advances RIP.
pub fn handle_cpuid(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    let regs: &mut GuestRegisters = &mut vm.guest_registers;

    let eax_in = regs.rax as u32;
    let ecx_in = regs.rcx as u32;

    trace!("CPUID exit: leaf={:#x}, sub_leaf={:#x}, RIP={:#x}", eax_in, ecx_in, regs.rip);

    // Execute CPUID on the real CPU.
    let CpuIdResult { eax, ebx, ecx, edx } = host_cpuid(eax_in, ecx_in);

    regs.rax = eax as u64;
    regs.rbx = ebx as u64;
    regs.rcx = ecx as u64;
    regs.rdx = edx as u64;

    // If you want to add any Illusion-style behaviour (e.g. special leaves
    // that talk to the hypervisor, or masking certain feature bits), this is
    // the natural place to hook them in:
    //
    //   match eax_in {
    //       0x4000_0000 => { /* hypervisor signature / interface */ }
    //       0x4149_4c4c => { /* "AILL" backdoor leaf */ }
    //       _ => { /* fall back to generic path above */ }
    //   }
    //
    // For now we keep everything as a transparent pass-through.

    Ok(ExitType::IncrementRIP)
}
