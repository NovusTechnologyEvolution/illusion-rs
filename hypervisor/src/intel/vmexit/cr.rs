//! Control Register access VM-exit handler
//! Credits to @vmctx (original), extended to handle all access types

use {
    crate::{
        error::HypervisorError,
        intel::{
            events::EventInjection,
            invvpid::{VPID_TAG, invvpid_single_context},
            support::{rdmsr, vmread, vmwrite},
            vm::Vm,
            vmerror::{ControlRegAccessExitQualification, CrAccessReg, CrAccessType},
            vmexit::ExitType,
        },
    },
    bit_field::BitField,
    core::{
        ops::Range,
        ptr::{addr_of, addr_of_mut},
    },
    log::{debug, trace, warn},
    x86::vmx::{
        vmcs,
        vmcs::{control, guest},
    },
    x86_64::registers::control::{Cr0Flags, Cr4Flags},
};

/// Handles the `ControlRegisterAccess` VM-exit.
///
/// This function is invoked when the guest executes certain instructions
/// that read or write to control registers.
///
/// # Arguments
///
/// * `vm`: A mutable reference to the VM.
///
/// # Returns
///
/// * `Result<ExitType, HypervisorError>`: Ok with the appropriate exit type or an error.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 26.1.3 Instructions That Cause VM Exits Conditionally
pub fn handle_cr_reg_access(vm: &mut Vm) -> Result<ExitType, HypervisorError> {
    let qual = vmread(vmcs::ro::EXIT_QUALIFICATION);
    let cr = ControlRegAccessExitQualification::from_exit_qualification(qual);
    let rip = vmread(guest::RIP);

    // Only log at trace level to reduce overhead
    trace!("CR access: {:?} {:?}, GPR={}, RIP={:#x}", cr.access_type, cr.control_reg, cr.gpr_mov_cr, rip);

    match cr.access_type {
        CrAccessType::MovToCr => match cr.control_reg {
            CrAccessReg::Cr0 => Ok(handle_mov_to_cr0(vm, cr.gpr_mov_cr)),
            CrAccessReg::Cr3 => Ok(handle_mov_to_cr3(vm, cr.gpr_mov_cr)),
            CrAccessReg::Cr4 => handle_mov_to_cr4(vm, cr.gpr_mov_cr),
            CrAccessReg::Cr8 => Ok(handle_mov_to_cr8(vm, cr.gpr_mov_cr)),
            _ => {
                warn!("Unhandled MOV to CR{:?}", cr.control_reg);
                Err(HypervisorError::UnhandledVmExit)
            }
        },
        CrAccessType::MovFromCr => match cr.control_reg {
            CrAccessReg::Cr0 => Ok(handle_mov_from_cr0(vm, cr.gpr_mov_cr)),
            CrAccessReg::Cr3 => Ok(handle_mov_from_cr3(vm, cr.gpr_mov_cr)),
            CrAccessReg::Cr4 => Ok(handle_mov_from_cr4(vm, cr.gpr_mov_cr)),
            CrAccessReg::Cr8 => Ok(handle_mov_from_cr8(vm, cr.gpr_mov_cr)),
            _ => {
                warn!("Unhandled MOV from CR{:?}", cr.control_reg);
                Err(HypervisorError::UnhandledVmExit)
            }
        },
        CrAccessType::Clts => Ok(handle_clts()),
        CrAccessType::Lmsw => Ok(handle_lmsw(cr.lmsw_source_data)),
    }
}

/// Gets the value of a guest GPR by index
#[inline]
fn get_gpr_value(vm: &Vm, gpr: u64) -> u64 {
    unsafe { addr_of!(vm.guest_registers).cast::<u64>().add(gpr as usize).read_unaligned() }
}

/// Sets the value of a guest GPR by index
#[inline]
fn set_gpr_value(vm: &mut Vm, gpr: u64, value: u64) {
    unsafe {
        addr_of_mut!(vm.guest_registers).cast::<u64>().add(gpr as usize).write_unaligned(value);
    }
}

// =============================================================================
// MOV TO CR handlers
// =============================================================================

/// Handle MOV to CR0
///
/// The MOV to CR0 instruction causes a VM exit unless the value of its source operand matches,
/// for the position of each bit set in the CR0 guest/host mask, the corresponding bit in the
/// CR0 read shadow.
fn handle_mov_to_cr0(vm: &mut Vm, gpr: u64) -> ExitType {
    trace!("Handling MOV to CR0, source GPR={}", gpr);

    let mut new_cr0 = Cr0Flags::from_bits_retain(get_gpr_value(vm, gpr));

    // CRITICAL: Use SHADOWS for constraint checks, not effective values!
    // The effective values may have VMX-forced bits (like CET) that the guest didn't enable.
    // The guest should only be constrained by bits IT set, not VMX requirements.
    let curr_cr0 = Cr0Flags::from_bits_retain(vmread(control::CR0_READ_SHADOW));
    let curr_cr4 = Cr4Flags::from_bits_retain(vmread(control::CR4_READ_SHADOW));

    let mut new_cr0_raw = new_cr0.bits();

    // CR0[15:6] is always 0
    new_cr0_raw.set_bits(6..16, 0);

    // CR0[17] is always 0
    new_cr0_raw.set_bit(17, false);

    // CR0[28:19] is always 0
    new_cr0_raw.set_bits(19..29, 0);

    new_cr0 = Cr0Flags::from_bits_retain(new_cr0_raw);

    // CR0.ET is always 1
    new_cr0.set(Cr0Flags::EXTENSION_TYPE, true);

    // #GP(0) if setting any reserved bits in CR0[63:32]
    if new_cr0.bits().get_bits(32..64) != 0 {
        debug!("MOV to CR0: #GP - reserved bits set in upper 32 bits");
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // #GP(0) if setting CR0.PG while CR0.PE is clear
    if new_cr0.contains(Cr0Flags::PAGING) && !new_cr0.contains(Cr0Flags::PROTECTED_MODE_ENABLE) {
        debug!("MOV to CR0: #GP - PG=1 with PE=0");
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // #GP(0) if invalid bit combination
    if !new_cr0.contains(Cr0Flags::CACHE_DISABLE) && new_cr0.contains(Cr0Flags::NOT_WRITE_THROUGH) {
        debug!("MOV to CR0: #GP - NW=1 with CD=0");
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // #GP(0) if an attempt is made to clear CR0.PG while in long mode
    // (we're always in long mode as a 64-bit hypervisor)
    if !new_cr0.contains(Cr0Flags::PAGING) {
        debug!("MOV to CR0: #GP - attempting to clear PG in long mode");
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // #GP(0) if an attempt is made to clear CR0.WP while CR4.CET is set
    // NOTE: We check the CR4 SHADOW (guest's view), not the effective CR4!
    // VMX may force CET on in the actual CR4, but that's a VMX requirement,
    // not something the guest enabled.
    if !new_cr0.contains(Cr0Flags::WRITE_PROTECT) && curr_cr4.contains(Cr4Flags::CONTROL_FLOW_ENFORCEMENT) {
        debug!("MOV to CR0: #GP - WP=0 with CET=1 (shadow check)");
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // Handle cache control changes (CD/NW bits)
    if new_cr0.contains(Cr0Flags::CACHE_DISABLE) != curr_cr0.contains(Cr0Flags::CACHE_DISABLE)
        || new_cr0.contains(Cr0Flags::NOT_WRITE_THROUGH) != curr_cr0.contains(Cr0Flags::NOT_WRITE_THROUGH)
    {
        // Cache control changed - may need to invalidate TLBs
        // For now, just allow the change
        trace!("MOV to CR0: cache control bits changed");
    }

    // Update CR0 read shadow (what guest sees when reading CR0)
    vmwrite(control::CR0_READ_SHADOW, new_cr0.bits());

    // Apply VMX fixed bits for the actual CR0 value
    let vmx_cr0_fixed0 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED0);
    let vmx_cr0_fixed1 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED1);

    let mut actual_cr0 = new_cr0;
    actual_cr0 |= Cr0Flags::from_bits_retain(vmx_cr0_fixed0);
    actual_cr0 &= Cr0Flags::from_bits_retain(vmx_cr0_fixed1);

    // CRITICAL: Check what the ACTUAL guest CR4 will have.
    // We need to read the current actual guest CR4 (which may have CET set by Windows).
    // If CET is set in the actual CR4, we MUST force WP=1 in CR0 to satisfy VMX entry checks.
    // This is an architectural requirement: CR0.WP must be 1 when CR4.CET is 1.
    let actual_guest_cr4 = vmread(guest::CR4);
    if (actual_guest_cr4 & (1 << 23)) != 0 {
        // Actual guest CR4 has CET set - we must force WP on
        actual_cr0.insert(Cr0Flags::WRITE_PROTECT);
        trace!("MOV to CR0: forcing WP=1 because actual guest CR4 has CET=1");
    }

    vmwrite(guest::CR0, actual_cr0.bits());

    trace!("MOV to CR0 completed: shadow={:#x}, actual={:#x}", vmread(control::CR0_READ_SHADOW), vmread(guest::CR0));

    ExitType::IncrementRIP
}

/// Handle MOV to CR3
///
/// MOV to CR3 causes a VM exit if any of the bits that are set in the CR3-target mask
/// are different in the source operand and CR3.
fn handle_mov_to_cr3(vm: &mut Vm, gpr: u64) -> ExitType {
    let new_cr3 = get_gpr_value(vm, gpr);

    trace!("Handling MOV to CR3: new value={:#x}", new_cr3);

    // Validate CR3 value
    // Upper bits beyond the physical address width must be 0
    // For simplicity, we allow any valid-looking CR3

    // Write the new CR3 directly to guest state
    vmwrite(guest::CR3, new_cr3);

    // Invalidate TLB for this VPID
    // CRITICAL: We need to invalidate after CR3 changes to ensure
    // the new page tables are used
    invvpid_single_context(VPID_TAG);

    trace!("MOV to CR3 completed");

    ExitType::IncrementRIP
}

/// Handle MOV to CR4
///
/// With minimal CR4 mask (only VMXE bit), most CR4 writes pass through without VM-exit.
/// We only get here when the guest is trying to access the VMXE bit.
/// Our job is simple: hide VMXE from the guest - shadow shows 0, actual has 1.
fn handle_mov_to_cr4(vm: &mut Vm, gpr: u64) -> Result<ExitType, HypervisorError> {
    trace!("Handling MOV to CR4, source GPR={}", gpr);

    let new_cr4_raw = get_gpr_value(vm, gpr);

    // Shadow: what guest thinks CR4 is (VMXE always 0)
    let shadow_cr4 = new_cr4_raw & !Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits();
    vmwrite(control::CR4_READ_SHADOW, shadow_cr4);

    // Actual: what CR4 really is (VMXE always 1 for VMX operation)
    let actual_cr4 = new_cr4_raw | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits();
    vmwrite(guest::CR4, actual_cr4);

    trace!("MOV to CR4 completed: shadow={:#x}, actual={:#x}", shadow_cr4, actual_cr4);

    Ok(ExitType::IncrementRIP)
}

/// Handle MOV to CR8 (Task Priority Register in x2APIC mode)
fn handle_mov_to_cr8(vm: &mut Vm, gpr: u64) -> ExitType {
    let value = get_gpr_value(vm, gpr);

    trace!("Handling MOV to CR8: value={:#x}", value);

    // CR8 only uses bits 3:0 for TPR
    // #GP(0) if bits 63:4 are not all zero
    if value & !0xF != 0 {
        debug!("MOV to CR8: #GP - reserved bits set");
        EventInjection::vmentry_inject_gp(0);
        return ExitType::Continue;
    }

    // Update the virtual TPR in VMCS
    // TPR is stored as bits 7:4 in the TPR threshold
    vmwrite(control::TPR_THRESHOLD, value & 0xF);

    ExitType::IncrementRIP
}

// =============================================================================
// MOV FROM CR handlers
// =============================================================================

/// Handle MOV from CR0
fn handle_mov_from_cr0(vm: &mut Vm, gpr: u64) -> ExitType {
    // Return the CR0 read shadow (what guest expects to see)
    let cr0_shadow = vmread(control::CR0_READ_SHADOW);

    trace!("Handling MOV from CR0: returning shadow={:#x} to GPR{}", cr0_shadow, gpr);

    set_gpr_value(vm, gpr, cr0_shadow);

    ExitType::IncrementRIP
}

/// Handle MOV from CR3
fn handle_mov_from_cr3(vm: &mut Vm, gpr: u64) -> ExitType {
    let cr3 = vmread(guest::CR3);

    trace!("Handling MOV from CR3: returning {:#x} to GPR{}", cr3, gpr);

    set_gpr_value(vm, gpr, cr3);

    ExitType::IncrementRIP
}

/// Handle MOV from CR4
fn handle_mov_from_cr4(vm: &mut Vm, gpr: u64) -> ExitType {
    // Return the CR4 read shadow (what guest expects to see)
    // This hides VMXE from the guest
    let cr4_shadow = vmread(control::CR4_READ_SHADOW);

    trace!("Handling MOV from CR4: returning shadow={:#x} to GPR{}", cr4_shadow, gpr);

    set_gpr_value(vm, gpr, cr4_shadow);

    ExitType::IncrementRIP
}

/// Handle MOV from CR8
fn handle_mov_from_cr8(vm: &mut Vm, gpr: u64) -> ExitType {
    // Read TPR threshold and return as CR8
    let tpr = vmread(control::TPR_THRESHOLD) & 0xF;

    trace!("Handling MOV from CR8: returning {:#x} to GPR{}", tpr, gpr);

    set_gpr_value(vm, gpr, tpr);

    ExitType::IncrementRIP
}

// =============================================================================
// CLTS and LMSW handlers
// =============================================================================

/// Handle CLTS (Clear Task-Switched flag in CR0)
fn handle_clts() -> ExitType {
    trace!("Handling CLTS");

    // Read current CR0 shadow
    let mut cr0_shadow = Cr0Flags::from_bits_retain(vmread(control::CR0_READ_SHADOW));

    // Clear TS bit
    cr0_shadow.remove(Cr0Flags::TASK_SWITCHED);

    // Update shadow
    vmwrite(control::CR0_READ_SHADOW, cr0_shadow.bits());

    // Update actual CR0 (with VMX fixed bits)
    let vmx_cr0_fixed0 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED0);
    let vmx_cr0_fixed1 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED1);

    let mut actual_cr0 = cr0_shadow;
    actual_cr0 |= Cr0Flags::from_bits_retain(vmx_cr0_fixed0);
    actual_cr0 &= Cr0Flags::from_bits_retain(vmx_cr0_fixed1);

    // CRITICAL: If actual guest CR4 has CET set, we must force WP on in CR0
    let actual_guest_cr4 = vmread(guest::CR4);
    if (actual_guest_cr4 & (1 << 23)) != 0 {
        actual_cr0.insert(Cr0Flags::WRITE_PROTECT);
    }

    vmwrite(guest::CR0, actual_cr0.bits());

    trace!("CLTS completed");

    ExitType::IncrementRIP
}

/// Handle LMSW (Load Machine Status Word - loads lower 16 bits of CR0)
fn handle_lmsw(source_data: u64) -> ExitType {
    trace!("Handling LMSW: source_data={:#x}", source_data);

    // LMSW only affects CR0[3:0] (PE, MP, EM, TS)
    // It cannot clear PE once set

    let mut cr0_shadow = Cr0Flags::from_bits_retain(vmread(control::CR0_READ_SHADOW));
    let old_pe = cr0_shadow.contains(Cr0Flags::PROTECTED_MODE_ENABLE);

    // Clear bits 3:0
    let mut cr0_raw = cr0_shadow.bits();
    cr0_raw &= !0xF;

    // Set new bits from source_data (only bits 3:0)
    cr0_raw |= source_data & 0xF;

    cr0_shadow = Cr0Flags::from_bits_retain(cr0_raw);

    // LMSW cannot clear PE
    if old_pe {
        cr0_shadow.insert(Cr0Flags::PROTECTED_MODE_ENABLE);
    }

    // Update shadow
    vmwrite(control::CR0_READ_SHADOW, cr0_shadow.bits());

    // Update actual CR0 with VMX fixed bits
    let vmx_cr0_fixed0 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED0);
    let vmx_cr0_fixed1 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED1);

    let mut actual_cr0 = cr0_shadow;
    actual_cr0 |= Cr0Flags::from_bits_retain(vmx_cr0_fixed0);
    actual_cr0 &= Cr0Flags::from_bits_retain(vmx_cr0_fixed1);

    // CRITICAL: If actual guest CR4 has CET set, we must force WP on in CR0
    let actual_guest_cr4 = vmread(guest::CR4);
    if (actual_guest_cr4 & (1 << 23)) != 0 {
        actual_cr0.insert(Cr0Flags::WRITE_PROTECT);
    }

    vmwrite(guest::CR0, actual_cr0.bits());

    trace!("LMSW completed");

    ExitType::IncrementRIP
}
