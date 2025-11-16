// hypervisor/src/intel/vmlaunch_diagnostics.rs
//! Extended VMLAUNCH/VMRESUME diagnostics for triple fault debugging.
//!
//! These helpers dump both guest and host VMCS state right before vmlaunch,
//! and perform some basic consistency checks (IA-32e mode, canonical addresses, etc).

use {crate::intel::support::vmread, log::error, x86::vmx::vmcs};

#[inline]
fn is_canonical(addr: u64) -> bool {
    // Canonical check for 48-bit virtual addresses.
    if (addr & 0x0000_8000_0000_0000) != 0 {
        // Upper half: bits 63:48 must all be 1s.
        (addr & 0xFFFF_0000_0000_0000) == 0xFFFF_0000_0000_0000
    } else {
        // Lower half: bits 63:48 must all be 0s.
        (addr & 0xFFFF_0000_0000_0000) == 0
    }
}

/// Dump and sanity-check the guest state in the current VMCS.
pub fn diagnose_guest_state_validity() {
    error!("=== GUEST STATE VALIDITY CHECK ===");

    // --- Control registers -------------------------------------------------
    let guest_cr0 = vmread(vmcs::guest::CR0);
    let guest_cr3 = vmread(vmcs::guest::CR3);
    let guest_cr4 = vmread(vmcs::guest::CR4);

    error!("Guest CR0: 0x{:016x}", guest_cr0);
    let pe = (guest_cr0 & 0x1) != 0;
    let pg = (guest_cr0 & (1 << 31)) != 0;
    error!("  PE (Protected Mode): {}", pe);
    error!("  PG (Paging): {}", pg);

    error!("Guest CR3: 0x{:016x}", guest_cr3);

    error!("Guest CR4: 0x{:016x}", guest_cr4);
    let pae = (guest_cr4 & (1 << 5)) != 0;
    let vmxe = (guest_cr4 & (1 << 13)) != 0;
    error!("  PAE: {}", pae);
    error!("  VMXE: {} (should be 0 in guest)", vmxe);
    if vmxe {
        error!("  ERROR: guest CR4 has VMXE set – guest can directly use VMX!");
    }

    // --- RFLAGS / RIP ------------------------------------------------------
    let guest_rflags = vmread(vmcs::guest::RFLAGS);
    error!("Guest RFLAGS: 0x{:016x}", guest_rflags);
    let rf = (guest_rflags & (1 << 16)) != 0;
    let vm = (guest_rflags & (1 << 17)) != 0;
    error!("  RF (Resume Flag): {}", rf);
    error!("  VM (Virtual-8086): {}", vm);

    let guest_rip = vmread(vmcs::guest::RIP);
    error!("Guest RIP: 0x{:016x}", guest_rip);

    // Entry controls: check IA-32e bit
    let entry_controls = vmread(vmcs::control::VMENTRY_CONTROLS);
    let ia32e_mode_guest = (entry_controls & (1 << 9)) != 0;
    let rip_canonical = is_canonical(guest_rip);

    error!("  IA-32e mode: {}", ia32e_mode_guest);
    error!("  RIP is canonical: {}", rip_canonical);

    // --- EFER --------------------------------------------------------------
    let guest_efer = vmread(vmcs::guest::IA32_EFER_FULL);
    error!("Guest IA32_EFER: 0x{:016x}", guest_efer);

    let efer_lme = (guest_efer & (1 << 8)) != 0;
    let efer_lma = (guest_efer & (1 << 10)) != 0;
    error!("  LME (Long Mode Enable): {}", efer_lme);
    error!("  LMA (Long Mode Active): {}", efer_lma);

    if ia32e_mode_guest && (!efer_lme || !efer_lma) {
        error!("  WARNING: VM entry is IA-32e but EFER.LME/LMA are not both set");
    }

    // --- Segments (CS/SS) --------------------------------------------------
    let guest_cs = vmread(vmcs::guest::CS_SELECTOR) as u16;
    let guest_cs_base = vmread(vmcs::guest::CS_BASE);
    let guest_cs_limit = vmread(vmcs::guest::CS_LIMIT);
    let guest_cs_ar = vmread(vmcs::guest::CS_ACCESS_RIGHTS);

    error!("Guest CS:");
    error!("  Selector: 0x{:04x}", guest_cs);
    error!("  Base: 0x{:016x}", guest_cs_base);
    error!("  Limit: 0x{:08x}", guest_cs_limit as u32);
    error!("  Access Rights: 0x{:08x}", guest_cs_ar as u32);

    let cs_present = (guest_cs_ar & (1 << 7)) != 0;
    let cs_dpl = (guest_cs_ar >> 5) & 0x3;
    let cs_type = guest_cs_ar & 0xF;
    error!("    Present: {}", cs_present);
    error!("    DPL: {}", cs_dpl);
    error!("    Type: 0x{:x}", cs_type);

    if !cs_present {
        error!("    ERROR: CS segment not present!");
    }

    let guest_ss = vmread(vmcs::guest::SS_SELECTOR) as u16;
    let guest_ss_ar = vmread(vmcs::guest::SS_ACCESS_RIGHTS);

    error!("Guest SS:");
    error!("  Selector: 0x{:04x}", guest_ss);
    error!("  Access Rights: 0x{:08x}", guest_ss_ar as u32);

    let ss_present = (guest_ss_ar & (1 << 7)) != 0;
    error!("    Present: {}", ss_present);
    if !ss_present && guest_ss != 0 {
        error!("    ERROR: SS segment not present but selector is non-zero!");
    }

    // --- Descriptor tables -------------------------------------------------
    let gdtr_base = vmread(vmcs::guest::GDTR_BASE);
    let gdtr_limit = vmread(vmcs::guest::GDTR_LIMIT);

    error!("Guest GDTR:");
    error!("  Base: 0x{:016x}", gdtr_base);
    error!("  Limit: 0x{:04x}", gdtr_limit as u16);

    let idtr_base = vmread(vmcs::guest::IDTR_BASE);
    let idtr_limit = vmread(vmcs::guest::IDTR_LIMIT);

    error!("Guest IDTR:");
    error!("  Base: 0x{:016x}", idtr_base);
    error!("  Limit: 0x{:04x}", idtr_limit as u16);

    // --- Controls ----------------------------------------------------------
    let primary_controls = vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS);
    let secondary_controls = vmread(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS);
    let unrestricted_guest = (secondary_controls & (1 << 7)) != 0; // UNRESTRICTED_GUEST bit

    error!("Primary controls:  0x{:08x}", primary_controls as u32);
    error!("Secondary controls: 0x{:08x}", secondary_controls as u32);
    error!("Unrestricted Guest: {}", unrestricted_guest);
}

/// Dump a minimal host-state snapshot from the VMCS.
/// Useful to catch obviously bogus host RIP/RSP/segment setup, which can cause
/// a triple fault on the first VM-exit.
pub fn diagnose_host_state_validity() {
    error!("=== HOST STATE CHECK ===");

    let host_cr0 = vmread(vmcs::host::CR0);
    let host_cr3 = vmread(vmcs::host::CR3);
    let host_cr4 = vmread(vmcs::host::CR4);

    error!("Host CR0: 0x{:016x}", host_cr0);
    let pe = (host_cr0 & 0x1) != 0;
    let pg = (host_cr0 & (1 << 31)) != 0;
    error!("  PE (Protected Mode): {}", pe);
    error!("  PG (Paging): {}", pg);

    error!("Host CR3: 0x{:016x}", host_cr3);

    error!("Host CR4: 0x{:016x}", host_cr4);
    let vmxe = (host_cr4 & (1 << 13)) != 0;
    error!("  VMXE: {} (should be 1 in host)", vmxe);
    if !vmxe {
        error!("  ERROR: host CR4 missing VMXE bit!");
    }

    let host_rip = vmread(vmcs::host::RIP);
    let host_rsp = vmread(vmcs::host::RSP);

    error!("Host RIP: 0x{:016x}", host_rip);
    error!("Host RSP: 0x{:016x}", host_rsp);
    error!("  RIP canonical: {}", is_canonical(host_rip));
    error!("  RSP canonical: {}", is_canonical(host_rsp));

    if host_rip == 0 {
        error!("  ERROR: Host RIP is zero!");
    }
    if host_rsp == 0 {
        error!("  ERROR: Host RSP is zero!");
    }

    let host_cs = vmread(vmcs::host::CS_SELECTOR) as u16;
    let host_ss = vmread(vmcs::host::SS_SELECTOR) as u16;
    let host_ds = vmread(vmcs::host::DS_SELECTOR) as u16;
    let host_es = vmread(vmcs::host::ES_SELECTOR) as u16;
    let host_fs = vmread(vmcs::host::FS_SELECTOR) as u16;
    let host_gs = vmread(vmcs::host::GS_SELECTOR) as u16;
    let host_tr = vmread(vmcs::host::TR_SELECTOR) as u16;

    error!("Host segments:");
    error!("  CS: 0x{:04x} (RPL: {})", host_cs, host_cs & 0x3);
    error!("  SS: 0x{:04x} (RPL: {})", host_ss, host_ss & 0x3);
    error!("  DS: 0x{:04x} (RPL: {})", host_ds, host_ds & 0x3);
    error!("  ES: 0x{:04x} (RPL: {})", host_es, host_es & 0x3);
    error!("  FS: 0x{:04x} (RPL: {})", host_fs, host_fs & 0x3);
    error!("  GS: 0x{:04x} (RPL: {})", host_gs, host_gs & 0x3);
    error!("  TR: 0x{:04x} (RPL: {})", host_tr, host_tr & 0x3);

    // All segment selectors must have RPL=0 for host
    if (host_cs & 0x3) != 0 {
        error!("  ERROR: Host CS has non-zero RPL!");
    }
    if (host_ss & 0x3) != 0 {
        error!("  ERROR: Host SS has non-zero RPL!");
    }
    if (host_ds & 0x3) != 0 {
        error!("  ERROR: Host DS has non-zero RPL!");
    }
    if (host_es & 0x3) != 0 {
        error!("  ERROR: Host ES has non-zero RPL!");
    }
    if (host_tr & 0x3) != 0 {
        error!("  ERROR: Host TR has non-zero RPL!");
    }

    let host_fs_base = vmread(vmcs::host::FS_BASE);
    let host_gs_base = vmread(vmcs::host::GS_BASE);
    let host_tr_base = vmread(vmcs::host::TR_BASE);
    let host_gdtr_base = vmread(vmcs::host::GDTR_BASE);
    let host_idtr_base = vmread(vmcs::host::IDTR_BASE);

    error!("Host FS Base: 0x{:016x}", host_fs_base);
    error!("Host GS Base: 0x{:016x}", host_gs_base);
    error!("Host TR Base: 0x{:016x}", host_tr_base);
    error!("Host GDTR base: 0x{:016x}", host_gdtr_base);
    error!("Host IDTR base: 0x{:016x}", host_idtr_base);

    if host_tr_base == 0 {
        error!("  ERROR: Host TR base is zero!");
    }
    if host_gdtr_base == 0 {
        error!("  ERROR: Host GDTR base is zero!");
    }
    if host_idtr_base == 0 {
        error!("  ERROR: Host IDTR base is zero!");
    }

    // Check SYSENTER MSRs
    let host_sysenter_cs = vmread(vmcs::host::IA32_SYSENTER_CS);
    let host_sysenter_esp = vmread(vmcs::host::IA32_SYSENTER_ESP);
    let host_sysenter_eip = vmread(vmcs::host::IA32_SYSENTER_EIP);

    error!("Host IA32_SYSENTER_CS: 0x{:016x}", host_sysenter_cs);
    error!("Host IA32_SYSENTER_ESP: 0x{:016x}", host_sysenter_esp);
    error!("Host IA32_SYSENTER_EIP: 0x{:016x}", host_sysenter_eip);

    // Check IA32_EFER
    let host_efer = vmread(vmcs::host::IA32_EFER_FULL);
    error!("Host IA32_EFER: 0x{:016x}", host_efer);
    let efer_lme = (host_efer & (1 << 8)) != 0;
    let efer_lma = (host_efer & (1 << 10)) != 0;
    error!("  LME (Long Mode Enable): {}", efer_lme);
    error!("  LMA (Long Mode Active): {}", efer_lma);

    // Check exit controls to see if we're in IA-32e mode
    let exit_controls = vmread(vmcs::control::VMEXIT_CONTROLS);
    let host_address_space_size = (exit_controls & (1 << 9)) != 0;
    error!("Host Address Space Size (64-bit mode): {}", host_address_space_size);

    if host_address_space_size && (!efer_lme || !efer_lma) {
        error!("  ERROR: Host is 64-bit but EFER.LME/LMA not set!");
    }
}
