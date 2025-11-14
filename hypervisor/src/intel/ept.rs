#![allow(unsafe_op_in_unsafe_fn)]
//! Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3 THE EXTENDED PAGE TABLE MECHANISM (EPT)
//! The extended page-table mechanism (EPT) is a feature that can be used to support the virtualization of physical memory.
//! When EPT is in use, certain addresses that would normally be treated as physical addresses (and used to access memory) are instead treated as guest-physical addresses
//! Guest-physical addresses are translated by traversing a set of EPT paging structures to produce physical addresses that are used to access memory.
//!
//! Credits to the work by Satoshi (https://github.com/tandasat/Hello-VT-rp/blob/main/hypervisor/src/intel_vt/epts.rs) and Matthias (https://github.com/not-matthias/amd_hypervisor/blob/main/hypervisor/src/svm/nested_page_table.rs).

use {
    crate::{
        error::HypervisorError,
        intel::{invept::invept_all_contexts, invvpid::invvpid_all_contexts, mtrr::MemoryType},
    },
    bitfield::bitfield,
    core::ptr::addr_of,
    log::*,
    x86::bits64::paging::{BASE_PAGE_SHIFT, BASE_PAGE_SIZE, HUGE_PAGE_SIZE, LARGE_PAGE_SIZE, VAddr, pd_index, pdpt_index, pml4_index, pt_index},
};

/// Represents the entire Extended Page Table structure.
///
/// EPT is a set of nested page tables similar to the standard x86-64 paging mechanism.
/// It consists of 4 levels: PML4, PDPT, PD, and PT.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual: 29.3.2 EPT Translation Mechanism
#[repr(C, align(4096))]
pub struct Ept {
    /// Page Map Level 4 (PML4) Table.
    pml4: Pml4,
    /// Page Directory Pointer Table (PDPT).
    pdpt: Pdpt,
    /// Array of Page Directory Table (PDT).
    pd: [Pd; 512],
    /// Page Table (PT).
    pt: Pt,
}

impl Ept {
    /// Initializes the Extended Page Table (EPT) structure.
    pub fn init(&mut self) {
        self.pml4 = Pml4(Table { entries: [Entry(0); 512] });
        self.pdpt = Pdpt(Table { entries: [Entry(0); 512] });
        self.pd = [Pd(Table { entries: [Entry(0); 512] }); 512];
        self.pt = Pt(Table { entries: [Entry(0); 512] });
    }

    /// Builds a simplified identity-mapped EPT using 2MB pages.
    ///
    /// This maps guest-physical 0..N directly to host-physical 0..N with
    /// read/write/execute and Write-Back memory type, using:
    ///   - PML4[0] → PDPT
    ///   - PDPT[i] → PD[i]
    ///   - PD entries as 2MB large pages
    ///
    /// We intentionally avoid per-page MTRR lookups here for robustness.
    pub fn build_identity(&mut self) -> Result<(), HypervisorError> {
        debug!("EPT: Building simplified identity map");

        // Ensure everything starts from a clean slate.
        self.init();

        // Point PML4[0] to PDPT.
        self.pml4.0.entries[0].set_readable(true);
        self.pml4.0.entries[0].set_writable(true);
        self.pml4.0.entries[0].set_executable(true);
        self.pml4.0.entries[0].set_pfn(addr_of!(self.pdpt) as u64 >> BASE_PAGE_SHIFT);

        // We'll map up to 512 GiB with 2MB pages:
        //   512 PDPT entries * 512 PDEs * 2MB = 512 GiB.
        let mut pa: u64 = 0;
        let max_pa: u64 = 512u64 * 512u64 * LARGE_PAGE_SIZE as u64;
        let wb_type = MemoryType::WriteBack as u64;

        for (pdpt_i, pdpte) in self.pdpt.0.entries.iter_mut().enumerate() {
            if pa >= max_pa {
                break;
            }

            // PDPT entry points to PD[pdpt_i]
            pdpte.set_readable(true);
            pdpte.set_writable(true);
            pdpte.set_executable(true);
            pdpte.set_pfn(addr_of!(self.pd[pdpt_i]) as u64 >> BASE_PAGE_SHIFT);

            let pd = &mut self.pd[pdpt_i];

            for pde in &mut pd.0.entries {
                if pa >= max_pa {
                    break;
                }

                // Large 2MB page mapping: R/W/X, WB
                pde.set_readable(true);
                pde.set_writable(true);
                pde.set_executable(true);
                pde.set_memory_type(wb_type);
                pde.set_large(true);
                pde.set_pfn(pa >> BASE_PAGE_SHIFT);

                pa += LARGE_PAGE_SIZE as u64;
            }
        }

        let mapped_gib = pa / (1024 * 1024 * 1024);
        debug!("EPT: Identity map complete ({} GiB mapped with 2MB pages, WB memory type)", mapped_gib);

        Ok(())
    }

    /// Translates a guest physical address to a host physical address using the EPT.
    ///
    /// This function traverses the EPT hierarchy (PML4, PDPT, PD, PT) to translate the given
    /// guest physical address (GPA) to its corresponding host physical address (HPA).
    ///
    /// # Arguments
    ///
    /// * `guest_pa` - The guest physical address to translate.
    ///
    /// # Returns
    ///
    /// A `Result<u64, HypervisorError>` containing the host physical address on success.
    /// Translates a guest physical address to a host physical address using the EPT.
    /// This function traverses the EPT hierarchy (PML4, PDPT, PD, PT) to translate the given
    /// guest physical address (GPA) to its corresponding host physical address (HPA).
    ///
    /// # Arguments
    ///
    /// * `ept_base` - The base address of the EPT structure.
    /// * `guest_pa` - The guest physical address to translate.
    ///
    /// # Returns
    ///
    /// A `Result<u64, HypervisorError>` containing the host physical address on success.
    pub unsafe fn translate_guest_pa_to_host_pa(ept_base: u64, guest_pa: u64) -> Result<u64, HypervisorError> {
        let guest_pa = VAddr::from(guest_pa);

        // Cast the EPT base to the PML4 table structure.
        let pml4_table = ept_base as *const Pml4;

        // Calculate the PML4 index and access the corresponding entry.
        let pml4_index = pml4_index(guest_pa);
        let pml4_entry = &(*pml4_table).0.entries[pml4_index];

        // Check if the PML4 entry is present (readable).
        if !pml4_entry.readable() {
            error!("PML4 entry is not present: {:#x}", guest_pa);
            return Err(HypervisorError::InvalidPml4Entry);
        }

        // Cast the entry to the PDPT table structure.
        let pdpt_table = (pml4_entry.pfn() << BASE_PAGE_SHIFT) as *const Pdpt;

        // Calculate the PDPT index and access the corresponding entry.
        let pdpt_index = pdpt_index(guest_pa);
        let pdpt_entry = &(*pdpt_table).0.entries[pdpt_index];

        // Check if the PDPT entry is present (readable).
        if !pdpt_entry.readable() {
            error!("PDPT entry is not present: {:#x}", guest_pa);
            return Err(HypervisorError::InvalidPdptEntry);
        }

        // Check if the PDPT entry is a huge page (1 GB), if so, calculate the host physical address.
        if pdpt_entry.large() {
            let host_pa = (pdpt_entry.pfn() << BASE_PAGE_SHIFT) + (guest_pa.as_u64() % HUGE_PAGE_SIZE as u64);
            return Ok(host_pa);
        }

        // Cast the entry to the PD table structure.
        let pd_table = (pdpt_entry.pfn() << BASE_PAGE_SHIFT) as *const Pd;

        // Calculate the PD index and access the corresponding entry.
        let pd_index = pd_index(guest_pa);
        let pd_entry = &(*pd_table).0.entries[pd_index];

        // Check if the PD entry is present (readable).
        if !pd_entry.readable() {
            error!("PD entry is not present: {:#x}", guest_pa);
            return Err(HypervisorError::InvalidPdEntry);
        }

        // Check if the PD entry is a large page (2 MB), if so, calculate the host physical address.
        if pd_entry.large() {
            let host_pa = (pd_entry.pfn() << BASE_PAGE_SHIFT) + (guest_pa.as_u64() % LARGE_PAGE_SIZE as u64);
            return Ok(host_pa);
        }

        // Cast the entry to the PT table structure.
        let pt_table = (pd_entry.pfn() << BASE_PAGE_SHIFT) as *const Pt;

        // Calculate the PT index and access the corresponding entry.
        let pt_index = pt_index(guest_pa);
        let pt_entry = &(*pt_table).0.entries[pt_index];

        /*
        // Check if the PT entry is present (readable).
        if !pt_entry.readable() {
            error!("PT entry is not present: {:#x}", guest_pa);
            return Err(HypervisorError::InvalidPtEntry);
        }
        */

        // The PT entry is a 4 KB page, calculate the host physical address.
        let host_pa = (pt_entry.pfn() << BASE_PAGE_SHIFT) + (guest_pa.as_u64() % BASE_PAGE_SIZE as u64);

        Ok(host_pa)
    }

    /// Checks if a guest physical address is part of a large 2MB page.
    pub fn is_large_page(&self, guest_pa: u64) -> bool {
        let guest_pa = VAddr::from(guest_pa);
        let guest_pa = guest_pa.align_down_to_base_page();
        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pde = &self.pd[pdpt_index].0.entries[pd_index];
        pde.large()
    }

    pub fn split_2mb_to_4kb(&mut self, guest_pa: u64, pt: &mut Pt) -> Result<(), HypervisorError> {
        trace!("Splitting 2mb page into 4kb pages: {:#x}", guest_pa);

        let guest_pa = VAddr::from(guest_pa);

        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pde = &mut self.pd[pdpt_index].0.entries[pd_index];

        if !pde.large() {
            trace!("Page is already split: {:x}.", guest_pa);
            return Err(HypervisorError::PageAlreadySplit);
        }

        let memory_type = pde.memory_type();

        *pde = Entry(0);

        trace!("Dumping EPT entries while splitting......");

        for (i, pte) in &mut pt.0.entries.iter_mut().enumerate() {
            *pte = Entry(0);

            let pa = (guest_pa.as_usize() + i * BASE_PAGE_SIZE) as u64;
            pte.set_readable(true);
            pte.set_writable(true);
            pte.set_executable(true);
            pte.set_memory_type(memory_type);
            pte.set_pfn(pa >> BASE_PAGE_SHIFT);
        }

        pde.set_readable(true);
        pde.set_writable(true);
        pde.set_executable(true);
        pde.set_memory_type(0); // reserved for PDE→PT
        pde.set_large(false);
        pde.set_pfn((pt as *mut _ as u64) >> BASE_PAGE_SHIFT);

        Ok(())
    }

    pub fn modify_page_permissions(&mut self, guest_pa: u64, access_type: AccessType, pt: &mut Pt) -> Result<(), HypervisorError> {
        trace!("Modifying permissions for GPA {:#x}", guest_pa);

        let guest_pa = VAddr::from(guest_pa);

        if !guest_pa.is_large_page_aligned() && !guest_pa.is_base_page_aligned() {
            error!("Page is not aligned: {:#x}", guest_pa);
            return Err(HypervisorError::UnalignedAddressError);
        }

        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);

        let pde = &mut self.pd[pdpt_index].0.entries[pd_index];

        if pde.large() {
            trace!("Changing the permissions of a 2MB page");
            pde.set_readable(access_type.contains(AccessType::READ));
            pde.set_writable(access_type.contains(AccessType::WRITE));
            pde.set_executable(access_type.contains(AccessType::EXECUTE));
        } else {
            trace!("Changing the permissions of a 4KB page");
            let pte = &mut pt.0.entries[pt_index];
            pte.set_readable(access_type.contains(AccessType::READ));
            pte.set_writable(access_type.contains(AccessType::WRITE));
            pte.set_executable(access_type.contains(AccessType::EXECUTE));
        }

        Ok(())
    }

    pub fn remap_gpa_to_hpa(&mut self, guest_pa: u64, host_pa: u64, pt: &mut Pt) -> Result<u64, HypervisorError> {
        trace!("Remapping GPA {:#x} to HPA {:#x}", guest_pa, host_pa);

        let guest_pa = VAddr::from(guest_pa);
        let host_pa = VAddr::from(host_pa);

        if !guest_pa.is_base_page_aligned() || !host_pa.is_base_page_aligned() {
            error!("Addresses are not aligned: GPA {:#x}, HPA {:#x}", guest_pa, host_pa);
            return Err(HypervisorError::UnalignedAddressError);
        }

        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);

        let pde = &self.pd[pdpt_index].0.entries[pd_index];

        if pde.large() {
            error!("Cannot remap a large page: GPA {:#x}", guest_pa);
            return Err(HypervisorError::LargePageRemapError);
        }

        let pte = &mut pt.0.entries[pt_index];
        let old_hpa = pte.pfn() << BASE_PAGE_SHIFT;

        pte.set_pfn(host_pa >> BASE_PAGE_SHIFT);
        trace!("Updated PTE for GPA {:#x} from old HPA {:#x} to new HPA {:#x}", guest_pa, old_hpa, host_pa);

        Ok(old_hpa)
    }

    pub fn dump_ept_entries(&self, guest_pa: u64, pt: &Pt) {
        let guest_pa = VAddr::from(guest_pa);
        let pdpt_index = pdpt_index(guest_pa);
        let pd_index = pd_index(guest_pa);
        let pt_index = pt_index(guest_pa);

        let pdpte = &self.pdpt.0.entries[pdpt_index];
        trace!("PDPT at index {}: {:#x?}", pdpt_index, pdpte);

        let pd_address = pdpte.pfn() << BASE_PAGE_SHIFT;
        trace!("PD located at physical address: {:#x}", pd_address);

        let pde = &self.pd[pdpt_index].0.entries[pd_index];
        trace!("PDE at index {}: {:#x?}", pd_index, pde);

        if pde.large() {
            trace!("This is a large page, no PT involved.");
        } else {
            let pt_address = pde.pfn() << BASE_PAGE_SHIFT;
            trace!("PT located at physical address: {:#x}", pt_address);

            let pte = pt.0.entries[pt_index];
            trace!("PTE at index {}: {:#x?}", pt_index, pte);
        }
    }

    pub fn swap_page(&mut self, guest_pa: u64, host_pa: u64, access_type: AccessType, pt: &mut Pt) -> Result<(), HypervisorError> {
        let guest_pa = VAddr::from(guest_pa);
        let host_pa = VAddr::from(host_pa);

        if !guest_pa.is_base_page_aligned() || !host_pa.is_base_page_aligned() {
            error!("Addresses are not aligned: GPA {:#x}, HPA {:#x}", guest_pa, host_pa);
            return Err(HypervisorError::UnalignedAddressError);
        }

        trace!("Modifying permissions for GPA {:#x} to {:?}", guest_pa, access_type);
        self.modify_page_permissions(guest_pa.as_u64(), access_type, pt)?;

        trace!("Remapping GPA {:#x} to HPA {:#x} in the primary EPT", guest_pa, host_pa);
        self.remap_gpa_to_hpa(guest_pa.as_u64(), host_pa.as_u64(), pt)?;

        invept_all_contexts();
        invvpid_all_contexts();

        Ok(())
    }

    pub fn decode_eptp(eptp: u64) -> Result<(u64, MemoryType, u8), HypervisorError> {
        let base_addr = eptp & 0x000f_ffff_ffff_f000;

        let memory_type = match eptp & 0b111 {
            0 => MemoryType::Uncacheable,
            1 => MemoryType::WriteCombining,
            4 => MemoryType::WriteThrough,
            5 => MemoryType::WriteProtected,
            6 => MemoryType::WriteBack,
            _ => return Err(HypervisorError::InvalidEptPml4BaseAddress),
        };

        let page_walk_length = ((eptp >> 3) & 0b111) + 1;

        if base_addr.trailing_zeros() >= 12 {
            Ok((base_addr, memory_type, page_walk_length as u8))
        } else {
            Err(HypervisorError::InvalidEptPml4BaseAddress)
        }
    }

    pub fn create_eptp_with_wb_and_4lvl_walk(&self) -> Result<u64, HypervisorError> {
        let addr = addr_of!(self.pml4) as u64;
        trace!("EPT PML4 (self) address: {:#x}", addr);

        let ept_pml4_base_addr = addr;

        const EPT_PAGE_WALK_LENGTH_4: u64 = 3 << 3;
        const EPT_MEMORY_TYPE_WB: u64 = MemoryType::WriteBack as u64;

        if ept_pml4_base_addr.trailing_zeros() >= 12 {
            Ok(ept_pml4_base_addr | EPT_PAGE_WALK_LENGTH_4 | EPT_MEMORY_TYPE_WB)
        } else {
            Err(HypervisorError::InvalidEptPml4BaseAddress)
        }
    }
}

/// Represents an EPT PML4 Entry (PML4E) that references a Page-Directory-Pointer Table.
#[derive(Debug, Clone, Copy)]
struct Pml4(Table);

/// Represents an EPT Page-Directory-Pointer-Table Entry (PDPTE) that references an EPT Page Directory.
#[derive(Debug, Clone, Copy)]
struct Pdpt(Table);

/// Represents an EPT Page-Directory Entry (PDE) that references an EPT Page Table.
#[derive(Debug, Clone, Copy)]
struct Pd(Table);

/// Represents an EPT Page-Table Entry (PTE) that maps a 4-KByte Page.
#[derive(Debug, Clone, Copy)]
pub struct Pt(Table);

#[repr(C, align(4096))]
#[derive(Debug, Clone, Copy)]
struct Table {
    entries: [Entry; 512],
}

bitfield! {
    #[derive(Clone, Copy)]
    pub struct Entry(u64);
    impl Debug;

    pub readable, set_readable: 0;
    pub writable, set_writable: 1;
    pub executable, set_executable: 2;
    pub memory_type, set_memory_type: 5, 3;
    pub large, set_large: 7;
    pub pfn, set_pfn: 51, 12;
    pub verify_guest_paging, set_verify_guest_paging: 57;
    pub paging_write_access, set_paging_write_access: 58;
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct AccessType: u8 {
        const READ = 0b001;
        const WRITE = 0b010;
        const EXECUTE = 0b100;
        const READ_WRITE = Self::READ.bits() | Self::WRITE.bits();
        const READ_EXECUTE = Self::READ.bits() | Self::EXECUTE.bits();
        const WRITE_EXECUTE = Self::WRITE.bits() | Self::EXECUTE.bits();
        const READ_WRITE_EXECUTE = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
    }
}
