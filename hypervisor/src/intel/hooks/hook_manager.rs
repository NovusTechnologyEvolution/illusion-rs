use {
    crate::{
        error::HypervisorError,
        intel::{
            addresses::PhysicalAddress,
            bitmap::{MsrAccessType, MsrBitmap, MsrOperation},
            ept::AccessType,
            hooks::{
                inline::{InlineHook, InlineHookType},
                memory_manager::MemoryManager,
            },
            invept::invept_all_contexts,
            invvpid::invvpid_all_contexts,
            vm::Vm,
        },
        windows::{
            nt::pe::{get_export_by_hash, get_image_base_address, get_size_of_image},
            ssdt::ssdt_hook::SsdtHook,
        },
    },
    alloc::vec::Vec,
    core::ptr::copy_nonoverlapping,
    lazy_static::lazy_static,
    log::*,
    spin::Mutex,
    x86::{
        bits64::paging::{BASE_PAGE_SIZE, PAddr},
        msr,
    },
};

/// What kind of EPT hook we're doing.
#[derive(Debug, Clone, Copy)]
pub enum EptHookType {
    /// We're hooking a function on the shadow page and placing an inline detour there.
    Function(InlineHookType),
    /// We're just hiding / protecting a page (your repo leaves this unimplemented).
    Page,
}

/// Central hook manager shared across the hypervisor.
///
/// NOTE ON ADDRESSES:
/// - `allocated_memory_ranges` are interpreted as **host physical ranges**
///   (or identity-mapped UEFI pointers from RUNTIME_SERVICES_* allocations).
/// - The EPT code expects host-physical page frame numbers when it swaps pages
///   to the dummy page.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct HookManager {
    pub memory_manager: MemoryManager,
    pub msr_bitmap: MsrBitmap,
    pub dummy_page_pa: u64,
    pub ntoskrnl_base_va: u64,
    pub ntoskrnl_base_pa: u64,
    pub ntoskrnl_size: u64,
    pub has_cpuid_cache_info_been_called: bool,

    /// Catalog of hypervisor-owned physical ranges that *may* be candidates
    /// for EPT hiding. Each entry is `(start_phys, size_bytes)`.
    ///
    /// In the current design, `hide_hv_with_ept` clears this vector and
    /// records only the contiguous `Vm` structure range, then calls
    /// `hide_hypervisor_memory_except` to selectively hide those pages.
    pub allocated_memory_ranges: Vec<(usize, usize)>,
}

lazy_static! {
    pub static ref SHARED_HOOK_MANAGER: Mutex<HookManager> = Mutex::new(HookManager {
        memory_manager: MemoryManager::new(),
        msr_bitmap: MsrBitmap::new(),
        dummy_page_pa: 0,
        ntoskrnl_base_va: 0,
        ntoskrnl_base_pa: 0,
        ntoskrnl_size: 0,
        has_cpuid_cache_info_been_called: false,
        allocated_memory_ranges: Vec::with_capacity(128),
    });
}

impl HookManager {
    /// Called once, early, to set the dummy page and some MSR interception.
    pub fn initialize_shared_hook_manager(dummy_page_pa: u64) {
        let mut hook_manager = SHARED_HOOK_MANAGER.lock();
        hook_manager.dummy_page_pa = dummy_page_pa;

        // Restore the behavior from the article / original project:
        // intercept IA32_LSTAR writes so we can hook the system call entry.
        trace!("Initializing MSR bitmap: intercepting IA32_LSTAR writes for syscall hook");

        hook_manager
            .msr_bitmap
            .modify_msr_interception(msr::IA32_LSTAR, MsrAccessType::Write, MsrOperation::Hook);
    }

    /// Record a hypervisor-owned physical range.
    ///
    /// `start` is treated as a physical address (or identity-mapped pointer),
    /// `size` is in bytes. Any unaligned start/size is handled when we walk
    /// pages in `hide_hypervisor_memory_except`.
    pub fn record_allocation(&mut self, start: usize, size: usize) {
        self.allocated_memory_ranges.push((start, size));
    }

    pub fn print_allocated_memory(&self) {
        for (start, size) in &self.allocated_memory_ranges {
            debug!("Memory Range: start={:#x}, size={:#x}", start, size);
        }
    }

    /// Resolve kernel base/size for later lookups.
    pub fn set_kernel_base_and_size(&mut self, guest_va: u64) -> Result<(), HypervisorError> {
        self.ntoskrnl_base_va = unsafe { get_image_base_address(guest_va)? };
        self.ntoskrnl_base_pa = PhysicalAddress::pa_from_va_with_current_cr3(self.ntoskrnl_base_va)?;
        self.ntoskrnl_size = unsafe { get_size_of_image(self.ntoskrnl_base_pa as _).ok_or(HypervisorError::FailedToGetKernelSize)? } as u64;
        Ok(())
    }

    /// Entry point your VM-exit code calls: enable/disable an EPT hook on a kernel export/SSDT.
    pub fn manage_kernel_ept_hook(
        &mut self,
        vm: &mut Vm,
        function_hash: u32,
        syscall_number: u16,
        ept_hook_type: EptHookType,
        enable: bool,
    ) -> Result<(), HypervisorError> {
        let action = if enable { "Enabling" } else { "Disabling" };
        debug!("{} EPT hook for function: {:#x}", action, function_hash);

        trace!("ntoskrnl va: {:#x}", self.ntoskrnl_base_va);
        trace!("ntoskrnl pa: {:#x}", self.ntoskrnl_base_pa);
        trace!("ntoskrnl size: {:#x}", self.ntoskrnl_size);

        // try export, otherwise SSDT
        let function_va = unsafe {
            if let Some(va) = get_export_by_hash(self.ntoskrnl_base_pa as _, self.ntoskrnl_base_va as _, function_hash) {
                va
            } else {
                let ssdt_function_address =
                    SsdtHook::find_ssdt_function_address(syscall_number as _, false, self.ntoskrnl_base_pa as _, self.ntoskrnl_size as _);
                match ssdt_function_address {
                    Ok(ssdt_hook) => ssdt_hook.guest_function_va as *mut u8,
                    Err(_) => return Err(HypervisorError::FailedToGetExport),
                }
            }
        };

        if enable {
            self.ept_hook_function(vm, function_va as u64, function_hash, ept_hook_type)?;
        } else {
            self.ept_unhook_function(vm, function_va as u64, ept_hook_type)?;
        }

        Ok(())
    }

    /// Legacy helper: hide all recorded hypervisor ranges with no exclusions.
    ///
    /// In the current design, `hide_hv_with_ept` prefers
    /// `hide_hypervisor_memory_except` and passes an explicit exclusion list,
    /// but we keep this for completeness and tests.
    pub fn hide_hypervisor_memory(&mut self, vm: &mut Vm, page_permissions: AccessType) -> Result<(), HypervisorError> {
        self.hide_hypervisor_memory_except(vm, &[], page_permissions)
    }

    /// Hide hypervisor memory EXCEPT for specific page-aligned addresses.
    ///
    /// This walks all `allocated_memory_ranges` and:
    ///   - splits any 2MB pages into 4KB pages as needed
    ///   - swaps each eligible 4KB page to the dummy page with the requested
    ///     EPT permissions
    ///   - *skips* any page that appears in `exclude_pages`
    ///
    /// The actual hardware invalidations (INVEPT/INVVPID) are issued once
    /// at the end for the entire batch, to match the original project's
    /// behavior and avoid performance issues.
    ///
    /// # Arguments
    /// * `vm` - The VM instance
    /// * `exclude_pages` - Slice of page-aligned physical addresses to NOT hide
    /// * `page_permissions` - EPT permissions for hidden pages
    pub fn hide_hypervisor_memory_except(&mut self, vm: &mut Vm, exclude_pages: &[u64], page_permissions: AccessType) -> Result<(), HypervisorError> {
        debug!("Hiding hypervisor memory with {} excluded pages", exclude_pages.len());

        // Collect all pages we want to process.
        let mut pages_to_hide: Vec<u64> = Vec::new();

        for (start, size) in &self.allocated_memory_ranges {
            let start_addr = *start as u64;
            let end_addr = start_addr + *size as u64;

            // Process each 4KB page in this range.
            let mut current_page = start_addr & !0xFFF; // Align to 4KB.
            while current_page < end_addr {
                // Check if this page should be excluded.
                let should_exclude = exclude_pages.iter().any(|&excluded| {
                    let excluded_aligned = excluded & !0xFFF;
                    current_page == excluded_aligned
                });

                if should_exclude {
                    debug!("  Skipping page {:#x} (in exclusion list)", current_page);
                } else {
                    pages_to_hide.push(current_page);
                }

                current_page += 0x1000; // Move to next 4KB page.
            }
        }

        // Avoid duplicate work if ranges overlap.
        pages_to_hide.sort_unstable();
        pages_to_hide.dedup();

        let num_pages = pages_to_hide.len();
        debug!("Hiding {} pages (excluded {} pages)", num_pages, exclude_pages.len());

        // Now hide all non-excluded pages WITHOUT invalidating after each one.
        // We'll do a single invalidation at the end for performance.
        for guest_page_pa in pages_to_hide {
            self.ept_hide_hypervisor_memory_no_invalidate(vm, guest_page_pa, page_permissions)?;
        }

        // Single invalidation at the end for all changes.
        debug!("Invalidating EPT and VPID caches once for all {} pages", num_pages);
        invept_all_contexts();
        invvpid_all_contexts();

        Ok(())
    }

    /// Hide a single hypervisor page WITHOUT invalidating caches.
    /// Use this when hiding multiple pages, then call invalidation once at the end.
    fn ept_hide_hypervisor_memory_no_invalidate(
        &mut self,
        vm: &mut Vm,
        guest_page_pa: u64,
        page_permissions: AccessType,
    ) -> Result<(), HypervisorError> {
        let guest_page_pa = PAddr::from(guest_page_pa).align_down_to_base_page();
        let guest_large_page_pa = guest_page_pa.align_down_to_large_page();
        let dummy_page_pa = self.dummy_page_pa;

        // Make sure we have a split page table for this 2MB region.
        self.memory_manager.map_large_page_to_pt(guest_large_page_pa.as_u64())?;

        let pre_alloc_pt = self
            .memory_manager
            .get_page_table_as_mut(guest_large_page_pa.as_u64())
            .ok_or(HypervisorError::PageTableNotFound)?;

        // If it's still a 2MB large page in the EPT, split it into 4KB entries.
        if vm.primary_ept.is_large_page(guest_page_pa.as_u64()) {
            vm.primary_ept.split_2mb_to_4kb(guest_large_page_pa.as_u64(), pre_alloc_pt)?;
        }

        // Finally, swap this 4KB page to the dummy page with the requested permissions.
        vm.primary_ept
            .swap_page(guest_page_pa.as_u64(), dummy_page_pa, page_permissions, pre_alloc_pt)?;

        // NO invalidation here - caller will do it once for all pages.

        Ok(())
    }

    /// The real EPT function hook install path.
    pub fn ept_hook_function(
        &mut self,
        vm: &mut Vm,
        guest_function_va: u64,
        function_hash: u32,
        ept_hook_type: EptHookType,
    ) -> Result<(), HypervisorError> {
        debug!("Creating EPT hook for function at VA: {:#x}", guest_function_va);

        let guest_function_pa = PAddr::from(PhysicalAddress::pa_from_va_with_current_cr3(guest_function_va)?);
        let guest_page_pa = guest_function_pa.align_down_to_base_page();
        let guest_large_page_pa = guest_function_pa.align_down_to_large_page();

        // 1) map large page into our preallocated PT
        self.memory_manager.map_large_page_to_pt(guest_large_page_pa.as_u64())?;

        // 2) split 2MB into 4KB in primary EPT if needed
        if vm.primary_ept.is_large_page(guest_page_pa.as_u64()) {
            let pre_alloc_pt = self
                .memory_manager
                .get_page_table_as_mut(guest_large_page_pa.as_u64())
                .ok_or(HypervisorError::PageTableNotFound)?;

            vm.primary_ept.split_2mb_to_4kb(guest_large_page_pa.as_u64(), pre_alloc_pt)?;
        }

        // 3) if we never processed this page, set up guest→shadow mapping and copy
        if !self.memory_manager.is_guest_page_processed(guest_page_pa.as_u64()) {
            self.memory_manager.map_guest_to_shadow_page(
                guest_page_pa.as_u64(),
                guest_function_va,
                guest_function_pa.as_u64(),
                ept_hook_type,
                function_hash,
            )?;

            let shadow_page_pa = PAddr::from(
                self.memory_manager
                    .get_shadow_page_as_ptr(guest_page_pa.as_u64())
                    .ok_or(HypervisorError::ShadowPageNotFound)?,
            );

            // copy guest page → shadow page
            Self::unsafe_copy_guest_to_shadow(guest_page_pa, shadow_page_pa);

            // if this is a function hook, install inline hook on the shadow copy
            if let EptHookType::Function(inline_hook_type) = ept_hook_type {
                let shadow_function_pa = PAddr::from(Self::calculate_function_offset_in_host_shadow_page(shadow_page_pa, guest_function_pa));
                InlineHook::new(shadow_function_pa.as_u64() as *mut u8, inline_hook_type).detour64();
            }

            // now point the guest page at the shadow page with RWX
            let pre_alloc_pt = self
                .memory_manager
                .get_page_table_as_mut(guest_large_page_pa.as_u64())
                .ok_or(HypervisorError::PageTableNotFound)?;

            let perms = AccessType::READ | AccessType::WRITE | AccessType::EXECUTE;

            vm.primary_ept
                .swap_page(guest_page_pa.as_u64(), shadow_page_pa.as_u64(), perms, pre_alloc_pt)?;

            invept_all_contexts();
            invvpid_all_contexts();
        } else {
            debug!("Guest page {:#x} already processed, skipping copy", guest_page_pa.as_u64());
        }

        Ok(())
    }

    /// Undo the EPT mapping (restore guest page).
    pub fn ept_unhook_function(&mut self, vm: &mut Vm, guest_function_va: u64, _ept_hook_type: EptHookType) -> Result<(), HypervisorError> {
        let guest_function_pa = PAddr::from(PhysicalAddress::pa_from_va_with_current_cr3(guest_function_va)?);
        let guest_page_pa = guest_function_pa.align_down_to_base_page();
        let guest_large_page_pa = guest_function_pa.align_down_to_large_page();

        self.memory_manager.map_large_page_to_pt(guest_large_page_pa.as_u64())?;

        let pre_alloc_pt = self
            .memory_manager
            .get_page_table_as_mut(guest_large_page_pa.as_u64())
            .ok_or(HypervisorError::PageTableNotFound)?;

        let perms = AccessType::READ | AccessType::WRITE | AccessType::EXECUTE;

        vm.primary_ept
            .swap_page(guest_page_pa.as_u64(), guest_page_pa.as_u64(), perms, pre_alloc_pt)?;

        invept_all_contexts();
        invvpid_all_contexts();

        Ok(())
    }

    /// Raw copy helper: guest page → shadow page.
    fn unsafe_copy_guest_to_shadow(guest_page_pa: PAddr, shadow_page_pa: PAddr) {
        unsafe {
            let src = guest_page_pa.as_u64() as *const u8;
            let dst = shadow_page_pa.as_u64() as *mut u8;
            copy_nonoverlapping(src, dst, BASE_PAGE_SIZE as usize);
        }
    }

    /// Keep the same offset inside the 4KB page as the original guest PA.
    fn calculate_function_offset_in_host_shadow_page(shadow_page_pa: PAddr, guest_function_pa: PAddr) -> u64 {
        let offset_in_page = guest_function_pa.as_u64() & (BASE_PAGE_SIZE as u64 - 1);
        shadow_page_pa.as_u64() + offset_in_page
    }

    // -------------------------------------------------------------------------
    // These two are ONLY here because your hypervisor/src/intel/vmexit/vmcall.rs
    // calls them as associated fns.
    // -------------------------------------------------------------------------

    pub fn hook_size(ept_hook_type: EptHookType) -> usize {
        match ept_hook_type {
            EptHookType::Function(_) => 0x10,
            EptHookType::Page => BASE_PAGE_SIZE as usize,
        }
    }

    pub fn calculate_instruction_count(_guest_function_pa: u64, hook_size: usize) -> usize {
        hook_size
    }
}
