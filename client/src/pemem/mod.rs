#![allow(dead_code)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(non_snake_case)]

extern crate alloc;

use {
    alloc::vec::Vec,
    core::{arch::asm, mem::size_of, slice::from_raw_parts},
    ntapi::{
        ntldr::LDR_DATA_TABLE_ENTRY,
        ntpebteb::{PEB, TEB},
    },
    std::{collections::BTreeMap, ffi::CStr},
    windows_sys::Win32::System::{
        Diagnostics::Debug::{
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
        },
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        SystemServices::{
            IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
            IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG64,
        },
    },
};

pub const HASH_NTDLL: u32 = 0x1edab0ed;
pub const HASH_KERNEL32: u32 = 0x6a4abc5b;
pub const HASH_KERNELBASE: u32 = 0x2c2234fd;
pub const HASH_KERNELEX: u32 = 0x06a27f5b;
pub const HASH_USER32: u32 = 0x14ba6b9b;
pub const HASH_ADVAPI32: u32 = 0x3ab7955f;
pub const HASH_SECHOST: u32 = 0x12e2b53f;
pub const HASH_SHLWAPI: u32 = 0x4b3b8a1f;
pub const HASH_SHELL32: u32 = 0x5060f1f5;
pub const HASH_WINSPOOLDRV: u32 = 0x78f9c405;
pub const HASH_COMDLG32: u32 = 0x38c543b5;

#[repr(C)]
pub struct IMAGE_THUNK_DATA64 {
    pub u1: IMAGE_THUNK_DATA64_u,
}

#[repr(C)]
pub union IMAGE_THUNK_DATA64_u {
    pub ForwarderString: u64,
    pub Function: u64,
    pub Ordinal: u64,
    pub AddressOfData: u64,
}

#[repr(C)]
pub struct IMAGE_IMPORT_BY_NAME_WRAPPER {
    pub Hint: u16,
    pub Name: [u8; 1],
}

pub unsafe fn get_dos_header(module_base: *mut u8) -> Option<*mut IMAGE_DOS_HEADER> {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    Some(dos_header)
}

pub unsafe fn get_nt_headers(module_base: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64> {
    let dos_header = get_dos_header(module_base)?;
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
        return None;
    }
    Some(nt_headers)
}

pub unsafe fn copy_headers(module_base: *mut u8, new_module_base: *mut u8) -> Option<()> {
    let nt_headers = get_nt_headers(module_base)?;

    for i in 0..(*nt_headers).OptionalHeader.SizeOfHeaders {
        new_module_base.cast::<u8>().add(i as usize).write(module_base.add(i as usize).read());
    }

    Some(())
}

pub unsafe fn copy_sections(module_base: *mut u8, new_module_base: *mut u8) -> Option<()> {
    let nt_headers = get_nt_headers(module_base)?;

    let section_header =
        (&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize) as *mut IMAGE_SECTION_HEADER;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections {
        let section_header_i = &*(section_header.add(i as usize));
        let destination = new_module_base.cast::<u8>().add(section_header_i.VirtualAddress as usize);

        let source = module_base.cast::<u8>().add(section_header_i.PointerToRawData as usize);

        let size = section_header_i.SizeOfRawData as usize;

        let source_data = from_raw_parts(source, size);

        for (x, src_data) in source_data.iter().enumerate() {
            let dest_data = destination.add(x);
            *dest_data = *src_data;
        }
    }

    Some(())
}

pub unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

pub unsafe fn get_peb() -> *mut PEB {
    let teb = get_teb();
    let peb = (*teb).ProcessEnvironmentBlock;
    peb
}

pub unsafe fn get_loaded_module_by_hash(module_hash: u32) -> Option<*mut u8> {
    let peb = get_peb();
    let peb_ldr_data_ptr = (*peb).Ldr;
    let mut module_list = (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !(*module_list).DllBase.is_null() {
        let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
        let dll_length = (*module_list).BaseDllName.Length as usize;
        let dll_name_slice = from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_hash == djb2_hash(dll_name_slice) {
            return Some((*module_list).DllBase as _);
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    None
}

pub unsafe fn get_section_header_by_hash(module_base: *mut u8, section_hash: u32) -> Option<*mut IMAGE_SECTION_HEADER> {
    let nt_headers = get_nt_headers(module_base)?;

    let section_header =
        (&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize) as *mut IMAGE_SECTION_HEADER;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections as usize {
        let section_name = (*section_header.add(i)).Name;
        let hash = djb2_hash(&section_name);
        if hash == section_hash {
            return Some(section_header.add(i));
        }
    }

    None
}

pub unsafe fn get_export_by_hash(module_base: *mut u8, export_hash: u32) -> Option<*mut u8> {
    let nt_headers = get_nt_headers(module_base)?;

    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize)
        as *mut IMAGE_EXPORT_DIRECTORY;

    let names =
        from_raw_parts((module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32, (*export_directory).NumberOfNames as _);
    let functions = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    let ordinals = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;
        let name_len = get_cstr_len(name_addr as _);
        let name_slice: &[u8] = from_raw_parts(name_addr as _, name_len);
        if djb2_hash(name_slice) == export_hash {
            let fn_rva = functions[ordinals[i as usize] as usize] as usize;
            return Some(module_base.add(fn_rva));
        }
    }

    None
}

pub unsafe fn get_exports_by_name(module_base: *mut u8) -> Option<BTreeMap<String, usize>> {
    let nt_headers = get_nt_headers(module_base)?;

    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize)
        as *mut IMAGE_EXPORT_DIRECTORY;

    let names =
        from_raw_parts((module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32, (*export_directory).NumberOfNames as _);
    let functions = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    let ordinals = from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    let mut map = BTreeMap::new();

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;
        let _name_len = get_cstr_len(name_addr as _);

        if let Ok(name) = CStr::from_ptr(name_addr).to_str() {
            let fn_rva = functions[ordinals[i as usize] as usize] as usize;
            map.insert(name.to_string(), fn_rva);
        }
    }

    Some(map)
}

pub unsafe fn rebase_image(module_base: *mut u8) -> Option<bool> {
    let nt_headers = get_nt_headers(module_base)?;

    let delta = module_base as isize - (*nt_headers).OptionalHeader.ImageBase as isize;

    if delta == 0 {
        return Some(true);
    }

    let base_relocation = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize)
        as *mut IMAGE_BASE_RELOCATION;

    let base_relocation_end =
        base_relocation as usize + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size as usize;

    let mut base_relocation = base_relocation;

    while (*base_relocation).VirtualAddress != 0u32
        && (*base_relocation).VirtualAddress as usize <= base_relocation_end
        && (*base_relocation).SizeOfBlock != 0u32
    {
        let address = (module_base as usize + (*base_relocation).VirtualAddress as usize) as isize;

        let item = (base_relocation as usize + size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;

        let count = ((*base_relocation).SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>();

        for i in 0..count {
            let type_field = (item.offset(i as isize).read() >> 12) as u32;
            let offset = item.offset(i as isize).read() & 0xFFF;

            if type_field == 0xA {
                *((address + offset as isize) as *mut isize) += delta;
            }
        }

        base_relocation = (base_relocation as usize + (*base_relocation).SizeOfBlock as usize) as *mut IMAGE_BASE_RELOCATION;
    }

    Some(true)
}

pub unsafe fn resolve_imports(module_base: *mut u8) -> Option<bool> {
    let nt_headers = get_nt_headers(module_base)?;
    // Get a pointer to the first _IMAGE_IMPORT_DESCRIPTOR
    let mut import_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize)
        as *mut IMAGE_IMPORT_DESCRIPTOR;

    if import_directory.is_null() {
        return Some(false);
    }

    while (*import_directory).Name != 0x0 {
        // Get the name of the dll in the current _IMAGE_IMPORT_DESCRIPTOR
        let dll_name = (module_base as usize + (*import_directory).Name as usize) as *const u8;
        // Load the DLL in the address space of the process
        let dll_handle = LoadLibraryA(dll_name);

        if dll_handle.is_null() {
            return None;
        }

        // Get a pointer to the Original Thunk or First Thunk via FirstThunk
        let mut original_thunk = if (module_base as usize + (*import_directory).FirstThunk as usize) != 0 {
            let orig_thunk = (module_base as usize + (*import_directory).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;
            orig_thunk
        } else {
            let thunk = (module_base as usize + (*import_directory).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;
            thunk
        };

        let mut thunk = (module_base as usize + (*import_directory).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;

        while (*original_thunk).u1.Function != 0 {
            // #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
            let snap_result = (*original_thunk).u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0;

            if snap_result {
                // #define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
                let fn_ordinal = ((*original_thunk).u1.Ordinal & 0xffff) as _;
                // Retrieve the address of the exported function by ordinal
                (*thunk).u1.Function = GetProcAddress(dll_handle, fn_ordinal)? as _;
            } else {
                // Get a pointer to _IMAGE_IMPORT_BY_NAME
                let thunk_data = (module_base as usize + (*original_thunk).u1.AddressOfData as usize) as *mut IMAGE_IMPORT_BY_NAME;
                // Get a pointer to the function name in the IMAGE_IMPORT_BY_NAME
                let fn_name = (*thunk_data).Name.as_ptr() as *const u8;
                // Retrieve the address of the exported function by name
                (*thunk).u1.Function = GetProcAddress(dll_handle, fn_name)? as _;
            }

            // Increment and get a pointer to the next Thunk and Original Thunk
            thunk = thunk.add(1);
            original_thunk = original_thunk.add(1);
        }

        // Increment and get a pointer to the next _IMAGE_IMPORT_DESCRIPTOR
        import_directory = (import_directory as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>()) as _;
    }

    Some(true)
}

/// Generate a unique hash (classic djb2)
pub fn djb2_hash(buffer: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &ch in buffer {
        let ch = ch.to_ascii_lowercase();
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(ch as u32);
    }
    hash
}

pub fn get_bytes_as_hex(pattern: &str) -> Result<Vec<Option<u8>>, ()> {
    let mut pattern_bytes = Vec::new();

    for x in pattern.split_whitespace() {
        match x {
            "?" => pattern_bytes.push(None),
            _ => pattern_bytes.push(u8::from_str_radix(x, 16).map(Some).map_err(|_| ())?),
        }
    }

    Ok(pattern_bytes)
}

/// Pattern or Signature scan a region of memory
pub fn pattern_scan(data: &[u8], pattern: &str) -> Result<Option<usize>, ()> {
    let pattern_bytes = get_bytes_as_hex(pattern)?;

    for i in 0..data.len() - pattern_bytes.len() {
        let mut match_found = true;
        for (j, b) in pattern_bytes.iter().enumerate() {
            if let Some(b) = b {
                if data[i + j] != *b {
                    match_found = false;
                    break;
                }
            }
        }
        if match_found {
            return Ok(Some(i));
        }
    }

    Ok(None)
}

pub unsafe fn get_cstr_len(pointer: *const u8) -> usize {
    let mut len: usize = 0;
    let mut tmp = pointer;
    while *(tmp as *const u8) != 0 {
        len += 1;
        tmp = tmp.add(1);
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let x = b"ntdll.dll";
        let _ = djb2_hash(x);
    }
}
