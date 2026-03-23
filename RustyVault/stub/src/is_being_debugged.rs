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

pub fn is_being_debugged() -> bool {
    #[cfg(target_os = "linux")]
    unsafe { if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) < 0 { return true; } }
    #[cfg(target_os = "windows")]
    unsafe { if winapi::um::debugapi::IsDebuggerPresent() != 0 { return true; } }
    false
}