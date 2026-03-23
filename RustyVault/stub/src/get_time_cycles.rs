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

// Wrapper Helper
pub unsafe fn get_time_cycles() -> u64 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    { std::arch::x86_64::_rdtsc() }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    { 0 }
}
