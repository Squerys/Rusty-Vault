use std::fs::File;
use std::io::Read;
use std::process::exit;

pub enum TargetType {
    Windows,
    Linux,
}

pub fn detect_file_type(path: &str) -> TargetType {
    let mut file = File::open(path).expect("Fichier introuvable");
    let mut buffer = [0u8; 4];
    if file.read_exact(&mut buffer).is_err() {
        println!("Fichier illisible.");
        exit(1);
    }
    if buffer[0] == 0x4D && buffer[1] == 0x5A { return TargetType::Windows; }
    if buffer[0] == 0x7F && buffer[1] == 0x45 && buffer[2] == 0x4C && buffer[3] == 0x46 { return TargetType::Linux; }
    println!("Format inconnu. Ni PE, ni ELF.");
    exit(1);
}
