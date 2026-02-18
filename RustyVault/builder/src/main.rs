use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::process::{Command, exit};
use std::path::{Path, PathBuf};

// MAGIC DELIMITER
const MAGIC_DELIMITER: &[u8] = &[
    0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0x11
];

const XOR_KEY: u8 = 0x55;

enum TargetType {
    Windows,
    Linux,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: rustyvault <payload_path>");
        exit(1);
    }
    let payload_path = &args[1];
    println!("Analyse du payload : {}", payload_path);
    // 1. DÉTECTION
    let target_type = detect_file_type(payload_path);
    // 2. CONFIGURATION DE LA CIBLE
    let (target_triple, executable_name, ext, build_command) = match target_type {
        TargetType::Windows => {
            println!("   -> Détecté : Exécutable Windows (PE)");
            ("x86_64-pc-windows-msvc", "stub.exe", "exe", "build")
        },
        TargetType::Linux => {
            println!("   -> Détecté : Exécutable Linux (ELF)");
            ("x86_64-unknown-linux-gnu", "stub", "bin", "zigbuild")
        },
    };
    println!("Compilation ({}) avec {}...", target_triple, build_command);
    // 3. COMPILATION
    let status = Command::new("cargo")
        .args(&[
            build_command, // <--- zigbuild si Linux
            "--release", 
            "--package", "stub",
            "--target", target_triple
        ])
        .status()
        .expect("Failed to run cargo build");
    if !status.success() {
        println!("Erreur de compilation !");
        if build_command == "zigbuild" {
            println!("Vérifiez que zig est installé et accessible :");
            println!("  > zig version");
            println!("  > cargo install cargo-zigbuild");
        }
        exit(1);
    }
    // 4. RÉCUPÉRATION DU STUB
    let stub_path = PathBuf::from("target")
        .join(target_triple)
        .join("release")
        .join(executable_name);
    if !stub_path.exists() {
        println!("Stub introuvable : {:?}", stub_path);
        exit(1);
    }
    // 5. PACKING
    println!("Packing en cours...");
    let payload_data = fs::read(payload_path).expect("Impossible de lire le payload");
    let encrypted: Vec<u8> = payload_data.iter().map(|&b| b ^ XOR_KEY).collect();
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
    final_file.write_all(&encrypted).unwrap();
    println!("SUCCÈS ! Fichier généré : {}", output_name);
}

fn detect_file_type(path: &str) -> TargetType {
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
