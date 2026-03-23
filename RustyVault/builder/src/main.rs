mod detector;
mod builder;
mod packer;
mod constants;

use std::env;
use std::process::exit;

use detector::{detect_file_type, TargetType};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: rustyvault <payload_path>");
        exit(1);
    }
    let payload_path = &args[1];
    println!("Analyse du payload : {}", payload_path);

    let target_type = detect_file_type(payload_path);

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

    let status = builder::build_stub(target_triple, build_command);

    if !status.success() {
        println!("Erreur de compilation !");
        if build_command == "zigbuild" {
            println!("Vérifiez que zig est installé et accessible :");
            println!("  > zig version");
            println!("  > cargo install cargo-zigbuild");
        }
        exit(1);
    }

    let stub_path = builder::get_stub_path(target_triple, executable_name);

    if !stub_path.exists() {
        println!("Stub introuvable : {:?}", stub_path);
        exit(1);
    }

    packer::pack(payload_path, &stub_path, ext);
}
