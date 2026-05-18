use std::process::Command;
use std::path::{Path, PathBuf};
use std::{fs, env};

pub fn build_stub(target_triple: &str, build_command: &str) -> std::process::ExitStatus {
    let mut cmd = Command::new("cargo");

    #[cfg(target_os = "windows")]
    cmd.arg("+nightly-2024-06-26");

    cmd.arg(build_command);

    cmd.args(&[
        "--release",
        "--package", "stub",
        "--target", target_triple,
    ]);

    #[cfg(target_os = "windows")]
    if target_triple.contains("windows") {
        let current_dir = env::current_dir().expect("Impossible de lire le répertoire courant");
        let plugin_path = current_dir.join("ollvm.dll");
        
        if !plugin_path.exists() {
            eprintln!("ollvm.dll est introuvable au chemin : {:?}", plugin_path);
        }

        let plugin_path_str = plugin_path.to_string_lossy();
        let passes = "irobf(irobf-cff,irobf-indbr,irobf-icall,irobf-indgv)";
        let rust_flags = format!("-Zllvm-plugins={} -Cpasses={}", plugin_path_str, passes);
        
        cmd.env("RUSTFLAGS", rust_flags);
        println!("Obfuscation LLVM activée (Cible Windows) avec : {}", plugin_path_str);
    } else {
        println!("Cible Linux détectée : Obfuscation LLVM désactivée (Feature Windows Only pour le moment).");
    }

    println!("--- Compilation du Stub ---");
    println!("Target Triple : {}", target_triple);

    let status = cmd.status().expect("Erreur lors de l'exécution de cargo");

    if status.success() {
        println!("Stub compilé avec succès.");
        
        let executable_name = if target_triple.contains("windows") { "stub.exe" } else { "stub" };
        
        let internal_path = PathBuf::from("target")
            .join(target_triple)
            .join("release")
            .join(executable_name);
            
        if internal_path.exists() {
            fs::copy(&internal_path, executable_name).ok();
        }
    }

    status
}

pub fn get_stub_path(_target_triple: &str, executable_name: &str) -> PathBuf {
    PathBuf::from(executable_name)
}