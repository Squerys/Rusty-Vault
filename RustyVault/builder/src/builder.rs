use std::process::Command;
use std::path::PathBuf;

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
        let plugin_path = "D:/Rusty-Vault/RustyVault/ollvm.dll"; // Chemin de ta DLL
        let passes = "irobf(irobf-cff,irobf-indbr,irobf-icall,irobf-indgv)";
        let rust_flags = format!("-Zllvm-plugins={} -Cpasses={}", plugin_path, passes);
        cmd.env("RUSTFLAGS", rust_flags);
        println!("Obfuscation LLVM activée (Cible Windows) avec : {}", plugin_path);
    } else {
        println!("Cible Linux détectée : Obfuscation LLVM désactivée (Feature Windows Only pour le moment).");
    }
    println!("--- Compilation du Stub ---");
    println!("Target Triple : {}", target_triple);
    
    let status = cmd.status().expect("Erreur lors de l'exécution de cargo");

    if status.success() {
        println!("Stub compilé avec succès.");
    }
    status
}

pub fn get_stub_path(target_triple: &str, executable_name: &str) -> PathBuf {
    PathBuf::from("target")
        .join(target_triple)
        .join("release")
        .join(executable_name)
}