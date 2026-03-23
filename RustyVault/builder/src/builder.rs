use std::process::Command;
use std::path::PathBuf;

pub fn build_stub(target_triple: &str, build_command: &str) -> std::process::ExitStatus {
    Command::new("cargo")
        .args(&[
            build_command,
            "--release",
            "--package", "stub",
            "--target", target_triple
        ])
        .status()
        .expect("Failed to run cargo build")
}

pub fn get_stub_path(target_triple: &str, executable_name: &str) -> PathBuf {
    PathBuf::from("target")
        .join(target_triple)
        .join("release")
        .join(executable_name)
}
