use std::process::Command;
use std::path::{Path, PathBuf};
use std::{fs, env};

pub fn build_stub(target_triple: &str, build_command: &str) -> std::process::ExitStatus {
    let status = Command::new("cargo")
        .args(&[
            build_command,
            "--release",
            "--package", "stub",
            "--target", target_triple
        ])
        .status()
        .expect("Failed to run cargo build");

    if status.success() {
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
