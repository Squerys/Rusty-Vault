// ===============================
// IMPORTS
// ===============================

use std::ptr::{null_mut};

#[cfg(windows)]
use windows_sys::Win32::{
    System::{
        Diagnostics::Debug::{IsDebuggerPresent, CheckRemoteDebuggerPresent},
        Threading::{GetCurrentProcess, GetCurrentProcessId},
        LibraryLoader::{LoadLibraryA, GetProcAddress},
        Memory::{GetProcessHeap, HeapWalk, PROCESS_HEAP_ENTRY, PROCESS_HEAP_ENTRY_BUSY},
    },
    Foundation::{HMODULE},
};

// ===============================
// NT TYPES
// ===============================

type NTSTATUS = i32;

const PROCESS_DEBUG_PORT: u32 = 7;
const PROCESS_DEBUG_FLAGS: u32 = 0x1f;

#[inline]
fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

// ===============================
// NtQueryInformationProcess
// ===============================

#[cfg(windows)]
pub fn nt_query_information_process() -> bool 
{
    let mut corrupted_mode = false;

    unsafe 
    {
        let h_ntdll: HMODULE = LoadLibraryA(b"ntdll.dll\0".as_ptr());

        if h_ntdll != 0 
        {
            let func = GetProcAddress(h_ntdll, b"NtQueryInformationProcess\0".as_ptr());

            if !func.is_null() 
            {
                let nt_query: extern "system" fn(isize,u32,*mut u32,u32,*mut u32,) -> NTSTATUS = std::mem::transmute(func);

                let mut debug_port: u32 = 0;
                let mut returned: u32 = 0;

                let status = nt_query(GetCurrentProcess(),PROCESS_DEBUG_PORT,&mut debug_port,std::mem::size_of::<u32>() as u32,&mut returned);

                if nt_success(status) && debug_port == u32::MAX {
                    corrupted_mode = true;
                }

                let mut debug_flags: u32 = 0;

                let status = nt_query(GetCurrentProcess(),PROCESS_DEBUG_FLAGS,&mut debug_flags,std::mem::size_of::<u32>() as u32,&mut returned);

                if nt_success(status) && debug_flags == 0 
                {
                    corrupted_mode = true;
                }
            }
        }
    }

    corrupted_mode
}

// ===============================
// HEAP CHECK
// ===============================

#[cfg(windows)]
pub fn heap_entry_check() -> bool 
{
    unsafe 
    {
        let mut entry: PROCESS_HEAP_ENTRY = std::mem::zeroed();

        while HeapWalk(GetProcessHeap(), &mut entry) != 0
        {
            if entry.wFlags == PROCESS_HEAP_ENTRY_BUSY
            {
                return true;
            }
        }
    }

    false
}

// ===============================
// Linux ajout 
// ===============================
//




// ===============================
// KUSER_SHARED_DATA CHECK
// ===============================

#[cfg(windows)]
pub fn check_kuser_shared_data_structure() -> bool
{
    unsafe 
    {
        let ptr = 0x7ffe02d4 as *const u8;
        let b = *ptr;
        (b & 0x01 != 0) || (b & 0x02 != 0)
    }
}

// ===============================
// MAIN DEBUGGER CHECK
// ===============================

#[cfg(windows)]
pub fn debugger_check() -> bool 
{
    let mut corrupted_mode = false;

    unsafe 
    {
        if IsDebuggerPresent() != 0 
        {
            corrupted_mode = true;
        }

        let mut remote_debugger: i32 = 0;

        if CheckRemoteDebuggerPresent(GetCurrentProcess(),&mut remote_debugger) != 0 && remote_debugger != 0
        {
            corrupted_mode = true;
        }
    }

    if nt_query_information_process() 
    {
        corrupted_mode = true;
    }

    if heap_entry_check() 
    {
        corrupted_mode = true;
    }

    if check_kuser_shared_data_structure() 
    {
        corrupted_mode = true;
    }

    corrupted_mode
}

// ===============================
// CHECK
// ===============================

#[cfg(windows)]
pub fn check() -> bool
{
    debugger_check()
}

#[cfg(not(windows))]
pub fn check() -> bool
{
    false
}
