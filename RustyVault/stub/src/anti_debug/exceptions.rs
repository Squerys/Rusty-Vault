// ===============================
// WINDOWS IMPORTS
// ===============================

#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::{
    SetUnhandledExceptionFilter,
    RaiseException,
    AddVectoredExceptionHandler,
    RemoveVectoredExceptionHandler,
    EXCEPTION_POINTERS
};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    EXCEPTION_CONTINUE_EXECUTION,
};

#[cfg(windows)]
use windows_sys::Win32::System::Threading::ExitProcess;

// ===============================
// LINUX IMPORTS
// ===============================

#[cfg(target_os = "linux")]
use libc::{sigaction, siginfo_t, SIGTRAP, SA_SIGINFO};

// ===============================
// VARIABLES
// ===============================   
#[cfg(target_os = "linux")]
static mut LINUX_SIGNAL_RECEIVED: bool = false;

#[cfg(windows)]
static mut LAST_VEH: *mut core::ffi::c_void = core::ptr::null_mut();

// ===============================
// EXCEPTION FILTER
// ===============================

#[cfg(windows)]
unsafe extern "system" fn unhandled_exception_filter(exception_info: *mut EXCEPTION_POINTERS) -> i32
{
    if !exception_info.is_null()
    {
        let ctx = (*exception_info).ContextRecord;

        if !ctx.is_null()
        {
            #[cfg(target_arch = "x86")]
            {
                (*ctx).Eip += 3;
            }

            #[cfg(target_arch = "x86_64")]
            {
                (*ctx).Rip += 1;
            }
        }
    }

    EXCEPTION_CONTINUE_EXECUTION
}

#[cfg(windows)]
fn unhandled_exception_check() -> bool
{
    let mut debugged = true;

    unsafe
    {
        SetUnhandledExceptionFilter(Some(unhandled_exception_filter));

        core::arch::asm!("int3");
    }

    debugged = false;

    debugged
}


// ===============================
// RAISE EXCEPTION CHECK
// ===============================

#[cfg(windows)]
unsafe extern "system" fn check_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    EXCEPTION_HIT = true;
    
    let ctx = (*info).ContextRecord;
    (*ctx).Rip += 1; 

    EXCEPTION_CONTINUE_EXECUTION
}

#[cfg(windows)]
fn raise_exception_check() -> bool {
    unsafe {
        EXCEPTION_HIT = false;
        
        let handle = AddVectoredExceptionHandler(1, Some(check_handler));
        
        if !handle.is_null() {
            core::arch::asm!("int3");
            
        }

        !EXCEPTION_HIT
    }
}

// ===============================
// VECTORED EXCEPTION HANDLERS
// ===============================
#[cfg(windows)]
unsafe extern "system" fn exception_handler2(info: *mut EXCEPTION_POINTERS) -> i32 {
    EXCEPTION_HIT = true; 
    let ctx = (*info).ContextRecord;
    (*ctx).Rip += 1; 
    EXCEPTION_CONTINUE_EXECUTION
}

#[cfg(windows)]
unsafe extern "system" fn exception_handler1(info: *mut EXCEPTION_POINTERS) -> i32 {
    if !LAST_VEH.is_null() {
        LAST_VEH = AddVectoredExceptionHandler(1, Some(exception_handler2));
        
        let ctx = (*info).ContextRecord;
        (*ctx).Rip += 1; // On répare le premier int3
        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn linux_sig_handler(_sig: i32, _info: *mut siginfo_t, ucontext: *mut libc::c_void) {
    let context = ucontext as *mut libc::ucontext_t;
    
    #[cfg(target_arch = "x86_64")]
    {
        (*context).uc_mcontext.gregs[libc::REG_RIP as usize] += 1;
    }
    
    LINUX_SIGNAL_RECEIVED = true;
}

// ===============================
// MAIN CHECK
// ===============================

pub fn exception_check() -> bool
{
    let mut corrupted_mode = false;
    
    #[cfg(target_os = "linux")]
    unsafe {
        LINUX_SIGNAL_RECEIVED = false;

        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = linux_sig_handler as usize;
        sa.sa_flags = SA_SIGINFO;

        libc::sigaction(SIGTRAP, &sa, std::ptr::null_mut());

        core::arch::asm!("int3");

        corrupted_mode = !LINUX_SIGNAL_RECEIVED;
    }

    #[cfg(windows)]
    if raise_exception_check()
    {
        corrupted_mode = true;
    }

    #[cfg(windows)]
    if !unhandled_exception_check()
    {
        corrupted_mode = true;
    }

    #[cfg(windows)]
    if veh_chain_check()
    {
        corrupted_mode = true;
    }

    corrupted_mode
}


pub fn check() -> bool
{
    exception_check()
}
