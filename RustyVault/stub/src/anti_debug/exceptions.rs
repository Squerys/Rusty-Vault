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
                (*ctx).Rip += 3;
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
fn raise_exception_check() -> bool
{
    let mut corrupted_mode = false;

    unsafe
    {
        let result = std::panic::catch_unwind(|| {
            RaiseException(0x40010005, 0, 0, core::ptr::null());
        });

        if result.is_err()
        {
            corrupted_mode = true;
        }
    }

    corrupted_mode
}


// ===============================
// VECTORED EXCEPTION HANDLERS
// ===============================

#[cfg(windows)]
unsafe extern "system" fn exception_handler2(_: *mut EXCEPTION_POINTERS) -> i32
{
    ExitProcess(0);
}

#[cfg(windows)]
unsafe extern "system" fn exception_handler1( _: *mut EXCEPTION_POINTERS) -> i32
{
    if !LAST_VEH.is_null()
    {
        RemoveVectoredExceptionHandler(LAST_VEH);

        LAST_VEH = AddVectoredExceptionHandler(1,Some(exception_handler2));

        if !LAST_VEH.is_null()
        {
            core::arch::asm!("int3");
        }
    }

    ExitProcess(0);
}

#[cfg(windows)]
fn veh_chain_check() -> bool
{
    unsafe
    {
        LAST_VEH = AddVectoredExceptionHandler(1,Some(exception_handler1));

        if !LAST_VEH.is_null()
        {
            core::arch::asm!("int3");
        }
    }

    false
}


// ===============================
// MAIN CHECK
// ===============================

pub fn exception_check() -> bool
{
    let mut corrupted_mode = false;

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
