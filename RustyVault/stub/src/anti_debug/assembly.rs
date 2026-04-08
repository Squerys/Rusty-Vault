use std::panic;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS
};

// --- HANDLER WINDOWS (Interne) ---
#[cfg(target_os = "windows")]
unsafe extern "system" fn internal_veh_handler(_: *mut EXCEPTION_POINTERS) -> i32 {
    -1 
}


// ===============================
// INT 2D 
// ===============================
#[inline(never)]
pub fn int2D() -> bool {
    let mut corrupted_mode = false;

    #[cfg(target_os = "windows")]
    unsafe {
        let handle = AddVectoredExceptionHandler(1, Some(internal_veh_handler));
        
        let result = panic::catch_unwind(|| {
            core::arch::asm!(
                "xor eax, eax",
                "int 0x2d",
                "nop",
                out("eax") _,
            );
        });

        corrupted_mode = result.is_ok();
        RemoveVectoredExceptionHandler(handle);
    }

    corrupted_mode
}


// ===============================
// INT 3
// ===============================
#[inline(never)]
pub fn int3() -> bool {
    let mut corrupted_mode = false;

    #[cfg(target_os = "windows")]
    unsafe {
        let handle = AddVectoredExceptionHandler(1, Some(internal_veh_handler));

        let result = panic::catch_unwind(|| {
            core::arch::asm!("int 3");
        });

        corrupted_mode = result.is_ok();

        RemoveVectoredExceptionHandler(handle);
    }

    #[cfg(target_os = "linux")]
    unsafe {
        if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) < 0 {
            corrupted_mode = true;
        }
    }
    corrupted_mode
}

// ===============================
// ICE / INT 1 (Single Step)
// ===============================
#[inline(never)]
pub fn ice() -> bool {
    let mut corrupted_mode = false;

    #[cfg(all(target_os = "windows", any(target_arch = "x86", target_arch = "x86_64")))]
    unsafe {
        let handle = AddVectoredExceptionHandler(1, Some(internal_veh_handler));
        
        let result = panic::catch_unwind(|| {
            core::arch::asm!(".byte 0xf1"); // Instruction ICE
        });

        corrupted_mode = result.is_ok();
        RemoveVectoredExceptionHandler(handle);
    }

    corrupted_mode
}


// ===============================
// CHECK
// ===============================
pub fn assembly_check() -> bool
{
    let mut corrupted_mode = false;
    if int3()
    {
        corrupted_mode = true;
    }

    if int2D()
    {
        corrupted_mode = true;
    }

    //if _debug_break()
    //{
    //    corrupted_mode = true;
    //}

    if ice()
    {
        corrupted_mode = true;
    }

    corrupted_mode

}


pub fn check() -> bool {
    assembly_check()
}
