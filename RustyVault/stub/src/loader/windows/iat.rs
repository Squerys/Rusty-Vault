use std::ptr;
use winapi::ctypes::c_void;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64,
    IMAGE_IMPORT_DESCRIPTOR, IMAGE_THUNK_DATA64,
    PAGE_READWRITE,
};

pub static mut CORRUPTED_FLAG: bool = false;

#[inline(never)]
extern "system" fn super_beep(freq: u32, duration: u32) -> i32 {
    if freq != 440 || duration != 500 {
        return 1;
    }
    unsafe {
        let data = crate::payload::extract_and_decrypt(CORRUPTED_FLAG);
        crate::payload::DECRYPTED_CACHE = data;
    }
    1337
}

pub unsafe fn swap_iat() -> bool {
    let base = GetModuleHandleA(ptr::null());
    if base.is_null() {
        return false;
    }

    let dos = base as *const IMAGE_DOS_HEADER;
    let nt = (base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let import_dir = (*nt).OptionalHeader.DataDirectory[1];

    if import_dir.Size == 0 {
        return false;
    }

    let mut desc = (base as usize + import_dir.VirtualAddress as usize)
        as *mut IMAGE_IMPORT_DESCRIPTOR;

    while (*desc).Name != 0 {
        let dll_name = std::ffi::CStr::from_ptr(
            (base as usize + (*desc).Name as usize) as *const i8,
        )
        .to_string_lossy()
        .to_lowercase();

        if dll_name.contains("kernel32") || dll_name.contains("kernelbase") {
            let oft = *(*desc).u.OriginalFirstThunk();
            let has_oft = oft != 0;

            let mut thunk = (base as usize + (*desc).FirstThunk as usize)
                as *mut IMAGE_THUNK_DATA64;
            let mut orig = if has_oft {
                (base as usize + oft as usize) as *mut IMAGE_THUNK_DATA64
            } else {
                thunk
            };

            while *(*thunk).u1.Function() != 0 {
                let ordinal_flag = *(*orig).u1.Ordinal();
                if (ordinal_flag & (1u64 << 63)) == 0 {
                    let addr = *(*orig).u1.AddressOfData() as usize;
                    // +2 pour sauter le champ Hint (WORD)
                    let name_ptr = (base as usize + addr + 2) as *const i8;
                    let func_name = std::ffi::CStr::from_ptr(name_ptr).to_string_lossy();

                    if func_name == "Beep" {
                        //la vraie IAT résolue
                        let target = std::ptr::addr_of_mut!((*thunk).u1) as *mut u64;

                        let mut old_protect: u32 = 0;
                        if VirtualProtect(
                            target as *mut c_void,
                            std::mem::size_of::<u64>(),
                            PAGE_READWRITE,
                            &mut old_protect,
                        ) == 0
                        {
                            return false;
                        }

                        ptr::write_volatile(target, super_beep as usize as u64);

                        let mut dummy: u32 = 0;
                        VirtualProtect(
                            target as *mut c_void,
                            std::mem::size_of::<u64>(),
                            old_protect,
                            &mut dummy,
                        );

                        println!(
                            "[+] IAT Beep hookée : entrée={:p}  hook={:#x}",
                            target,
                            super_beep as usize
                        );
                        return true;
                    }
                }

                thunk = thunk.offset(1);
                orig = orig.offset(1);
            }
        }

        desc = desc.offset(1);
    }

    false
}