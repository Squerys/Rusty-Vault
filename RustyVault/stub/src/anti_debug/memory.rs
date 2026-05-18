use std::ptr;

#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};

#[cfg(unix)]
use libc::{ptrace, PTRACE_TRACEME, PTRACE_DETACH};

// ===============================
// LOGIQUE DE SCAN MÉMOIRE
// ===============================

pub unsafe fn scan_for_int3(addr: *const u8, size: usize) -> bool {
    let mut i = 0;
    loop {
        if size > 0 && i >= size { break; }
        
        let current_byte = *addr.add(i);
        
        // Mode "scan jusqu'au retour" si size est 0
        if size == 0 && current_byte == 0xC3 { break; }

        if current_byte == 0xCC {
            return true; 
        }
        i += 1;
    }
    false
}

// ===============================
// LOGIQUE SYSTÈME (WINDOWS)
// ===============================

#[cfg(windows)]
pub fn patch_system_breakpoints() -> bool {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll == std::ptr::null_mut()  { return false; }

        let mut detected = false;
        // Correction : On utilise un tableau de slices de bytes (&[u8])
        let symbols: &[&[u8]] = &[
            b"DbgBreakPoint\0",
            b"DbgUiRemoteBreakin\0"
        ];

        for symbol in symbols {
            // Correction : On récupère explicitement le pointeur
            let symbol_ptr = symbol.as_ptr();

            if let Some(addr) = GetProcAddress(ntdll, symbol_ptr) {
                let mut old_protect: PAGE_PROTECTION_FLAGS = 0;

                if VirtualProtect(addr as _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                    *(addr as *mut u8) = 0xC3; // On injecte le RET (0xC3)
                    VirtualProtect(addr as _, 1, old_protect, &mut old_protect);
                    detected = true;
                }
            }
        }
        detected
  }

}

// ===============================
// LOGIQUE SYSTÈME (LINUX)
// ===============================

#[cfg(unix)]
pub fn check_ptrace_debug() -> bool {
    unsafe {
        // Tente de devenir le propre traceur du processus. 
        // Échoue si un debugger (GDB/EdB) est déjà présent.
        if ptrace(PTRACE_TRACEME, 0, 1, 0) < 0 {
            return true; 
        }
        // Si réussi, on se détache pour laisser le processus continuer normalement
        ptrace(PTRACE_DETACH, 0, 1, 0);
        false
    }
}


// ===============================
// Check
// ===============================

pub fn check_memory(addresses_to_watch: &[*const u8]) -> bool {

    let mut corrupted_mode = false;

    #[cfg(windows)]
    patch_system_breakpoints();

    #[cfg(unix)]
    if check_ptrace_debug() { corrupted_mode = true; }

    // 2. Scan des zones sensibles passées en paramètre
    for &addr in addresses_to_watch {
        unsafe {
            if *addr == 0xCC {
				corrupted_mode = true;
			}
        }
    }

    corrupted_mode
}

pub fn check(addresses_to_watch: &[*const u8]) -> bool {
    // On passe l'argument reçu à check_memory
    check_memory(addresses_to_watch) 
}
