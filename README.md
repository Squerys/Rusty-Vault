# 🦀 Rusty Vault

Projet modulaire en **Rust** de *hardening* et de protection de binaires : packing,
chiffrement personnalisé, obfuscation LLVM, techniques anti-debug et chargement en mémoire.  
Projet à vocation **pédagogique et de recherche**.

---

## 🏗️ Architecture

Le projet est un **workspace Cargo** composé de deux crates distincts, séparant la
phase de *build* de l'exécution runtime :

| Crate | Rôle |
|:----------|:---------------------------------------------------------------------------------|
| **`builder`** | Outil de packing exécuté côté développeur : détecte le format du binaire d'entrée, le chiffre avec RogueCipher et génère l'exécutable protégé en y embarquant le stub. |
| **`stub`** | Loader runtime embarqué dans le binaire final : dérive la clé, déchiffre le payload, applique les contrôles anti-debug puis charge et lance la cible en mémoire. |

```
RustyVault/
├── Cargo.toml              # Workspace + profil release durci
│                           # (opt-level "z", LTO, strip, panic=abort, codegen-units=1)
├── ollvm.dll               # Plugin LLVM d'obfuscation (iROBF)
├── builder/
│   └── src/
│       ├── main.rs
│       ├── builder.rs      # Compilation cross-target du stub (+ injection RUSTFLAGS OLLVM)
│       ├── packer.rs       # Assemblage : stub + MAGIC_DELIMITER + payload chiffré
│       ├── cypher.rs       # RogueCipher (chiffrement) + dérivation de clé (Stolen Bytes)
│       ├── detector.rs     # Détection heuristique du format d'entrée (PE / ELF)
│       └── constants.rs    # MAGIC_DELIMITER, constantes partagées
└── stub/
    └── src/
        ├── main.rs
        ├── config.rs               # Configuration embarquée
        ├── payload.rs              # Localisation du payload (via MAGIC_DELIMITER)
        ├── cypher.rs               # RogueCipher (déchiffrement) + dérivation de clé
        ├── run_pe.rs               # RunPE / Process Hollowing
        ├── resolve_rva.rs          # Résolution des RVA
        ├── inject_remote_dll.rs    # Injection de DLL distante
        ├── linux_mem_exec.rs       # Exécution en mémoire sous Linux
        ├── get_time_cycles.rs      # Lecture des cycles CPU (RDTSC)
        ├── is_being_debugged.rs    # Vérification haut niveau (kill-switch)
        ├── utils.rs
        ├── anti_debug/             # assembly, debugger, exceptions, handles,
        │                           # interactive, memory, misc, timing
        └── loader/
            ├── linux.rs
            └── windows/            # pe, process, iat
```

---

## ✨ Fonctionnalités

### Obfuscation

- **String Encryption** : chiffrement des littéraux à la compilation via `obfstr`.
- **Code Obfuscation** : via `goldberg`.
- **OLLVM / iROBF** (Windows) : lors de la compilation du stub pour une cible Windows,
  le builder injecte automatiquement le plugin LLVM `ollvm.dll` via `RUSTFLAGS`, avec
  les passes suivantes :
  - `irobf-cff` — Control Flow Flattening
  - `irobf-indbr` — Indirect Branching
  - `irobf-icall` — Indirect Calls
  - `irobf-indgv` — Indirect Global Variables

  > OLLVM est **désactivé pour les cibles Linux** pour l'instant.

- **Profil de build durci** : strip des symboles, LTO, `panic = "abort"`,
  `opt-level = "z"`, `codegen-units = 1`.

### Analyse heuristique

Détection automatique du format du binaire d'entrée par magic bytes :

| Format | Magic |
|:-------|:------|
| PE (Windows) | `MZ` (`0x4D 0x5A`) |
| ELF (Linux) | `\x7fELF` (`0x7F 0x45 0x4C 0x46`) |

> Le raw shellcode n'est pas supporté en l'état.

### Chiffrement — RogueCipher

Le payload est chiffré avec **RogueCipher**, un chiffrement bloc symétrique
personnalisé (**non standard**) :

- **Structure** : réseau de Feistel à **12 rounds**, blocs de **128 bits**
  (deux demi-blocs `u64`).
- **Fonction de round (ARX)** : XOR, addition modulaire et rotation du demi-bloc
  droit, contrôlée par les sous-clés.
- **Key Scheduling** : dérivation de 12 paires de sous-clés 64 bits par additions
  modulaires, rotations et XOR avec les constantes `0x5555…` / `0xAAAA…`.
- **Padding** : PKCS#7.

#### Dérivation de clé — Stolen Bytes / API Fingerprinting

La clé de 16 octets est dérivée au runtime en lisant les **premiers octets des
fonctions système** résolues dynamiquement — ce qui lie le payload à l'environnement
d'exécution attendu :

| OS | DLL | Fonctions échantillonnées |
|:---|:----|:--------------------------|
| Windows | `kernel32.dll` | `VirtualAlloc`, `CreateProcessA` |
| Windows | `ntdll.dll` | `NtProtectVirtualMemory`, `NtWriteVirtualMemory` |
| Linux | `libc.so.6` | `mmap`, `mprotect`, `fork`, `execve` |

4 octets sont prélevés par fonction → 16 octets au total.

### Format du binaire produit

```
[ stub (PE ou ELF) ][ MAGIC_DELIMITER ][ payload chiffré (RogueCipher + PKCS#7) ]
```

Le stub localise le payload à l'exécution en cherchant le `MAGIC_DELIMITER`.

### Chargement & exécution en mémoire

- **Windows** (x64) :
  - RunPE / Process Hollowing
  - Mapping manuel du PE, résolution des RVA et de l'IAT
  - Injection de DLL distante
- **Linux** — exécution fileless via `memfd_create` :
  1. Création d'un fd anonyme en mémoire (`memfd_create`, flag `MFD_CLOEXEC`),
     nommé `"initrd"` (obfusqué) pour le masquer dans `/proc/<pid>/fd/`.
  2. Écriture du payload ELF déchiffré directement dans ce fd.
  3. Exécution via `/proc/self/fd/<fd>` — le binaire ne touche jamais le disque.
  4. Les arguments du processus courant sont transmis à l'enfant.

### Anti-Debug & Évasion

Techniques défensives regroupées dans `anti_debug/`, réparties par famille :

| Module | Vecteur de détection |
|:-------------------|:--------------------------------------------------------------|
| `debugger.rs`      | API standard (`IsDebuggerPresent`, etc.)                      |
| `timing.rs`        | Délais anormaux via RDTSC                                     |
| `handles.rs`       | Vérifications sur les handles                                 |
| `memory.rs`        | Inspection de la mémoire                                      |
| `exceptions.rs`    | Comportement anormal de la gestion des exceptions             |
| `assembly.rs`      | Vérifications bas niveau en assembleur inline                 |
| `interactive.rs` / `misc.rs` | Contrôles divers                                    |

**Kill-switch** : si une anomalie est détectée, la dérivation de clé renvoie une
clé partielle / incorrecte, ce qui corrompt le déchiffrement et produit un payload
invalide.

---

## 🔧 Build

Le projet requiert une toolchain **nightly** (`cargo-features = ["edition2024"]`) :

```bash
cd RustyVault

# Build des deux crates du workspace
cargo +nightly build --release

# Le builder compile également le stub en cross-compilation selon la cible détectée
# (nightly-2024-06-26 est épinglé pour les builds Windows avec OLLVM)
```

> **Dépendances principales** : `obfstr`, `goldberg`, `libc`, `winapi`, `windows-sys`.

---

## 🚀 Utilisation

```bash
./builder <binaire_entrée> <binaire_sortie>
```

Le builder détecte le format du binaire d'entrée, compile le stub pour la cible
correspondante, chiffre le payload et produit le binaire protégé.

Des exemples déjà packés sont fournis dans [`exemples/`](exemples/) :

| Entrée | Sortie | Type |
|:----------------|:----------------------|:------|
| `calc.exe`      | `calc_packed.exe`     | PE    |
| `crackme.exe`   | `crackme_packed.exe`  | PE    |
| `ch1.bin`       | —                     | ELF   |

---

## 🗺️ Roadmap / À faire

- [ ] Renforcer la dérivation de clé (critère plus robuste / résistant à la
  portabilité inter-machines).
- [ ] Activer OLLVM pour les cibles Linux.
- [ ] Swap de fonctions par hooking de l'IAT au runtime.
- [ ] Compléter et renforcer la couche anti-debug.

---

## ⚠️ Avertissement

Projet développé dans un cadre **éducatif et de recherche** sur la protection et
l'analyse de binaires. Son utilisation doit se faire uniquement sur des systèmes et
des binaires pour lesquels vous disposez d'une autorisation explicite.
