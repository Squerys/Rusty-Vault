# 🦀 Rusty Vault

Projet modulaire en **Rust** implémentant des techniques avancées de manipulation de binaires, d'obfuscation et d'injection.

## Fonctionnalités Implémentées

### Obfuscation
* **String Encryption** : Chiffrement des littéraux à la compilation via `obfstr`.

### Packing
* **Compression** : Aucune (*Raw*).
* **Chiffrement** : Algorithme **XOR** (changera pour un truc plus solide, faut juste qu'on trouve un bon critère de dérivation de clé).
* **Loader** : Exécution dynamique en mémoire (**RunPE**).

### Process Hollowing
* **Cible** : Windows uniquement.
* **Architecture** : x64 uniquement.

### Anti-Debug & Evasion
Techniques défensives pour ralentir l'analyse dynamique.

| Mécanisme | Description |
| :--- | :--- |
| **API Flag** | Vérification standard via `IsDebuggerPresent()`. |
| **Timing Check** | Détection des délais anormaux (RDTSC) dus au "step-over". |
| **Payload Corruption** | **Kill-switch** : Si une anomalie est détectée, le déchiffrement utilise une clé partielle pour corrompre l'exécutable final. |

### Analyse Heuristique
Détection automatique du type de fichier d'entrée :
- [x] PE (Portable Executable)
- [x] ELF
- [x] Raw Shellcode

### A faire
Renforcer le chiffrement, compléter l'antidebug, implémenter le control flow flattening, implémenter le swap de fonction par hooking de l'iat au runtime.

