# Catalog

What is actually in the knowledge base, generated from the index.
Regenerate with `make catalog`.

**4,767 documents · 1,222,671 lines · 40,581 code blocks · 8,722 tags · 597 CTFs**

## By type

| Type | Count | What it is |
|---|---:|---|
| `writeup` | 2,920 | solved challenges from real competitions |
| `reference` | 866 | tables, mirrored wikis and vendored libraries |
| `technique` | 693 | one attack each, with a working exploit |
| `script` | 189 | complete, self-testing tools |
| `cheatsheet` | 56 | dense command and payload references |
| `tool` | 30 | install plus the invocations that matter |
| `playbook` | 13 | decision trees for when you do not know where to start |

## By category

| Category | Docs | Covers |
|---|---:|---|
| [Cryptography](#crypto) | 1,083 | RSA, AES, ECC, lattices, PRNG, classical |
| [Web](#web) | 1,131 | Injection, SSTI, deserialization, JWT, SSRF |
| [Binary Exploit](#pwn) | 800 | Stack, ROP, heap, kernel, format string |
| [Reversing](#rev) | 421 | Ghidra, angr, packers, obfuscation, VMs |
| [Forensics](#forensics) | 321 | Memory, disk, pcap, logs, documents |
| [Steganography](#stego) | 73 | Images, audio, polyglots, archives |
| [Misc](#misc) | 517 | Jails, recon, AD, esolangs, PoW |
| [OSINT](#osint) | 105 | People, geolocation, infrastructure |
| [Mobile](#mobile) | 116 | Android, iOS, Frida, APK |
| [Hardware](#hardware) | 85 | Firmware, UART, JTAG, SDR, side channel |
| [Blockchain](#blockchain) | 92 | Solidity, EVM, DeFi, Foundry |
| [Cloud](#cloud) | 23 | K8s, containers, AWS/GCP/Azure, CI/CD |

## Start here

When you do not know what you are looking at, open a playbook:

- **Binary Exploitation Triage** &nbsp; `ctfbrain show playbooks:pwn-triage`  
  checksec -> bug class -> technique, plus the 'I have primitive X, now what' table for pwn.
- **Crypto Challenge Triage** &nbsp; `ctfbrain show playbooks:crypto-triage`  
  Sort any crypto challenge into an attack family by what you were given: parameters, a service, a ciphertext blob, or source code.
- **Forensics Triage: pcap, Memory, Disk, Documents** &nbsp; `ctfbrain show playbooks:forensics-triage`  
  Four branches by artifact type: pcap, memory image, disk image, or a document. Each ends in a concrete extraction command.
- **I Have Been Stuck for 30 Minutes** &nbsp; `ctfbrain show playbooks:stuck`  
  A systematic unsticking checklist: re-read the prompt, verify the flag format, list your assumptions, find the intended-vs-actual gap, and decide when to move on.
- **I Have Primitive P, What Can I Turn It Into?** &nbsp; `ctfbrain show playbooks:attack-surface-by-primitive`  
  Conversion table: for each primitive you already have (web, pwn, crypto, system), the next primitive it buys you and the exact way to get there.
- **I Have `nc host port`** &nbsp; `ctfbrain show playbooks:remote-service`  
  Fingerprint any remote service, detect a proof-of-work gate and an interactive protocol, and route to the right attack family.
- **I Have an Unknown File** &nbsp; `ctfbrain show playbooks:unknown-file`  
  Decision tree from a mystery blob to a category: file -> magic bytes -> entropy -> container vs executable vs archive vs ciphertext.
- **RSA Decision Tree by Known Parameters** &nbsp; `ctfbrain show playbooks:rsa-decision-tree`  
  Lookup table: given exactly which RSA values you know, which attack applies and the exact command to run.
- **Reverse Engineering Triage** &nbsp; `ctfbrain show playbooks:rev-triage`  
  Identify the language/toolchain of a binary, pick the right decompiler, then pick the solving strategy (read, emulate, symbolic, brute).
- **Steganography Triage: Image, Audio, Video, Archive** &nbsp; `ctfbrain show playbooks:stego-triage`  
  Run the universal sweep, then branch by container: PNG/BMP, JPEG, GIF, audio, video, or archive. Every branch ends in a command.
- **The Challenge Gave Me Source Code** &nbsp; `ctfbrain show playbooks:source-code-given`  
  The review order for any handout source plus a per-language grep list of dangerous sinks.
- **The Competition Just Started** &nbsp; `ctfbrain show playbooks:ctf-start`  
  First 30 minutes of a CTF: environment check, team split, the triage sweep across all challenges, note-taking, and how to pick what to work on.
- **Web Challenge Triage** &nbsp; `ctfbrain show playbooks:web-triage`  
  Recon order for a URL, the grep list per language for given source, and where the bug usually is per stack.

<a id="crypto"></a>

## Cryptography

*RSA, AES, ECC, lattices, PRNG, classical*

`writeup` 768  `script` 127  `technique` 91  `reference` 81  `cheatsheet` 10  `tool` 4  `playbook` 2

Common tags: `crypto` `ctf-writeup` `rsa` `xor` `cryptography` `aes` `2024` `sage` `proof-of-work` `gcd` `base64` `2025` `chinese-remainder` `lattice` `2026` `cbc` `prng` `crypto-attacks` `lll` `eval` `rsactftool` `discrete-log`

**playbook** (2)

- Playbook - RSA Decision Tree by Known Parameters  `playbooks:rsa-decision-tree`
- Playbook - Crypto Challenge Triage  `playbooks:crypto-triage`

**cheatsheet** (10)

- Classical Ciphers - Identification and One-Liner Cheatsheet  `cheatsheets:crypto:classical-ciphers-cheatsheet`
- ECC - Formulas, Sage Recipes and the Attack Decision Table  `cheatsheets:crypto:ecc-cheatsheet`
- Encodings - Base16/32/58/62/64/85/91, uuencode, URL, HTML, Punycode and Friends  `cheatsheets:crypto:encoding-cheatsheet`
- Factoring - Cheatsheet (factordb, yafu, cado-nfs, msieve, ECM, sympy, gmpy2)  `cheatsheets:crypto:factoring-cheatsheet`
- Hash Cracking Cheatsheet - hashcat, John, Masks, Rules, Identification  `cheatsheets:crypto:hash-cracking-cheatsheet`
- Lattices - Basis Templates, fpylll/Sage Recipes and LLL Debugging  `cheatsheets:crypto:lattice-cheatsheet`
- PRNG Cheatsheet - Which Language Uses What, and How to Break It  `cheatsheets:crypto:prng-cheatsheet`
- RSA - Cheatsheet (what do I have -> what attack)  `cheatsheets:crypto:rsa-cheatsheet`
- SageMath - Install, Preparser Gotchas and the 80 Idioms a CTF Crypto Player Needs  `cheatsheets:crypto:sagemath-cheatsheet`
- Symmetric Crypto Cheatsheet - Modes, Oracles, openssl, pycryptodome  `cheatsheets:crypto:symmetric-cheatsheet`

**technique** (91)

- Collision (Cryptography)  `techniques:crypto:notes-cryptography-collision-md`
- AES-ECB - Byte-at-a-Time Decryption with a Chosen-Prefix Oracle · medium  `techniques:crypto:aes-ecb-byte-at-a-time`
- AES-ECB - Cut-and-Paste Forgery, Block Shuffling and the ECB Penguin · easy  `techniques:crypto:aes-ecb-cut-and-paste`
- Meet-in-the-Middle on Double Encryption (2DES-style) · medium  `techniques:crypto:block-meet-in-the-middle`
- AES-CBC - Bit-Flipping Attack · easy  `techniques:crypto:aes-cbc-bit-flipping`
- AES-CBC - IV Recovery and the key==IV Attack · medium  `techniques:crypto:aes-cbc-iv-recovery`
- AES-CBC - Padding Oracle: Full Decryption and Forged Encryption (CBC-R) · medium  `techniques:crypto:aes-cbc-padding-oracle`
- ADFGVX / ADFGX, Nihilist and the Polybius Square Family · medium  `techniques:crypto:classical-adfgvx-polybius`
- Baconian, Tap Code, Morse, Pigpen, Dancing Men and Other Symbol Ciphers · easy  `techniques:crypto:classical-symbol-ciphers`
- Caesar / ROT-n / Affine - Full Keyspace Brute Force with Scoring · trivial  `techniques:crypto:classical-caesar-affine`
- Enigma and Rotor Machines - How to Attack One in a CTF · hard  `techniques:crypto:classical-enigma-rotor`
- Hill Cipher - Known-Plaintext Key Recovery by Matrix Inversion mod 26 · medium  `techniques:crypto:classical-hill-cipher`
- Monoalphabetic Substitution - Frequency Analysis + Hill Climbing · easy  `techniques:crypto:classical-substitution-hillclimb`
- Playfair, Bifid, Trifid and Four-Square - Polybius-Grid Ciphers · medium  `techniques:crypto:classical-playfair-bifid`
- *...and 77 more: `ctfbrain search "" -c crypto -t technique -n 200`*

**script** (127)

- AES Toolkit - ECB Byte-at-a-Time, CBC Padding Oracle, CBC-R, Bit-Flipping, CTR Keystream  `scripts:crypto:aes-toolkit`
- Fms (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-fms`
- Nonce Reuse (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-nonce-reuse`
- Padding Oracle (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-padding-oracle`
- Unsafe Generator (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-unsafe-generator`
- Iv Recovery (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-iv-recovery`
- Eam Key Reuse (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-eam-key-reuse`
- Etm Key Reuse (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-etm-key-reuse`
- Mte Key Reuse (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-mte-key-reuse`
- Key Reuse (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-key-reuse`
- classical-solver.py - Auto-Detect and Solve Caesar, Affine, Vigenere, Substitution and Transposition  `scripts:crypto:classical-solver`
- Bit Flipping (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-bit-flipping`
- Crime (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-crime`
- Separator Oracle (crypto-attacks)  `scripts:crypto:vendor-crypto-attacks-separator-oracle`
- *...and 113 more: `ctfbrain search "" -c crypto -t script -n 200`*

**tool** (4)

- Tool - FactorDB  `tools:factordb`
- Tool - SageMath  `tools:sagemath`
- Tool - RsaCtfTool  `tools:rsactftool`
- Tool - bkcrack  `tools:bkcrack`

Plus 849 writeups and reference pages: `ctfbrain search "" -c crypto -t writeup -n 200`

<a id="web"></a>

## Web

*Injection, SSTI, deserialization, JWT, SSRF*

`writeup` 672  `technique` 229  `reference` 211  `cheatsheet` 10  `tool` 4  `script` 4  `playbook` 1

Common tags: `web` `ctf-writeup` `xss` `sqli` `base64` `hacktricks` `ssrf` `2025` `lfi` `jwt` `2024` `burp` `path-traversal` `wstg` `web-exploitation` `flask` `ssti` `injection` `union-select` `2026` `csrf` `deserialization`

**playbook** (1)

- Playbook - Web Challenge Triage  `playbooks:web-triage`

**cheatsheet** (10)

- Command Injection - Separators, Filter Bypass and Argument Injection  `cheatsheets:web:command-injection-payloads`
- Deserialization Gadgets - Magic Bytes, ysoserial/phpggc Lists, Pickle Opcodes  `cheatsheets:web:deserialization-gadgets`
- GraphQL Recon - Introspection, Clairvoyance, graphw00f, Batching  `cheatsheets:web:graphql-recon`
- LFI - PHP Wrappers, High-Value Paths and Traversal Encodings  `cheatsheets:web:lfi-wrappers-and-paths`
- PHP Tricks - Type Juggling, Wrappers, Filter Bypass, RCE Primitives  `cheatsheets:web:php-tricks`
- SQL Injection - Payloads, Per-DBMS Enumeration and sqlmap  `cheatsheets:web:sqli-payloads`
- SSRF - Metadata Endpoints, IP Obfuscation and gopher:// Construction  `cheatsheets:web:ssrf-payloads`
- SSTI Payloads - Detection Matrix and Per-Engine RCE Ladder  `cheatsheets:web:ssti-payloads`
- JWT Attacks - jwt_tool, hashcat and openssl Recipes  `cheatsheets:web:jwt-attacks`
- XSS - Payloads by Injection Context, CSP Bypass and DOM Sinks  `cheatsheets:web:xss-payloads`

**technique** (229)

- Bypass Php Functions Blacklist (Web)  `techniques:web:notes-web-bypass-php-functions-blacklist-md`
- Intercept sqlmap requests with burp (Web)  `techniques:web:notes-web-intercept-sqlmap-requests-with-burp-md`
- Local Python server (Web)  `techniques:web:notes-web-local-python-server-md`
- Local Tunnel (Web)  `techniques:web:notes-web-local-tunnel-md`
- Nodejs readfile (Web)  `techniques:web:notes-web-nodejs-readfile-md`
- PHAR wrapper file execution PHP bypass (Web)  `techniques:web:notes-web-phar-wrapper-file-execution-php-bypass-md`
- Python Blacklist Bypass (Web)  `techniques:web:notes-web-python-blacklist-bypass-md`
- SLQ Injection Enumeration (Web)  `techniques:web:notes-web-slq-injection-enumeration-md`
- Send a file via curl (Web)  `techniques:web:notes-web-send-a-file-via-curl-md`
- Account Takeover (PayloadsAllTheThings) · medium  `techniques:web:ext-payloads-account-takeover`
- Directory Traversal File Include (OWASP WSTG) · medium  `techniques:web:ext-wstg-authorization-directory-traversal-file-include`
- BrowExt - ClickJacking (HackTricks) · medium  `techniques:web:ext-hacktricks-browser-extension-pentesting-methodology-browext-clickjacking`
- BrowExt - XSS Example (HackTricks) · medium  `techniques:web:ext-hacktricks-browser-extension-pentesting-methodology-browext-xss-example`
- Forced Extension Load & Preferences MAC Forgery (Windows) (HackTricks) · medium  `techniques:web:ext-hacktricks-browser-extension-pentesting-methodology-forced-extension-load-preferenc`
- *...and 215 more: `ctfbrain search "" -c web -t technique -n 200`*

**script** (4)

- php://filter Simulator and a Log-Poisoning Fixture  `scripts:web:lfi-log-poison`
- Race Condition Harness - Threaded Barrier + HTTP/2 Single-Packet Attack  `scripts:web:race-condition-harness`
- Blind Extraction - Binary Search Over a Character Space  `scripts:web:blind-sqli-exfil`
- JWT Toolkit - Decode, Forge, alg=none, Key Confusion, Secret Brute, jku Injection  `scripts:web:jwt-toolkit`

**tool** (4)

- Tool - ffuf  `tools:ffuf`
- Tool - jwt_tool  `tools:jwt-tool`
- Tool - Burp Suite  `tools:burpsuite`
- Tool - sqlmap  `tools:sqlmap`

Plus 883 writeups and reference pages: `ctfbrain search "" -c web -t writeup -n 200`

<a id="pwn"></a>

## Binary Exploit

*Stack, ROP, heap, kernel, format string*

`writeup` 458  `reference` 155  `technique` 142  `script` 34  `cheatsheet` 6  `tool` 4  `playbook` 1

Common tags: `pwn` `heap` `rop` `canary` `pie` `ctf-writeup` `aslr` `shellcode` `buffer-overflow` `pwntools` `checksec` `binary-exploitation` `tcache` `xor` `ctf-wiki` `hacktricks` `use-after-free` `chinese` `zh` `pwndbg` `one-gadget` `stack`

**playbook** (1)

- Playbook - Binary Exploitation Triage  `playbooks:pwn-triage`

**cheatsheet** (6)

- glibc Heap - Command and Constraint Cheatsheet  `cheatsheets:pwn:glibc-heap-cheatsheet`
- Linux Kernel Pwn - Command and Struct Cheatsheet  `cheatsheets:pwn:kernel-pwn-cheatsheet`
- ROP Gadgets - Hunting, Shopping Lists and Chaining  `cheatsheets:pwn:rop-gadgets-cheatsheet`
- Shellcode - Ready Payloads for x86, x86-64, ARM, AArch64, MIPS  `cheatsheets:pwn:shellcode-cheatsheet`
- GDB + GEF + pwndbg - Side-by-Side Debugging Cheatsheet  `cheatsheets:pwn:gdb-gef-pwndbg-cheatsheet`
- pwntools - Complete Exploitation Cheatsheet  `cheatsheets:pwn:pwntools-cheatsheet`

**technique** (142)

- Pwntools (pwn)  `techniques:pwn:notes-pwn-pwntools-md`
- Swap Endianess (pwn)  `techniques:pwn:notes-pwn-swap-endianess-md`
- Template (pwn)  `techniques:pwn:notes-pwn-template-md`
- ret2VDSO (CTF Wiki) · hard  `techniques:pwn:ext-ctf-wiki-x86-advanced-rop-ret2vdso`
- ret2dlresolve (CTF Wiki) · hard  `techniques:pwn:ext-ctf-wiki-x86-advanced-rop-ret2dlresolve`
- Arm ROP (CTF Wiki) · hard  `techniques:pwn:ext-ctf-wiki-stackoverflow-arm-rop`
- Partial Overwrite - Beating PIE and ASLR One Nibble at a Time · medium  `techniques:pwn:mitigation-partial-overwrite-brute`
- Ret2plt (HackTricks) · hard  `techniques:pwn:ext-hacktricks-common-binary-protections-and-bypasses-aslr-ret2plt`
- Ret2ret & Ret2pop (HackTricks) · hard  `techniques:pwn:ext-hacktricks-common-binary-protections-and-bypasses-aslr-ret2ret`
- R34R Session (Attacks)  `techniques:pwn:notes-pwn-attacks-r34r-session-md`
- Ret2Dlresolve (Attacks)  `techniques:pwn:notes-pwn-attacks-ret2dlresolve-md`
- FreeBSD ptrace RFI and vmmap PROTEXEC bypass (PS5 case study) (HackTricks) · hard  `techniques:pwn:ext-hacktricks-freebsd-ptrace-rfi-vm-map-prot-exec-bypass-ps`
- Integer Overflow (HackTricks) · hard  `techniques:pwn:ext-hacktricks-integer-overflow-and-underflow`
- Vectored Overloading PE Injection (HackTricks) · hard  `techniques:pwn:ext-hacktricks-windows-vectored-overloading`
- *...and 128 more: `ctfbrain search "" -c pwn -t technique -n 200`*

**script** (34)

- Decrypt Safe Linking (how2heap)  `scripts:pwn:vendor-how2heap-decrypt-safe-linking`
- Fastbin Dup (how2heap)  `scripts:pwn:vendor-how2heap-fastbin-dup`
- Fastbin Dup Consolidate (how2heap)  `scripts:pwn:vendor-how2heap-fastbin-dup-consolidate`
- Fastbin Dup Into Stack (how2heap)  `scripts:pwn:vendor-how2heap-fastbin-dup-into-stack`
- Heap Menu Exploit Template - pwntools Boilerplate  `scripts:pwn:heap-menu-template`
- House Of Botcake (how2heap)  `scripts:pwn:vendor-how2heap-house-of-botcake`
- House Of Einherjar (how2heap)  `scripts:pwn:vendor-how2heap-house-of-einherjar`
- House Of Io (how2heap)  `scripts:pwn:vendor-how2heap-house-of-io`
- House Of Lore (how2heap)  `scripts:pwn:vendor-how2heap-house-of-lore`
- House Of Spirit (how2heap)  `scripts:pwn:vendor-how2heap-house-of-spirit`
- House Of Tangerine (how2heap)  `scripts:pwn:vendor-how2heap-house-of-tangerine`
- House Of Water (how2heap)  `scripts:pwn:vendor-how2heap-house-of-water`
- Large Bin Attack (how2heap)  `scripts:pwn:vendor-how2heap-large-bin-attack`
- Poison Null Byte (how2heap)  `scripts:pwn:vendor-how2heap-poison-null-byte`
- *...and 20 more: `ctfbrain search "" -c pwn -t script -n 200`*

**tool** (4)

- Tool - gdb with pwndbg / GEF  `tools:gdb-pwndbg-gef`
- Tool - ROPgadget / ropper  `tools:ropgadget-ropper`
- Tool - one_gadget  `tools:one-gadget`
- Tool - pwntools  `tools:pwntools`

Plus 613 writeups and reference pages: `ctfbrain search "" -c pwn -t writeup -n 200`

<a id="rev"></a>

## Reversing

*Ghidra, angr, packers, obfuscation, VMs*

`writeup` 294  `reference` 79  `technique` 32  `script` 7  `tool` 4  `cheatsheet` 4  `playbook` 1

Common tags: `rev` `ctf-writeup` `xor` `reverse-engineering` `reverse` `ghidra` `static-analysis` `2026` `radare2` `pie` `anti-debug` `base64` `chinese` `ctf-wiki` `zh` `2024` `2025` `symbolic-execution` `python-bytecode` `z3` `aes` `obfuscation`

**playbook** (1)

- Playbook - Reverse Engineering Triage  `playbooks:rev-triage`

**cheatsheet** (4)

- GDB for Reverse Engineering - Cheatsheet  `cheatsheets:rev:gdb-reversing-cheatsheet`
- Ghidra - Shortcuts, Analysis Options and Headless  `cheatsheets:rev:ghidra-cheatsheet`
- radare2 - The 80 Commands That Matter  `cheatsheets:rev:radare2-cheatsheet`
- angr and z3 - Recipes Side by Side  `cheatsheets:rev:angr-z3-cheatsheet`

**technique** (32)

- Compile C code (Reverse)  `techniques:rev:notes-reverse-compile-c-code-md`
- Extract .jar files (Reverse)  `techniques:rev:notes-reverse-extract-jar-files-md`
- Set a variable to a specific value in gdb-pwndg (Reverse)  `techniques:rev:notes-reverse-set-a-variable-to-a-specific-value-in-gdb-pwndg-md`
- angr - Symbolic Execution for Keygens and Flag Checkers · medium  `techniques:rev:angr-symbolic-execution`
- Anti-Debugging - Every Trick and How to Defeat It · medium  `techniques:rev:anti-debug-bypass`
- Anti-VM and Anti-Sandbox - Environment Checks and Their Bypasses · medium  `techniques:rev:anti-vm-bypass`
- C++ RE - Vtables, RTTI and STL Layouts · medium  `techniques:rev:cpp-vtables-stl`
- Crackme Patterns - Recognise the Check, Invert It · easy  `techniques:rev:crackme-patterns`
- Custom VM and Bytecode Interpreters - Recover the ISA · hard  `techniques:rev:custom-vm-bytecode`
- IDA, Binary Ninja, radare2 and Cutter - Cross-Tool Workflow · medium  `techniques:rev:ida-r2-binja-workflow`
- .NET Reversing - dnSpy, de4dot and Patching IL · easy  `techniques:rev:dotnet-reversing`
- Dynamic Analysis - ltrace, strace, LD_PRELOAD and gdb Scripting · medium  `techniques:rev:dynamic-analysis-ltrace-ldpreload`
- Unicorn & Qiling - Emulating a Fragment of a Binary · medium  `techniques:rev:unicorn-qiling-emulation`
- Firmware and Raw Blobs - Extraction, Architecture ID, Base Address · hard  `techniques:rev:firmware-raw-blob-loading`
- *...and 18 more: `ctfbrain search "" -c rev -t technique -n 200`*

**script** (7)

- angr Solver Template - stdin, argv, call_state and hooks  `scripts:rev:angr-template`
- Ghidra Headless - analyzeHeadless Recipes and Three Jython Scripts  `scripts:rev:ghidra-headless-scripts`
- angr Basic Template (Reversing)  `scripts:rev:notes-scripts-reversing-angr-basic-template-md`
- angr Template - 02 (Reversing)  `scripts:rev:notes-scripts-reversing-angr-template-02-md`
- z3 Solver (Reversing)  `scripts:rev:notes-scripts-reversing-z3-solver-md`
- Unicorn - Emulate One Function Out of a Binary  `scripts:rev:unicorn-emulate-function`
- z3 Flag Solver Template - byte arrays, charsets and all_solutions  `scripts:rev:z3-flagsolver-template`

**tool** (4)

- Tool - Ghidra  `tools:ghidra`
- Tool - radare2 / rizin  `tools:radare2`
- Tool - z3  `tools:z3`
- Tool - angr  `tools:angr`

Plus 373 writeups and reference pages: `ctfbrain search "" -c rev -t writeup -n 200`

<a id="forensics"></a>

## Forensics

*Memory, disk, pcap, logs, documents*

`writeup` 167  `reference` 78  `technique` 62  `tool` 5  `script` 4  `cheatsheet` 4  `playbook` 1

Common tags: `forensics` `ctf-writeup` `pcap` `wireshark` `network` `forensic` `hacktricks` `2024` `base64` `tshark` `my-notes` `personal` `dfir` `xor` `binwalk` `aes` `volatility` `2025` `disk` `memory-forensics` `cyberchef` `file`

**playbook** (1)

- Playbook - Forensics Triage: pcap, Memory, Disk, Documents  `playbooks:forensics-triage`

**cheatsheet** (4)

- Disk Forensics Cheatsheet - Sleuthkit, Mounting, Hashing, Carving  `cheatsheets:forensics:disk-forensics-cheatsheet`
- Volatility Cheatsheet - vol3 and vol2 Side by Side  `cheatsheets:forensics:volatility-cheatsheet`
- tshark and Wireshark Cheatsheet - Filters, Fields and Extraction  `cheatsheets:forensics:tshark-wireshark-cheatsheet`
- Forensics Triage Cheatsheet - I Was Given a File of Type X  `cheatsheets:forensics:forensics-triage-cheatsheet`

**technique** (62)

- BitLocker encrypted drive (Forensics)  `techniques:forensics:notes-forensics-bitlocker-encrypted-drive-md`
- Chainsaw (Forensics)  `techniques:forensics:notes-forensics-chainsaw-md`
- Docker forensics (Forensics)  `techniques:forensics:notes-forensics-docker-forensics-md`
- GPG Decryption (Forensics)  `techniques:forensics:notes-forensics-gpg-decryption-md`
- Gixy (Forensics)  `techniques:forensics:notes-forensics-gixy-md`
- LNK Files (Forensics)  `techniques:forensics:notes-forensics-lnk-files-md`
- Logs (Forensics)  `techniques:forensics:notes-forensics-logs-md`
- Macro Documents (Forensics)  `techniques:forensics:notes-forensics-macro-documents-md`
- Mount a EWFExpert WitnessEnCase image file format .E01 (Forensics)  `techniques:forensics:notes-forensics-mount-a-ewfexpert-witnessencase-image-file-format-e01-md`
- NTFS Log Tracker (Forensics)  `techniques:forensics:notes-forensics-ntfs-log-tracker-md`
- Obfuscated Powershell (Forensics)  `techniques:forensics:notes-forensics-obfuscated-powershell-md`
- OleDump (Forensics)  `techniques:forensics:notes-forensics-oledump-md`
- Unzip Nested Zips (Forensics)  `techniques:forensics:notes-forensics-unzip-nested-zips-md`
- Xor Gif (Forensics)  `techniques:forensics:notes-forensics-xor-gif-md`
- *...and 48 more: `ctfbrain search "" -c forensics -t technique -n 200`*

**script** (4)

- Carve and Identify - Magic-Byte Scanner and Extractor  `scripts:forensics:carve-and-identify`
- PCAP Extractor - Objects, Credentials, DNS and Streams  `scripts:forensics:pcap-extractor`
- XOR two images (Forensics)  `scripts:forensics:notes-scripts-forensics-xor-two-images-md`
- USB HID Decoder - Keystrokes and Mouse Drawings  `scripts:forensics:usb-hid-decoder`

**tool** (5)

- Tool - binwalk  `tools:binwalk`
- Tool - Volatility 3  `tools:volatility3`
- Tool - ExifTool  `tools:exiftool`
- Tool - Wireshark / tshark  `tools:wireshark-tshark`
- Tool - Scapy  `tools:scapy`

Plus 245 writeups and reference pages: `ctfbrain search "" -c forensics -t writeup -n 200`

<a id="stego"></a>

## Steganography

*Images, audio, polyglots, archives*

`writeup` 39  `technique` 14  `reference` 13  `tool` 2  `script` 2  `cheatsheet` 2  `playbook` 1

Common tags: `stego` `ctf-writeup` `lsb` `exiftool` `steganography` `image` `spectrogram` `2025` `zsteg` `stegsolve` `binwalk` `audio` `exif` `metadata` `2026` `base64` `steghide` `2024` `outguess` `polyglot` `ctf-cit` `hacktricks`

**playbook** (1)

- Playbook - Steganography Triage: Image, Audio, Video, Archive  `playbooks:stego-triage`

**cheatsheet** (2)

- Steganography - Master Cheatsheet  `cheatsheets:stego:stego-cheatsheet`
- Image Forensics - ImageMagick and FFmpeg Recipes  `cheatsheets:stego:image-forensics-cheatsheet`

**technique** (14)

- Archive Attacks - bkcrack, Cracking, Bombs and Zip Slip · hard  `techniques:stego:archive-attacks`
- Audio Stego - Spectrogram, LSB, DTMF, SSTV and Morse · medium  `techniques:stego:audio-stego`
- QR Codes and Barcodes - Repair, Decode, Read by Hand · medium  `techniques:stego:qr-barcode`
- Brute Forcing Passworded Stego Tools · easy  `techniques:stego:stego-bruteforce`
- GIF, BMP, WEBP and TIFF - Format-Specific Tricks · medium  `techniques:stego:other-image-formats`
- Image Stego - Triage Order · easy  `techniques:stego:image-triage`
- JPEG - Markers, DCT Stego and Thumbnail Tricks · medium  `techniques:stego:jpeg-structure-attacks`
- LSB Steganography - Exhaustive Extraction · medium  `techniques:stego:lsb-extraction`
- Metadata Hiding - EXIF, GPS, ICC and XMP · easy  `techniques:stego:metadata-hiding`
- PNG - Structure and Chunk Attacks · medium  `techniques:stego:png-structure-attacks`
- Polyglots and Appended Data · medium  `techniques:stego:polyglot-files`
- Server Side Template Injection (PayloadsAllTheThings) · easy  `techniques:stego:ext-payloads-server-side-template-injection`
- Text Stego - Whitespace, Zero-Width and Homoglyphs · medium  `techniques:stego:text-unicode-stego`
- Video Stego and Frame Extraction · medium  `techniques:stego:video-stego`

**script** (2)

- Script - Audio Analyzer (Spectrogram, Morse, DTMF)  `scripts:stego:audio-analyzer`
- Script - Universal LSB Extractor  `scripts:stego:lsb-extractor`

**tool** (2)

- Tool - Aperi'Solve  `tools:aperisolve`
- Tool - Stegsolve / zsteg  `tools:stegsolve-zsteg`

Plus 52 writeups and reference pages: `ctfbrain search "" -c stego -t writeup -n 200`

<a id="misc"></a>

## Misc

*Jails, recon, AD, esolangs, PoW*

`writeup` 355  `reference` 92  `technique` 47  `cheatsheet` 9  `playbook` 6  `tool` 4  `script` 4

Common tags: `misc` `ctf-writeup` `miscellaneous` `2024` `2025` `base64` `2026` `eval` `hacktricks` `author-solution` `challenge-source` `nullcon-goa-hackim-2025-ctf` `subprocess` `proof-of-work` `python` `rsa` `tsg-ctf` `tsg-ctf-2024` `xor` `privesc` `gtfobins` `arkark-my-ctf-challenges`

**playbook** (6)

- Playbook - I Have Been Stuck for 30 Minutes  `playbooks:stuck`
- Playbook - The Competition Just Started  `playbooks:ctf-start`
- Playbook - I Have Primitive P, What Can I Turn It Into?  `playbooks:attack-surface-by-primitive`
- Playbook - I Have `nc host port`  `playbooks:remote-service`
- Playbook - I Have an Unknown File  `playbooks:unknown-file`
- Playbook - The Challenge Gave Me Source Code  `playbooks:source-code-given`

**cheatsheet** (9)

- Active Directory Cheatsheet - impacket, netexec, certipy, rubeus  `cheatsheets:misc:ad-cheatsheet`
- CTF General Cheatsheet - Flags, Encodings, strings, nc, PoW  `cheatsheets:misc:ctf-general-cheatsheet`
- Jail Escape Payloads - Python, Shell, JavaScript  `cheatsheets:misc:jail-escape-payloads`
- Service Enumeration Cheatsheet - First 5 Commands Per Port  `cheatsheets:misc:net-service-enumeration-cheatsheet`
- Service Exploitation Cheatsheet - Version Check to RCE per Product  `cheatsheets:misc:svc-exploitation-cheatsheet`
- Pivoting and Tunnelling Cheatsheet  `cheatsheets:misc:net-pivoting-cheatsheet`
- Reverse Shell Cheatsheet - 20 Languages, Listeners, PTY Upgrade  `cheatsheets:misc:net-reverse-shell-cheatsheet`
- Nmap and Recon Cheatsheet  `cheatsheets:misc:net-nmap-and-recon-cheatsheet`
- Web Fuzzing Cheatsheet - ffuf, feroxbuster, wfuzz, gobuster  `cheatsheets:misc:net-fuzzing-cheatsheet`

**technique** (47)

- Covert Timestamps python (random)  `techniques:misc:notes-random-covert-timestamps-python-md`
- Create Pdf File Command Line (random)  `techniques:misc:notes-random-create-pdf-file-command-line-md`
- JS Jail (Jails)  `techniques:misc:notes-jails-js-jail-md`
- One Liners (random)  `techniques:misc:notes-random-one-liners-md`
- Regex (random)  `techniques:misc:notes-random-regex-md`
- Zsh Jails (Jails)  `techniques:misc:notes-jails-zsh-jails-md`
- AD ACL and Delegation Abuse - GenericAll, WriteDACL, RBCD · hard  `techniques:misc:ad-acl-delegation-abuse`
- AD CS Abuse - ESC1 to ESC8 with Certipy · hard  `techniques:misc:ad-adcs-esc-attacks`
- AD Credential Attacks - Spraying, Relay, PtH/PtT and DCSync · hard  `techniques:misc:ad-credential-attacks`
- Active Directory Enumeration - LDAP, netexec and BloodHound · medium  `techniques:misc:ad-enumeration-bloodhound`
- Kerberos Ticket Attacks - Kerberoasting and AS-REP Roasting · medium  `techniques:misc:ad-kerberoasting-asreproast`
- Buffer Overflow (ctfs/resources) · medium  `techniques:misc:ext-ctfs-resources-buffer-overflow`
- Misc Classics - CVE Hunting, Keygens, Custom Protocols, PRNG · medium  `techniques:misc:misc-classics`
- Container Escape in CTF · hard  `techniques:misc:container-escape`
- *...and 33 more: `ctfbrain search "" -c misc -t technique -n 200`*

**script** (4)

- Docker  `scripts:misc:notes-scripts-docker-md`
- TCP Client Template - Raw Socket and pwntools for Unknown Services  `scripts:misc:net-tcp-client-template`
- Script - Universal Proof-of-Work Solver  `scripts:misc:pow-solver`
- Async Port Scanner and Banner Grabber (No nmap)  `scripts:misc:net-port-knock-and-scan`

**tool** (4)

- Tool - CyberChef  `tools:cyberchef`
- Tool - John the Ripper  `tools:john`
- Tool - hashcat  `tools:hashcat`
- Tool - nmap  `tools:nmap`

Plus 447 writeups and reference pages: `ctfbrain search "" -c misc -t writeup -n 200`

<a id="osint"></a>

## OSINT

*People, geolocation, infrastructure*

`writeup` 80  `reference` 16  `technique` 8  `cheatsheet` 1

Common tags: `osint` `ctf-writeup` `2024` `2025` `methodology` `hacktricks` `thcon-2k25-ctf` `exif` `phishing` `phishing-methodology` `base64` `rsa` `2026` `geolocation` `open-source-intelligence` `pie` `pivoting` `wayback` `xss` `vacation` `xor` `classical`

**cheatsheet** (1)

- OSINT Tools and Sites Cheatsheet  `cheatsheets:osint:osint-tools-cheatsheet`

**technique** (8)

- Corporate, Document and Code OSINT · medium  `techniques:osint:osint-documents-and-code`
- Image Geolocation · medium  `techniques:osint:osint-geolocation`
- Domain and Infrastructure OSINT · medium  `techniques:osint:osint-infrastructure`
- OSINT Methodology for CTF · easy  `techniques:osint:osint-methodology`
- Username, Email and People Pivoting · medium  `techniques:osint:osint-people-pivoting`
- Clipboard Hijacking (Pastejacking) Attacks (HackTricks) · easy  `techniques:osint:ext-hacktricks-phishing-methodology-clipboard-hijacking`
- Discord Invite Hijacking (HackTricks) · easy  `techniques:osint:ext-hacktricks-phishing-methodology-discord-invite-hijacking`
- Social Media Forensics and Archive Recovery · medium  `techniques:osint:osint-social-and-archives`

Plus 96 writeups and reference pages: `ctfbrain search "" -c osint -t writeup -n 200`

<a id="mobile"></a>

## Mobile

*Android, iOS, Frida, APK*

`reference` 76  `technique` 26  `writeup` 8  `tool` 2  `script` 2  `cheatsheet` 2

Common tags: `mobile` `hacktricks` `pentesting` `android` `frida` `adb` `app` `android-app-pentesting` `ios` `objection` `apktool` `ios-pentesting` `jadx` `smali` `ssl-pinning` `aes` `my-notes` `personal` `sqlite` `heap` `base64` `chinese`

**cheatsheet** (2)

- Android CTF Cheatsheet - adb, apktool, jadx, am, pm, content  `cheatsheets:mobile:android-cheatsheet`
- iOS CTF Cheatsheet - libimobiledevice, class-dump, frida-ios-dump, codesign  `cheatsheets:mobile:ios-cheatsheet`

**technique** (26)

- Decompilation (Mobile)  `techniques:mobile:notes-mobile-decompilation-md`
- Root check bypass (Mobile)  `techniques:mobile:notes-mobile-root-check-bypass-md`
- Strcmp (Mobile)  `techniques:mobile:notes-mobile-strcmp-md`
- Toast hooking (Mobile)  `techniques:mobile:notes-mobile-toast-hooking-md`
- Android Task Hijacking (HackTricks) · medium  `techniques:mobile:ext-hacktricks-mobile-pentesting-android-app-pentesting-android-task-hijacking`
- Intent Injection (HackTricks) · medium  `techniques:mobile:ext-hacktricks-mobile-pentesting-android-app-pentesting-intent-injection`
- Android Native Libraries - JNI, RegisterNatives and Reversing the .so · hard  `techniques:mobile:android-native-jni`
- Frida on Android - Setup and the Ten Hooks You Always Need · medium  `techniques:mobile:android-frida-basics`
- Android APK Triage - First 10 Minutes on an Unknown APK · easy  `techniques:mobile:android-apk-triage`
- Android Static Secrets - API Keys, Firebase and Endpoints in an APK · easy  `techniques:mobile:android-static-secrets`
- Smali Patching - Read, Patch, Rebuild and Re-sign an APK · medium  `techniques:mobile:android-smali-patching`
- Android Root, Emulator and Debug Detection - Bypass Catalogue · medium  `techniques:mobile:android-root-detection-bypass`
- Air Keyboard Remote Input Injection (Unauthenticated TCP / WebSocket Listener) (HackTricks) · medium  `techniques:mobile:ext-hacktricks-mobile-pentesting-ios-pentesting-air-keyboard-remote-input-injection`
- iOS Runtime - Frida, objection and Jailbreak Detection Bypass · hard  `techniques:mobile:ios-frida-runtime`
- *...and 12 more: `ctfbrain search "" -c mobile -t technique -n 200`*

**script** (2)

- Frida Script Library - Copy-Paste Hooks for Android and iOS  `scripts:mobile:frida-script-library`
- adb, objection and frida-tools Recipes - Task-Oriented Command Sets  `scripts:mobile:adb-objection-recipes`

**tool** (2)

- Tool - jadx  `tools:jadx`
- Tool - Frida  `tools:frida`

Plus 84 writeups and reference pages: `ctfbrain search "" -c mobile -t writeup -n 200`

<a id="hardware"></a>

## Hardware

*Firmware, UART, JTAG, SDR, side channel*

`reference` 42  `writeup` 22  `technique` 17  `script` 2  `cheatsheet` 2

Common tags: `hardware` `hacktricks` `pentesting` `pentesting-wifi` `wifi` `firmware` `tshark` `pcap` `ctf-writeup` `wireshark` `uart` `2025` `bootloader` `wi-fi` `analysis` `embedded` `firmware-analysis` `binwalk` `side-channel` `aes` `ghidra` `ics`

**cheatsheet** (2)

- RF and SDR Cheatsheet - rtl-sdr, HackRF, URH, rtl_433 and ISM Bands  `cheatsheets:hardware:rf-sdr-cheatsheet`
- Hardware Tools Cheatsheet - binwalk, flashrom, openocd, sigrok, esptool  `cheatsheets:hardware:hardware-tools-cheatsheet`

**technique** (17)

- Tools (Hardware)  `techniques:hardware:notes-hardware-tools-md`
- CAN Bus and Automotive - candump, cansend, DBC Reversing and Replay · medium  `techniques:hardware:can-bus-automotive`
- Fault Injection - Voltage and Clock Glitching for CTF · insane  `techniques:hardware:fault-injection-glitching`
- Firmware Emulation - qemu-user, qemu-system, chroot and FAT · hard  `techniques:hardware:firmware-emulation`
- Firmware Extraction - binwalk, squashfs, jffs2, ubifs and Finding the Root · medium  `techniques:hardware:firmware-extraction`
- Unknown Blob - Identifying Architecture, Endianness and Load Address · hard  `techniques:hardware:firmware-arch-identification`
- SPI and I2C Flash Dumping - flashrom, Bus Pirate, CH341A · medium  `techniques:hardware:spi-i2c-flash-dump`
- ICS and OT Protocols - Modbus, S7comm and DNP3 · medium  `techniques:hardware:ics-modbus-protocols`
- JTAG and SWD - Pinout Discovery, OpenOCD, Halting and Dumping Flash · hard  `techniques:hardware:jtag-swd`
- Logic Analyzer Captures - Decoding SPI, I2C, UART and 1-Wire from a .sr File · medium  `techniques:hardware:logic-analyzer-decoding`
- Microcontroller Reversing - AVR, PIC, STM32 and ESP32 · hard  `techniques:hardware:mcu-reversing`
- Enable NexMon Monitor Mode & Packet Injection on Android (Broadcom chips) (HackTricks) · hard  `techniques:hardware:ext-hacktricks-pentesting-wifi-enable-nexmon-monitor-and-injection-on-androi`
- Wi-Fi DoS and Management-Frame Attacks (HackTricks) · hard  `techniques:hardware:ext-hacktricks-pentesting-wifi-wifi-dos-and-management-frame-attacks`
- Common RF Protocols - 433 MHz Remotes, RFID/NFC and Bluetooth LE · medium  `techniques:hardware:rf-protocols-rfid-ble`
- *...and 3 more: `ctfbrain search "" -c hardware -t technique -n 200`*

**script** (2)

- Protocol Decoders - SPI, I2C and UART from Raw Logic Samples in Python  `scripts:hardware:protocol-decoders`
- UART Baud Scanner - Auto-Detect the Right Rate by Scoring Printability  `scripts:hardware:uart-baud-scanner`

Plus 64 writeups and reference pages: `ctfbrain search "" -c hardware -t writeup -n 200`

<a id="blockchain"></a>

## Blockchain

*Solidity, EVM, DeFi, Foundry*

`writeup` 47  `reference` 23  `technique` 16  `cheatsheet` 3  `script` 2  `tool` 1

Common tags: `blockchain` `solidity` `foundry` `ctf-writeup` `evm` `2024` `chinese` `ctf-wiki` `smart-contract` `zh` `web3py` `cast` `ethereum` `attacks` `delegatecall` `justctf-2024-teaser` `xor` `2026` `hacktricks` `integer-overflow` `proof-of-work` `author-solution`

**cheatsheet** (3)

- Solidity Vulnerability Checklist - Ordered by CTF Win Rate  `cheatsheets:blockchain:solidity-vuln-checklist`
- Foundry - cast / forge / anvil Cheatsheet  `cheatsheets:blockchain:foundry-cast-cheatsheet`
- web3.py Cheatsheet - Connect, Sign, Send, Decode  `cheatsheets:blockchain:web3py-cheatsheet`

**technique** (16)

- Get Abi (Blockchain)  `techniques:blockchain:notes-blockchain-get-abi-md`
- Access Control Failures - Missing Modifiers, tx.origin, Uninitialized Proxies · easy  `techniques:blockchain:access-control`
- Integer Overflow and Underflow - Pre-0.8 Wrapping and unchecked Blocks · easy  `techniques:blockchain:integer-overflow`
- Integer Overflow and Underflow (CTF Wiki) · medium  `techniques:blockchain:ext-ctf-wiki-ethereum-attacks-overflow-underflow`
- Price Oracle Manipulation and Flash Loans · hard  `techniques:blockchain:oracle-flashloan-manipulation`
- delegatecall and Storage Collision - Proxies, Libraries and selfdestruct · medium  `techniques:blockchain:delegatecall-storage-collision`
- Gas and Denial of Service - Unbounded Loops, Griefing and Force-Fed Ether · medium  `techniques:blockchain:gas-and-dos`
- EVM Bytecode Puzzles - Disassembly, Decompilation and CREATE2 Address Prediction · hard  `techniques:blockchain:evm-bytecode-and-create2`
- Writing the Attacker Contract - Constructor Tricks, CREATE2 Mining, Multicall · medium  `techniques:blockchain:attacker-contract-patterns`
- Non-EVM Chains - Solana, Cosmos and Move Bug Classes · hard  `techniques:blockchain:non-evm-chains`
- Bad Randomness - Predicting block.timestamp, blockhash and prevrandao · easy  `techniques:blockchain:bad-randomness`
- Reentrancy - Single-Function, Cross-Function, Read-Only and Callback · medium  `techniques:blockchain:reentrancy`
- Signature Bugs - Replay, ECDSA Malleability, ecrecover(0) and EIP-712 Confusion · medium  `techniques:blockchain:signature-replay-malleability`
- Random Notes (Blockchain)  `techniques:blockchain:notes-blockchain-random-notes-md`
- *...and 2 more: `ctfbrain search "" -c blockchain -t technique -n 200`*

**script** (2)

- EVM Storage Dumper - Slot Scanner and Mapping/Array Resolver  `scripts:blockchain:storage-dumper`
- EVM Solve Templates - Foundry Solve.s.sol and web3.py  `scripts:blockchain:solve-template`

**tool** (1)

- Tool - Foundry (cast / forge / anvil)  `tools:foundry-cast`

Plus 70 writeups and reference pages: `ctfbrain search "" -c blockchain -t writeup -n 200`

<a id="cloud"></a>

## Cloud

*K8s, containers, AWS/GCP/Azure, CI/CD*

`writeup` 10  `technique` 9  `cheatsheet` 3  `script` 1

Common tags: `cloud` `ctf-writeup` `enumeration` `kubernetes` `namespace` `secrets` `2024` `aws` `azure` `imds` `metadata` `s3` `service-account` `capabilities` `cloud-security` `container` `docker` `docker-sock` `iam` `jwt` `kubectl` `lambda`

**cheatsheet** (3)

- AWS CLI Cheatsheet - Enumeration After You Get Keys  `cheatsheets:cloud:aws-cli-cheatsheet`
- Container Detection & Isolation Cheatsheet  `cheatsheets:cloud:container-escape-cheatsheet`
- Kubernetes Cheatsheet - kubectl Enumeration, In-Pod Recon and RBAC  `cheatsheets:cloud:kubernetes-cheatsheet`

**technique** (9)

- AWS Post-Credential Enumeration and Privilege-Escalation Paths · medium  `techniques:cloud:aws-enumeration-privesc`
- BaaS Misconfiguration - Firebase and Supabase Open Rules and Anonymous Access · easy  `techniques:cloud:baas-firebase-supabase`
- CI/CD - GitHub Actions Injection, Self-Hosted Runners, OIDC and Secret Leakage · medium  `techniques:cloud:cicd-attacks`
- Container Isolation Failures - Recognising Escape-Prone Configurations · medium  `techniques:cloud:container-escape`
- Docker Image Forensics - Layers, History and Secrets in the Filesystem · easy  `techniques:cloud:docker-image-analysis`
- Kubernetes CTF - In-Pod Enumeration, Service Accounts and RBAC Probing · medium  `techniques:cloud:kubernetes-attacks`
- Cloud Metadata Services - IMDSv1/v2, GCP, Azure and Credential Use · easy  `techniques:cloud:cloud-metadata-ssrf`
- Serverless - Lambda / Cloud Functions Env Leakage, Source Recovery, Handler Injection · medium  `techniques:cloud:serverless-attacks`
- Object Storage Misconfiguration - S3, GCS and Azure Blob · easy  `techniques:cloud:object-storage-misconfig`

**script** (1)

- In-Container Environment Recon - Bash Fingerprint + Python Reporter  `scripts:cloud:cloud-enum-script`

Plus 10 writeups and reference pages: `ctfbrain search "" -c cloud -t writeup -n 200`

## Where the content came from

| Source | Documents |
|---|---:|
| HackTricks | 494 |
| CTF Wiki | 254 |
| Dvd848/CTFs | 130 |
| Personal notes | 128 |
| OWASP WSTG | 125 |
| TFNS/writeups | 123 |
| perfectblue/ctf-writeups | 114 |
| ljagiello/ctf-skills | 109 |
| sixstars/ctf | 88 |
| nobodyisnobody/write-ups | 79 |
| Adamkadaban/CTFs | 78 |
| balsn/ctf_writeup | 72 |
| jvdsn/crypto-attacks | 71 |
| arkark/my-ctf-challenges | 71 |
| baumroll0928-spec/myRepository | 70 |
| PayloadsAllTheThings | 67 |
| hackthebox/cyber-apocalypse-2024 | 66 |
| hackthebox/cyber-apocalypse-2025 | 65 |
| susers/Writeups | 55 |
| bl4de/ctf | 53 |
| RsaCtfTool/RsaCtfTool | 45 |
| project-sekai-ctf/sekaictf-2023 | 30 |
| shellphish/how2heap | 25 |
| project-sekai-ctf/sekaictf-2022 | 25 |
| minaminao/my-ctf-challenges | 25 |

Documents with no `source:` were written for this knowledge base directly.
Provenance for mirrors and vendored code is in
[vendor/PROVENANCE.md](../vendor/PROVENANCE.md) and
[content/reference/ext-CORPORA-PROVENANCE.md](../content/reference/ext-CORPORA-PROVENANCE.md).
