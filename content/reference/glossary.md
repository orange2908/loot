---
title: "Reference - CTF Glossary"
category: misc
subcategory: glossary
type: reference
tags: [glossary, jargon, terminology, definitions, what-does-this-mean, acronyms, slang, ctf-terms, crypto-terms, pwn-terms, web-terms, forensics-terms, unfamiliar-word]
summary: "Definitions for the jargon a CTF player runs into, from competition terms to attack names, so an unfamiliar word lands somewhere useful."
related: [ctf-start, stuck, attack-surface-by-primitive]
---

## Competition and process

| Term | Meaning |
|---|---|
| **CTF** | Capture The Flag. A security competition where you find secret strings ("flags") by solving challenges |
| **Jeopardy** | The common format: independent challenges in categories, each worth points |
| **Attack-Defense (A/D)** | Each team runs identical vulnerable services; you patch yours and exploit others' |
| **King of the Hill (KotH)** | Teams compete to hold control of a shared machine |
| **Boot2root** | A full machine you compromise from the network to root |
| **Flag** | The secret string that proves you solved a challenge, usually `xxx{...}` |
| **First blood** | The first solve of a challenge; often awarded bonus points or bragging rights |
| **Dynamic scoring** | A challenge's point value decreases as more teams solve it |
| **CTFtime** | The community site that indexes CTF events, ratings and writeups |
| **Writeup** | A post-event explanation of how a challenge was solved |
| **Handout** | The files given to you with a challenge |
| **Infra** | The competition's hosting; "infra is down" means the service, not your exploit, is broken |
| **Guessy** | A challenge whose solution requires guessing the author's intent rather than reasoning. A criticism |
| **Baby / Warmup** | An intentionally easy challenge |
| **Troll** | A challenge designed to waste your time |
| **Rev** / **Pwn** / **Crypto** / **Forensics** / **Stego** / **Misc** / **OSINT** | the standard challenge categories |
| **Sanity check** | A freebie challenge whose flag is in the description, to verify submission works |
| **Scoreboard freeze** | Scores hidden for the last hours to keep the ending tense |
| **Flag hoarding** | Delaying submissions to hide your progress. Often against the rules |
| **Shared flag** | Submitting a flag obtained from another team. Always against the rules |
| **PoW** | Proof of work; a computational gate in front of a service to limit abuse |
| **Netcat / nc** | The tool used to connect to a raw TCP challenge service |
| **Docker handout** | A `Dockerfile`/`docker-compose.yml` that lets you run the challenge locally, identical to remote |
| **Local vs remote** | Your copy of the challenge vs the scored instance. Exploits must work on remote |

## General security

| Term | Meaning |
|---|---|
| **Primitive** | A capability an attacker has gained (arbitrary read, arbitrary write, one free) |
| **Gadget** | A small reusable piece of code or data used as a building block in an exploit |
| **Chain** | Combining several weak primitives into a strong one |
| **Sink** | A dangerous function that user data reaches (`eval`, `system`, `query`) |
| **Source** | Where untrusted data enters the program |
| **Taint** | Tracking untrusted data from source to sink |
| **Oracle** | Anything that answers a yes/no question about a secret; the basis of most crypto attacks |
| **Side channel** | Information leaked by timing, power, cache behaviour or error messages, not by the output |
| **TOCTOU** | Time-of-check to time-of-use; a race between validating something and using it |
| **PoC** | Proof of concept; a minimal demonstration that the bug is real |
| **RCE** | Remote code execution |
| **LPE** / **privesc** | Local privilege escalation |
| **Pivot** | Using a compromised host to reach a network you could not reach directly |
| **Exfil** | Exfiltration; getting data out of a system |
| **OOB** | Out-of-band; using a separate channel (DNS, HTTP callback) to confirm a blind bug |
| **Blind** | A vulnerability whose output you cannot see directly, only infer |
| **Polyglot** | A file that is valid in two or more formats simultaneously |
| **Magic bytes** | The signature at the start of a file that identifies its format |
| **Entropy** | A measure of randomness; high entropy means compressed or encrypted |
| **Canary / cookie** | A random value placed to detect tampering (stack canary) |
| **Sandbox escape** | Breaking out of a restricted execution environment |
| **Jail** | A restricted interpreter environment (pyjail, bashjail) you must escape |
| **GTFOBins / LOLBAS** | Catalogues of legitimate binaries abusable for privilege escalation (Unix / Windows) |

## Crypto

| Term | Meaning |
|---|---|
| **Plaintext / ciphertext** | The message before and after encryption |
| **Symmetric** | Same key encrypts and decrypts (AES, ChaCha20) |
| **Asymmetric / public-key** | Different keys (RSA, ECC, ElGamal) |
| **Block cipher** | Encrypts fixed-size blocks (AES: 16 bytes) |
| **Stream cipher** | Generates a keystream XORed with the plaintext (RC4, ChaCha20) |
| **Mode of operation** | How a block cipher handles data longer than one block: ECB, CBC, CTR, GCM, CFB, OFB |
| **ECB** | Electronic Codebook: each block encrypted independently. Identical plaintext blocks give identical ciphertext blocks. Broken by design |
| **CBC** | Cipher Block Chaining: each block XORed with the previous ciphertext. Vulnerable to padding oracles and bit flipping |
| **CTR** | Counter mode: turns a block cipher into a stream cipher. Nonce reuse is catastrophic |
| **GCM** | Galois/Counter Mode: CTR plus authentication. Nonce reuse leaks the auth key |
| **IV** | Initialisation vector; the per-message randomness. Must be unpredictable for CBC |
| **Nonce** | Number used once. Reusing one breaks CTR, GCM, ECDSA and more |
| **Padding** | Bytes added to reach a block boundary. PKCS#7 is the common scheme |
| **Padding oracle** | A service that reveals whether decryption produced valid padding; lets you decrypt everything |
| **MAC** | Message authentication code; proves integrity and authenticity with a shared key |
| **HMAC** | A MAC construction built from a hash function; immune to length extension |
| **AEAD** | Authenticated Encryption with Associated Data (GCM, ChaCha20-Poly1305) |
| **Length extension** | Given `H(secret\|\|m)` and `len(secret)`, compute `H(secret\|\|m\|\|pad\|\|m2)`. Affects MD5, SHA-1, SHA-2 |
| **Collision** | Two inputs with the same hash |
| **Preimage** | An input producing a given hash |
| **Birthday attack** | Finding a collision in about `sqrt(N)` work instead of `N` |
| **Rainbow table** | Precomputed hash chains for reversing unsalted hashes |
| **Salt** | Random data added before hashing so identical passwords hash differently |
| **KDF** | Key derivation function (PBKDF2, scrypt, argon2); deliberately slow |
| **RSA** | Public-key scheme based on the difficulty of factoring `n = p*q` |
| **Modulus / n** | The public composite in RSA |
| **Public exponent / e** | Usually 65537, sometimes 3 (which enables small-root attacks) |
| **Private exponent / d** | `e^-1 mod phi(n)` |
| **phi / totient** | `phi(n)` counts the integers below `n` coprime to it; for `n=pq` it is `(p-1)(q-1)` |
| **Textbook RSA** | RSA without padding; deterministic and malleable, so always attackable |
| **Coppersmith** | A lattice method for finding small roots of polynomials mod `n`; underlies many partial-information attacks |
| **Wiener's attack** | Recovers a small private exponent `d` using continued fractions |
| **Hastad broadcast** | Same message sent to `e` recipients with small `e` -> CRT -> integer root |
| **Common modulus** | Same `n`, two coprime `e` -> recover the message without factoring |
| **CRT** | Chinese Remainder Theorem; combines congruences over coprime moduli |
| **Fermat factorisation** | Fast when `p` and `q` are close |
| **Smooth** | An integer whose prime factors are all small. Smooth `p-1` enables Pollard p-1; a smooth group order enables Pohlig-Hellman |
| **DLOG / DLP** | Discrete logarithm problem: find `x` given `g^x` |
| **ECC** | Elliptic curve cryptography |
| **ECDSA** | The elliptic-curve signature scheme; reusing or biasing the nonce `k` leaks the private key |
| **Pohlig-Hellman** | Solves the DLOG efficiently when the group order is smooth |
| **BSGS** | Baby-step giant-step; a `sqrt(n)` time-memory DLOG algorithm |
| **Lattice / LLL** | Lattice basis reduction; the workhorse behind Coppersmith, HNP and knapsack attacks |
| **HNP** | Hidden Number Problem; recovers a secret from partial information about many multiples of it |
| **QR / quadratic residue** | A value that is a square modulo `p` |
| **Tonelli-Shanks** | Algorithm for square roots modulo a prime |
| **Legendre / Jacobi symbol** | Indicators of quadratic residuosity; Jacobi is computable without factoring |
| **LCG** | Linear congruential generator; a weak PRNG, invertible from a few outputs |
| **MT19937** | The Mersenne Twister, Python's `random`; 624 consecutive 32-bit outputs recover the full state |
| **LFSR** | Linear feedback shift register; recovered from `2n` output bits by Berlekamp-Massey |
| **Crib dragging** | Guessing a known plaintext fragment against `p1 ^ p2` to recover both |
| **Malleable** | A ciphertext that can be modified into a predictable plaintext change |
| **Blinding** | Multiplying a ciphertext by `r^e` to disguise it from a decryption oracle |
| **Bleichenbacher** | The PKCS#1 v1.5 padding oracle attack ('98) and the low-exponent signature forgery ('06) |
| **Vigenere / Caesar / substitution** | Classical ciphers, solved by frequency analysis and key-length detection |
| **Kasiski / index of coincidence** | Methods for finding a Vigenere key length |
| **One-time pad** | Perfectly secure if the key is random, as long as the message, and used once. Reuse breaks it completely |

## Binary exploitation (pwn)

| Term | Meaning |
|---|---|
| **Buffer overflow** | Writing past the end of a buffer, corrupting adjacent memory |
| **Stack smashing** | Overflowing a stack buffer to overwrite the saved return address |
| **Saved RIP / return address** | The address execution resumes at when a function returns; the classic overwrite target |
| **Canary** | A random value between locals and the return address; checked on return |
| **NX / DEP** | Non-executable stack and heap; forces ROP instead of shellcode |
| **ASLR** | Address space layout randomisation; base addresses change per run |
| **PIE** | Position-independent executable; the binary itself is also randomised |
| **RELRO** | Relocation read-only. Partial leaves the GOT writable; Full makes it read-only |
| **GOT / PLT** | Global Offset Table and Procedure Linkage Table; the indirection used for dynamic library calls. A writable GOT entry is a control-flow hijack |
| **ROP** | Return-oriented programming; chaining short instruction sequences ending in `ret` |
| **Gadget** | One such sequence, e.g. `pop rdi; ret` |
| **ret2libc** | Returning into a libc function such as `system` |
| **ret2win** | Returning to a function the challenge already provides that prints the flag |
| **ret2csu** | Using `__libc_csu_init` gadgets to control rdx/rsi/rdi when no direct gadget exists |
| **ret2dlresolve** | Forging dynamic-linker structures to resolve and call an arbitrary symbol without a leak |
| **SROP** | Sigreturn-oriented programming; a fake signal frame gives full register control |
| **Stack pivot** | Moving `rsp` to a buffer you control so a longer chain fits |
| **one_gadget** | A single libc address that spawns a shell if certain register/memory constraints hold |
| **Format string bug (FSB)** | `printf(user_input)`; `%p`/`%s` read memory, `%n` writes it |
| **Shellcode** | Raw machine code, usually spawning a shell |
| **Egghunter** | Small shellcode that searches memory for a larger payload |
| **Heap** | Dynamically allocated memory managed by `malloc`/`free` |
| **Chunk** | One heap allocation, with a header containing its size and flags |
| **Bin** | A free list: tcache, fastbin, unsorted, small, large |
| **tcache** | Per-thread cache of free chunks, introduced in glibc 2.26. The main modern exploitation target |
| **tcache poisoning** | Overwriting a freed chunk's `fd` so the next `malloc` returns an address you chose |
| **Safe linking** | glibc 2.32+ mangles `fd` pointers as `ptr ^ (addr >> 12)`; requires a heap leak to defeat |
| **UAF** | Use after free; a dangling pointer to freed memory |
| **Double free** | Freeing the same chunk twice; corrupts the free list |
| **House of X** | A family of named heap techniques (Force, Spirit, Einherjar, Orange, Apple, Cat, Banana) |
| **Unsorted bin leak** | Reading a freed chunk's `fd`/`bk`, which point into `main_arena` in libc |
| **main_arena** | The primary heap management structure in libc; a fixed offset from the libc base |
| **`__free_hook` / `__malloc_hook`** | Function pointers in libc called by `free`/`malloc`; removed in glibc 2.34 |
| **FSOP** | File Stream Oriented Programming; forging `FILE` structures and vtables (`_IO_2_1_stdout_`) |
| **Off-by-one / poison null byte** | A single-byte overflow, typically a null, that corrupts a chunk size |
| **Seccomp** | A syscall filter; commonly blocks `execve`, forcing open/read/write shellcode |
| **ORW** | open-read-write shellcode, used under seccomp |
| **checksec** | The tool that prints a binary's protections |
| **pwntools** | The Python exploit development framework |
| **libc-database** | A service/tool that identifies the exact libc from leaked symbol addresses |
| **Cyclic pattern** | De Bruijn sequence used to find the exact overflow offset |

## Reverse engineering

| Term | Meaning |
|---|---|
| **Disassembly** | Machine code rendered as assembly |
| **Decompilation** | Machine code rendered as pseudo-C (Ghidra, IDA, Binary Ninja) |
| **Stripped** | Symbol names removed from the binary |
| **Packed** | The real code is compressed/encrypted and unpacked at runtime (UPX and friends) |
| **OEP** | Original entry point; where execution goes after unpacking |
| **Obfuscation** | Deliberately unreadable code: control-flow flattening, opaque predicates, string encryption |
| **VM obfuscation** | The logic is compiled to a custom bytecode interpreted by a loop in the binary |
| **Anti-debug** | Checks that detect a debugger (`ptrace`, timing, `TracerPid`) |
| **Patching** | Editing the binary to skip a check |
| **Symbolic execution** | Running with symbolic rather than concrete inputs to solve for a path (angr) |
| **SMT solver** | A constraint solver such as z3, used to invert a check |
| **State explosion** | Symbolic execution failing because the number of paths grows too fast |
| **Xref** | Cross-reference; every place that reads a value or calls a function |
| **Mangled name** | A C++/Rust symbol encoding types into the name; demangle with `c++filt` |
| **IL / IR** | Intermediate representation used by a decompiler |
| **Keygen / keygenme** | A challenge asking you to write a valid serial-number generator |
| **Crackme** | A challenge asking you to find the correct input |

## Web

| Term | Meaning |
|---|---|
| **XSS** | Cross-site scripting; your JavaScript runs in another user's browser. Reflected, stored, or DOM-based |
| **CSRF / XSRF** | Forcing a logged-in user's browser to make a request |
| **SSRF** | Server-side request forgery; the server fetches a URL you control |
| **SQLi** | SQL injection |
| **NoSQLi** | Injection into MongoDB-style query objects (`$ne`, `$regex`, `$where`) |
| **LFI / RFI** | Local / remote file inclusion |
| **Path traversal** | `../` to escape an intended directory |
| **SSTI** | Server-side template injection; `{{7*7}}` returning `49` is the classic test |
| **XXE** | XML external entity; makes an XML parser read files or make requests |
| **IDOR** | Insecure direct object reference; changing an id to access someone else's data |
| **BOLA / BFLA** | Broken object-level / function-level authorisation; the API names for IDOR and missing auth |
| **Mass assignment** | The server binds every JSON field to a model, so you can set `role: admin` |
| **Prototype pollution** | Polluting `Object.prototype` in JavaScript so unrelated code inherits your properties |
| **Deserialization** | Rebuilding objects from attacker data; often direct RCE |
| **Gadget chain** | The sequence of classes abused in a deserialization exploit (ysoserial, phpggc) |
| **JWT** | JSON Web Token; three base64url parts. Attacked via `alg:none`, weak secrets, `kid`, `jku` |
| **CORS** | Cross-origin resource sharing; misconfiguration lets an attacker origin read responses |
| **CSP** | Content Security Policy; restricts what scripts may run |
| **SameSite** | A cookie attribute controlling cross-site sending; the main CSRF defence |
| **Open redirect** | A redirect to an attacker-supplied URL; used in OAuth token theft |
| **Host header injection** | Abusing a trusted `Host` for password-reset poisoning or cache poisoning |
| **Request smuggling** | Front-end and back-end disagree on request boundaries (CL.TE, TE.CL, H2.CL) |
| **Cache poisoning / deception** | Making a shared cache store attacker content, or store a victim's private page |
| **Unkeyed input** | A request component the cache ignores when computing its key; the basis of poisoning |
| **Race condition** | Two requests interleaving to bypass a check (limit-overrun, TOCTOU) |
| **Type juggling** | Loose comparison in PHP/JS treating different types as equal (`"0e1" == "0e2"`) |
| **WAF** | Web application firewall; a filter to bypass |
| **Webshell** | An uploaded script giving command execution through the web server |
| **Zip slip** | A path-traversal filename inside an archive that writes outside the extraction directory |
| **Subdomain takeover** | Claiming a dangling DNS record pointing at an unclaimed service |
| **Burp** | Burp Suite, the intercepting HTTP proxy |
| **Collaborator / interactsh** | Out-of-band services for confirming blind SSRF/XXE/injection |

## Forensics, stego and OSINT

| Term | Meaning |
|---|---|
| **pcap** | A packet capture file |
| **Follow stream** | Reassembling one TCP conversation in Wireshark |
| **Carving** | Recovering files from raw data by scanning for signatures (`foremost`, `binwalk`, `photorec`) |
| **Slack space** | Unused bytes at the end of a filesystem cluster that may hold old data |
| **Unallocated space** | Deleted-but-not-overwritten disk regions |
| **MFT** | NTFS Master File Table; the source of a full filesystem timeline |
| **Prefetch** | Windows execution artefacts proving a program ran |
| **Registry hive** | A Windows configuration database file (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`) |
| **EVTX** | The Windows event log format |
| **Volatility** | The standard memory-forensics framework |
| **Profile / symbol table** | The OS-version metadata Volatility needs to parse a dump |
| **Timeline** | Events ordered by time across all artefacts (`plaso`, `mactime`) |
| **LSB stego** | Hiding data in the least significant bits of pixel or sample values |
| **Bit plane** | The image formed by one bit position across all pixels |
| **Spectrogram** | A frequency-over-time view of audio; hidden text is often drawn in it |
| **zsteg / steghide / outguess** | The standard stego extraction tools for PNG/BMP and JPEG |
| **Magic / libmagic** | The signature database behind the `file` command |
| **EXIF** | Image metadata; often contains GPS coordinates, the camera, and comments |
| **Geolocation** | Determining where a photo was taken, from EXIF or from visual clues |
| **OSINT** | Open-source intelligence; solving with publicly available information |
| **Pivot (OSINT)** | Moving from one identifier (a username, an email, an image) to another |
| **Reverse image search** | Finding the origin of an image |
| **Wayback / archive** | Historical snapshots of a website, often holding deleted content |

## Miscellaneous

| Term | Meaning |
|---|---|
| **Base64 / base32 / base58** | Binary-to-text encodings, not encryption |
| **ROT13** | A Caesar shift of 13; its own inverse |
| **XOR** | Exclusive or; `a ^ b ^ b == a`, which makes it a reversible "encryption" |
| **Endianness** | Byte order; little-endian (x86) stores the least significant byte first |
| **Null byte** | `\x00`; terminates C strings and often truncates filters |
| **Off-by-one** | A boundary error of exactly one element |
| **Integer overflow** | Arithmetic wrapping past the type's maximum |
| **Signedness bug** | A negative value passing an unsigned size check |
| **Fuzzing** | Feeding random or mutated inputs to find crashes (`afl++`, `libfuzzer`) |
| **Emulation** | Running a binary for a different architecture (`qemu-user`) |
| **Cross-compilation** | Building for a different architecture |
| **Shell upgrade** | Turning a raw reverse shell into a full interactive TTY |
| **Reverse shell / bind shell** | A shell that connects out to you / listens for you |
| **C2** | Command and control infrastructure |
| **IOC** | Indicator of compromise |
| **CVE** | A public vulnerability identifier, e.g. CVE-2021-44228 (Log4Shell) |
| **0day / nday** | An unpatched vulnerability / a known, patched one |
| **PoC\|GTFO** | "Proof of concept or get lost"; also a well-known security zine |
| **Sage / SageMath** | A mathematics system that includes most of the algorithms CTF crypto needs |
| **z3** | Microsoft Research's SMT solver |
| **angr** | A binary analysis framework with symbolic execution |
| **Frida** | A dynamic instrumentation toolkit for hooking running processes |
| **GTFOBins** | A catalogue of Unix binaries abusable to bypass restrictions |
| **Pastebin-style dump** | Where CTF authors sometimes hide the second half of a challenge |
| **Rubber duck** | Explaining your problem aloud to find the answer yourself |

If a term you searched for is not here, try `ctfbrain search <term>` against the technique and cheatsheet files, or start from `ctfbrain search stuck`.
