"""Query expansion vocabulary.

A CTF player types the symptom, not the file name.  They type "gcd" when they
mean "these two moduli share a prime", or "penguin" when they mean ECB.  This
module maps what gets typed onto the vocabulary the corpus is actually written
in, so a one-word query lands on the right page.

Every entry is `trigger -> extra terms OR-ed into the FTS query`.  Triggers are
matched on whole, lowercased, punctuation-stripped query terms.
"""
from __future__ import annotations

import re

# Canonical concept expansions.  Keep values lowercase; they are fed to FTS5.
SYNONYMS: dict[str, list[str]] = {
    # ------------------------------------------------------------ crypto: RSA
    "gcd": ["common-factor", "batch-gcd", "shared-prime", "euclidean", "common-modulus", "bezout", "factoring"],
    "euclid": ["gcd", "extended-euclidean", "bezout", "modular-inverse"],
    "phi": ["totient", "euler", "known-phi", "lambda", "carmichael"],
    "totient": ["phi", "euler", "carmichael"],
    "rsa": ["modulus", "public-exponent", "private-exponent", "factoring", "coppersmith"],
    "smalle": ["small-e", "cube-root", "low-exponent", "hastad"],
    "cuberoot": ["cube-root", "nth-root", "small-e"],
    "wiener": ["small-d", "continued-fraction", "convergents", "boneh-durfee"],
    "smalld": ["wiener", "boneh-durfee", "small-d"],
    "hastad": ["broadcast", "crt", "chinese-remainder", "small-e"],
    "broadcast": ["hastad", "crt", "chinese-remainder"],
    "crt": ["chinese-remainder", "chinese-remainder-theorem", "garner"],
    "coppersmith": ["small-roots", "lattice", "lll", "stereotyped", "partial-p", "howgrave-graham"],
    "factordb": ["factoring", "factorisation", "factorization"],
    "factorise": ["factoring", "factorization", "factordb", "fermat", "pollard"],
    "factorize": ["factoring", "factorisation", "factordb", "fermat", "pollard"],
    "closeprimes": ["fermat", "close-primes", "p-q-close"],
    "fermat": ["close-primes", "factoring", "fermat-factorization"],
    "pollard": ["rho", "p-minus-1", "factoring", "ecm"],
    "roca": ["weak-keygen", "infineon", "coppersmith"],
    "paritY": ["lsb-oracle", "parity-oracle", "decryption-oracle"],
    "lsb": ["least-significant-bit", "parity", "oracle", "bit-plane"],
    "parity": ["lsb-oracle", "parity-oracle", "bit"],

    # ------------------------------------------------------ crypto: symmetric
    "ecb": ["electronic-codebook", "penguin", "block-shuffle", "cut-and-paste", "byte-at-a-time"],
    "penguin": ["ecb", "electronic-codebook"],
    "cbc": ["cipher-block-chaining", "bit-flipping", "padding-oracle", "iv"],
    "paddingoracle": ["padding-oracle", "cbc", "pkcs7", "vaudenay"],
    "bitflip": ["bit-flipping", "malleability", "cbc"],
    "ctr": ["counter-mode", "keystream", "nonce-reuse", "stream"],
    "gcm": ["galois-counter", "forbidden-attack", "nonce-reuse", "authentication-tag", "ghash"],
    "noncereuse": ["nonce-reuse", "keystream-reuse", "forbidden-attack", "ecdsa"],
    "xor": ["exclusive-or", "one-time-pad", "crib-drag", "repeating-key", "vernam"],
    "otp": ["one-time-pad", "xor", "key-reuse", "many-time-pad"],
    "cribdrag": ["crib-drag", "xor", "many-time-pad"],
    "lengthextension": ["length-extension", "merkle-damgard", "hashpump", "sha1", "md5"],
    "hashpump": ["length-extension", "merkle-damgard"],
    "merkle": ["merkle-damgard", "length-extension"],
    "collision": ["hash-collision", "birthday", "chosen-prefix", "md5"],
    "magichash": ["magic-hash", "type-juggling", "0e", "php"],

    # ------------------------------------------------------- crypto: advanced
    "lll": ["lattice", "lattice-reduction", "fpylll", "babai", "cvp", "svp", "reduction"],
    "lattice": ["lll", "bkz", "cvp", "svp", "babai", "hidden-number-problem", "knapsack"],
    "hnp": ["hidden-number-problem", "lattice", "lll", "biased-nonce", "ecdsa"],
    "knapsack": ["subset-sum", "merkle-hellman", "lattice", "low-density"],
    "ecc": ["elliptic-curve", "ecdsa", "ecdh", "point-multiplication", "weierstrass"],
    "ecdsa": ["signature", "nonce", "biased-nonce", "nonce-reuse", "hnp", "malleability"],
    "smart": ["anomalous", "smarts-attack", "p-adic", "elliptic-curve"],
    "anomalous": ["smart", "trace-one", "elliptic-curve"],
    "mov": ["pairing", "embedding-degree", "frey-ruck", "elliptic-curve"],
    "singular": ["singular-curve", "cusp", "node", "elliptic-curve"],
    "invalidcurve": ["invalid-curve", "small-subgroup", "ecdh"],
    "dlp": ["discrete-log", "discrete-logarithm", "pohlig-hellman", "bsgs", "baby-step-giant-step", "index-calculus"],
    "discretelog": ["dlp", "discrete-logarithm", "pohlig-hellman", "bsgs"],
    "pohlig": ["pohlig-hellman", "smooth-order", "dlp"],
    "bsgs": ["baby-step-giant-step", "dlp", "meet-in-the-middle"],
    "diffiehellman": ["diffie-hellman", "dh", "small-subgroup", "parameter-injection"],
    "lwe": ["learning-with-errors", "lattice", "post-quantum", "ntru"],
    "isogeny": ["sidh", "sike", "castryck-decru", "post-quantum"],

    # ------------------------------------------------------------ crypto: PRNG
    "mt19937": ["mersenne-twister", "untemper", "state-recovery", "randcrack", "predict"],
    "mersenne": ["mt19937", "untemper", "state-recovery"],
    "prng": ["random", "rng", "seed", "predictable", "state-recovery"],
    "rng": ["prng", "random", "seed"],
    "lcg": ["linear-congruential", "truncated-lcg", "state-recovery"],
    "seed": ["prng", "srand", "time-based-seed", "bruteforce"],
    "random": ["prng", "rng", "predictable", "getrandbits"],

    # ---------------------------------------------------------- crypto: classic
    "vigenere": ["kasiski", "index-of-coincidence", "friedman", "polyalphabetic"],
    "caesar": ["rot13", "shift-cipher", "rot-n", "affine"],
    "rot13": ["caesar", "shift-cipher", "rot-n"],
    "substitution": ["monoalphabetic", "frequency-analysis", "quipqiup", "hill-climbing"],
    "frequency": ["frequency-analysis", "chi-squared", "index-of-coincidence"],
    "ioc": ["index-of-coincidence", "kasiski", "vigenere"],
    "cipher": ["encryption", "classical", "crypto", "decrypt"],

    # -------------------------------------------------------------------- web
    "sqli": ["sql-injection", "union-select", "blind", "sqlmap", "boolean-based", "time-based"],
    "sqlinjection": ["sqli", "union-select", "sqlmap"],
    "xss": ["cross-site-scripting", "javascript-injection", "csp-bypass", "dom-xss", "payload"],
    "csp": ["content-security-policy", "csp-bypass", "nonce", "jsonp", "unsafe-eval"],
    "ssrf": ["server-side-request-forgery", "metadata", "gopher", "internal", "169.254.169.254"],
    "lfi": ["local-file-inclusion", "path-traversal", "directory-traversal", "php-filter", "log-poisoning"],
    "rfi": ["remote-file-inclusion", "lfi"],
    "traversal": ["path-traversal", "directory-traversal", "lfi", "dot-dot-slash"],
    "ssti": ["server-side-template-injection", "jinja2", "twig", "freemarker", "template"],
    "jinja": ["jinja2", "ssti", "flask", "template-injection"],
    "rce": ["remote-code-execution", "command-injection", "code-execution", "shell"],
    "cmdi": ["command-injection", "os-command-injection", "shell-injection"],
    "xxe": ["xml-external-entity", "external-dtd", "billion-laughs", "xinclude"],
    "deser": ["deserialization", "unserialize", "pickle", "gadget-chain", "ysoserial"],
    "deserialization": ["unserialize", "pickle", "gadget-chain", "ysoserial", "phpggc", "marshal"],
    "pickle": ["deserialization", "reduce", "python", "rce"],
    "jwt": ["json-web-token", "alg-none", "hs256", "rs256", "key-confusion", "jku", "kid"],
    "protopollution": ["prototype-pollution", "__proto__", "constructor"],
    "prototype": ["prototype-pollution", "__proto__", "constructor", "merge"],
    "graphql": ["introspection", "batching", "alias", "query"],
    "smuggling": ["request-smuggling", "cl-te", "te-cl", "desync"],
    "desync": ["request-smuggling", "cl-te", "te-cl"],
    "race": ["race-condition", "toctou", "single-packet-attack", "limit-overrun"],
    "toctou": ["race-condition", "time-of-check"],
    "upload": ["file-upload", "webshell", "extension-bypass", "magic-bytes", "polyglot"],
    "webshell": ["file-upload", "rce", "backdoor", "shell"],
    "typejuggling": ["type-juggling", "loose-comparison", "php", "magic-hash"],
    "waf": ["bypass", "filter-bypass", "blacklist-bypass", "encoding"],
    "bypass": ["filter-bypass", "waf", "blacklist", "evasion"],
    "cors": ["cross-origin", "access-control-allow-origin", "origin-reflection"],
    "nosqli": ["nosql-injection", "mongodb", "operator-injection", "$ne", "$regex"],

    # -------------------------------------------------------------------- pwn
    "bof": ["buffer-overflow", "stack-overflow", "overflow"],
    "overflow": ["buffer-overflow", "stack-overflow", "heap-overflow", "integer-overflow"],
    "rop": ["return-oriented-programming", "gadget", "chain", "ropgadget", "ret2libc", "srop"],
    "ret2libc": ["rop", "system", "binsh", "libc-leak", "one-gadget"],
    "ret2win": ["control-flow-hijack", "return-address", "stack-overflow"],
    "fmtstr": ["format-string", "printf", "%n", "arbitrary-write", "stack-leak"],
    "formatstring": ["fmtstr", "printf", "%n", "arbitrary-write"],
    "canary": ["stack-canary", "stack-protector", "cookie", "leak"],
    "nx": ["no-execute", "dep", "non-executable-stack", "mitigation"],
    "aslr": ["address-space-layout-randomization", "pie", "leak", "brute-force"],
    "pie": ["position-independent-executable", "aslr", "partial-overwrite"],
    "relro": ["got-overwrite", "mitigation", "full-relro", "partial-relro"],
    "got": ["global-offset-table", "got-overwrite", "plt", "relro"],
    "heap": ["malloc", "free", "chunk", "tcache", "fastbin", "glibc", "bins"],
    "tcache": ["heap", "tcache-poisoning", "safe-linking", "glibc", "double-free"],
    "uaf": ["use-after-free", "dangling-pointer", "heap"],
    "usefree": ["use-after-free", "uaf"],
    "doublefree": ["double-free", "tcache-dup", "fastbin-dup", "heap"],
    "fsop": ["file-stream-oriented-programming", "_io_file", "house-of-orange", "vtable"],
    "hook": ["free-hook", "malloc-hook", "__free_hook", "__malloc_hook"],
    "onegadget": ["one-gadget", "execve", "constraints", "libc"],
    "shellcode": ["asm", "assembly", "execve", "syscall", "shellcraft", "null-free"],
    "seccomp": ["sandbox", "filter", "orw", "open-read-write", "seccomp-tools"],
    "srop": ["sigreturn", "sigreturn-oriented-programming", "rt_sigreturn"],
    "kernel": ["kernel-pwn", "ring0", "commit-creds", "modprobe-path", "kpti", "smep"],
    "privesc": ["privilege-escalation", "suid", "sudo", "capabilities", "gtfobins"],

    # -------------------------------------------------------------------- rev
    "re": ["reverse-engineering", "reversing", "disassembly", "decompile"],
    "reversing": ["reverse-engineering", "disassembly", "decompiler", "ghidra", "ida"],
    "decompile": ["decompiler", "ghidra", "ida", "hex-rays", "retdec"],
    "angr": ["symbolic-execution", "claripy", "constraint", "solver"],
    "symbolic": ["symbolic-execution", "angr", "z3", "constraint-solving"],
    "z3": ["smt-solver", "constraint-solving", "bitvector", "satisfiability"],
    "crackme": ["keygen", "serial", "flag-checker", "license"],
    "keygen": ["crackme", "serial", "algorithm-recovery"],
    "antidebug": ["anti-debug", "ptrace", "tracerpid", "debugger-detection"],
    "packer": ["upx", "unpacking", "oep", "packed", "dump"],
    "upx": ["packer", "unpacking", "oep"],
    "obfuscation": ["deobfuscation", "control-flow-flattening", "opaque-predicate", "mba"],
    "vm": ["virtual-machine", "bytecode", "dispatch-loop", "custom-vm", "interpreter"],
    "pyc": ["python-bytecode", "decompyle", "uncompyle6", "pycdc", "marshal"],
    "pyinstaller": ["pyinstxtractor", "python-bytecode", "pyc", "frozen"],
    "wasm": ["webassembly", "wat", "wabt", "wasm2wat"],

    # -------------------------------------------------------------- forensics
    "memdump": ["memory-dump", "volatility", "ram", "memory-forensics"],
    "volatility": ["volatility3", "memory-forensics", "plugin", "pslist", "memdump"],
    "memory": ["memory-forensics", "volatility", "ram-dump", "process-dump"],
    "pcap": ["packet-capture", "wireshark", "tshark", "network-forensics", "scapy"],
    "wireshark": ["tshark", "pcap", "display-filter", "follow-stream"],
    "carving": ["file-carving", "foremost", "binwalk", "scalpel", "photorec", "magic-bytes"],
    "mft": ["ntfs", "master-file-table", "filesystem", "timestamps"],
    "registry": ["hive", "regripper", "run-keys", "shellbags", "userassist", "windows"],
    "evtx": ["event-log", "windows-logs", "event-id", "security-log"],
    "usb": ["usb-hid", "keystrokes", "capdata", "hid"],
    "hid": ["usb-hid", "keyboard", "keystrokes", "capdata"],
    "timeline": ["plaso", "log2timeline", "mactime", "super-timeline"],

    # ------------------------------------------------------------------ stego
    "stego": ["steganography", "hidden-data", "lsb", "steghide", "zsteg"],
    "steganography": ["stego", "lsb", "hidden", "zsteg", "steghide", "stegsolve"],
    "bitplane": ["bit-plane", "lsb", "stegsolve", "channel"],
    "spectrogram": ["audio", "sonic-visualiser", "waveform", "audacity"],
    "morse": ["audio", "dots-dashes", "telegraph"],
    "sstv": ["slow-scan-television", "audio", "image"],
    "exif": ["metadata", "exiftool", "gps", "xmp"],
    "metadata": ["exif", "exiftool", "properties"],
    "zerowidth": ["zero-width", "unicode", "invisible-characters", "text-stego"],
    "polyglot": ["appended-data", "multiple-formats", "magic-bytes"],
    "zipcrack": ["known-plaintext", "bkcrack", "pkzip", "password-crack"],
    "bkcrack": ["known-plaintext", "zip", "pkzip", "biham-kocher"],
    "qr": ["qr-code", "barcode", "datamatrix", "zbar"],

    # ------------------------------------------------------------------- misc
    "jail": ["sandbox-escape", "pyjail", "restricted", "escape", "filter-bypass"],
    "pyjail": ["python-jail", "sandbox-escape", "builtins", "subclasses"],
    "sandbox": ["escape", "jail", "restricted-environment", "vm2"],
    "esolang": ["brainfuck", "whitespace", "malbolge", "piet", "befunge"],
    "pow": ["proof-of-work", "hashcash", "kctf", "redpwnpow"],
    "proofofwork": ["pow", "hashcash", "kctf"],
    "gtfobins": ["suid", "sudo", "privilege-escalation", "binary-abuse"],
    "docker": ["container", "escape", "docker-sock", "privileged"],
    "container": ["docker", "escape", "namespace", "cgroup", "capabilities"],
    "kubernetes": ["k8s", "kubectl", "pod", "service-account", "rbac"],
    "k8s": ["kubernetes", "kubectl", "pod", "rbac"],
    "ad": ["active-directory", "kerberos", "bloodhound", "ntlm", "domain"],
    "kerberos": ["kerberoasting", "asreproast", "ticket", "tgt", "tgs"],
    "recon": ["enumeration", "scanning", "nmap", "discovery", "fingerprinting"],
    "enum": ["enumeration", "recon", "discovery"],
    "fuzzing": ["ffuf", "gobuster", "wordlist", "content-discovery", "wfuzz"],
    "revshell": ["reverse-shell", "bind-shell", "netcat", "listener", "pty"],
    "shell": ["reverse-shell", "rce", "command-execution", "tty"],

    # ----------------------------------------------------------------- mobile
    "apk": ["android", "jadx", "apktool", "smali", "dex", "manifest"],
    "android": ["apk", "frida", "adb", "smali", "jadx"],
    "frida": ["hook", "runtime-instrumentation", "objection", "interceptor", "javascript"],
    "pinning": ["ssl-pinning", "certificate-pinning", "bypass", "frida"],
    "ios": ["ipa", "objective-c", "swift", "frida", "jailbreak", "plist"],

    # --------------------------------------------------------------- hardware
    "firmware": ["binwalk", "squashfs", "extraction", "embedded", "flash-dump"],
    "uart": ["serial", "tx", "rx", "baud", "console"],
    "jtag": ["swd", "openocd", "debug-port", "boundary-scan"],
    "sdr": ["software-defined-radio", "rtl-sdr", "hackrf", "urh", "demodulation"],
    "rf": ["radio", "sdr", "ook", "ask", "fsk", "433mhz"],
    "sidechannel": ["side-channel", "power-analysis", "dpa", "cpa", "chipwhisperer", "timing"],
    "glitch": ["fault-injection", "voltage-glitching", "clock-glitching"],
    "canbus": ["can-bus", "automotive", "candump", "obd"],

    # ------------------------------------------------------------- blockchain
    "solidity": ["smart-contract", "evm", "ethereum", "foundry", "contract"],
    "evm": ["ethereum", "bytecode", "opcode", "solidity"],
    "reentrancy": ["reentrant", "callback", "checks-effects-interactions", "smart-contract"],
    "delegatecall": ["storage-collision", "proxy", "smart-contract"],
    "flashloan": ["flash-loan", "oracle-manipulation", "defi"],
    "foundry": ["forge", "cast", "anvil", "solidity"],

    # ------------------------------------------------------------------ cloud
    "imds": ["metadata-service", "169.254.169.254", "instance-metadata", "ssrf", "aws"],
    "metadataservice": ["imds", "169.254.169.254", "ssrf"],
    "s3": ["bucket", "aws", "object-storage", "public-bucket"],
    "iam": ["aws", "permissions", "privilege-escalation", "role", "policy"],
    "cicd": ["github-actions", "pipeline", "runner", "workflow-injection"],

    # ---------------------------------------------------------- generic intent
    "attack": ["exploit", "technique", "vulnerability", "bug"],
    "exploit": ["attack", "poc", "payload", "technique"],
    "payload": ["exploit", "injection", "poc"],
    "cheatsheet": ["reference", "commands", "quick-reference"],
    "howto": ["technique", "guide", "walkthrough"],
    "writeup": ["solution", "walkthrough", "solve"],
    "solve": ["solution", "writeup", "solver", "script"],
    "leak": ["information-disclosure", "infoleak", "disclosure"],
    "oracle": ["side-channel", "padding-oracle", "decryption-oracle", "query"],
    "bruteforce": ["brute-force", "exhaustive-search", "wordlist", "crack"],
    "crack": ["cracking", "hashcat", "john", "bruteforce", "wordlist"],
}

# Multi-word phrases the user is likely to type, mapped to terms.
PHRASES: dict[str, list[str]] = {
    "crypto attack": ["cryptanalysis", "attack", "crypto", "technique"],
    "common modulus": ["common-modulus", "same-n", "rsa"],
    "common factor": ["common-factor", "batch-gcd", "shared-prime"],
    "shared prime": ["common-factor", "batch-gcd", "gcd"],
    "padding oracle": ["padding-oracle", "cbc", "vaudenay", "pkcs7"],
    "length extension": ["length-extension", "merkle-damgard", "hashpump"],
    "nonce reuse": ["nonce-reuse", "keystream-reuse", "ecdsa", "gcm"],
    "buffer overflow": ["buffer-overflow", "stack-overflow", "bof"],
    "format string": ["format-string", "fmtstr", "printf"],
    "use after free": ["use-after-free", "uaf", "dangling-pointer"],
    "double free": ["double-free", "tcache-dup", "fastbin-dup"],
    "heap overflow": ["heap-overflow", "chunk-corruption"],
    "sql injection": ["sqli", "union-select", "sqlmap"],
    "command injection": ["cmdi", "os-command-injection", "shell-injection"],
    "file inclusion": ["lfi", "rfi", "path-traversal"],
    "path traversal": ["path-traversal", "directory-traversal", "lfi"],
    "template injection": ["ssti", "jinja2", "template"],
    "prototype pollution": ["prototype-pollution", "__proto__"],
    "request smuggling": ["request-smuggling", "desync", "cl-te"],
    "race condition": ["race-condition", "toctou", "limit-overrun"],
    "reverse shell": ["reverse-shell", "netcat", "listener"],
    "privilege escalation": ["privesc", "suid", "sudo", "gtfobins"],
    "active directory": ["active-directory", "kerberos", "bloodhound", "ntlm"],
    "discrete log": ["dlp", "discrete-logarithm", "pohlig-hellman"],
    "elliptic curve": ["ecc", "ecdsa", "weierstrass", "point-multiplication"],
    "lattice reduction": ["lll", "lattice", "bkz", "fpylll"],
    "hidden number": ["hnp", "hidden-number-problem", "biased-nonce"],
    "side channel": ["side-channel", "timing", "power-analysis"],
    "symbolic execution": ["angr", "symbolic-execution", "z3"],
    "memory forensics": ["volatility", "volatility3", "memory-dump"],
    "packet capture": ["pcap", "wireshark", "tshark"],
    "smart contract": ["solidity", "evm", "blockchain"],
    "container escape": ["docker", "privileged", "capabilities", "release-agent"],
    "ssl pinning": ["certificate-pinning", "frida", "bypass"],
    "where to start": ["playbook", "triage", "stuck", "methodology"],
    "what attack": ["playbook", "triage", "decision-tree"],
    "i am stuck": ["stuck", "playbook", "triage", "methodology"],
}

TOKEN_RE = re.compile(r"[a-z0-9_$.]+")


def normalise(term: str) -> str:
    """Strip punctuation/hyphens so `common-modulus` and `common modulus` agree."""
    return re.sub(r"[^a-z0-9]", "", term.lower())


_NORM_SYNONYMS = {normalise(k): v for k, v in SYNONYMS.items()}


def expand(query: str, max_extra: int = 24) -> list[str]:
    """Return extra search terms implied by the query. Never includes the originals."""
    lowered = query.lower().strip()
    extra: list[str] = []

    for phrase, terms in PHRASES.items():
        if phrase in lowered:
            extra.extend(terms)

    for token in TOKEN_RE.findall(lowered):
        for candidate in (token, normalise(token)):
            if candidate in _NORM_SYNONYMS:
                extra.extend(_NORM_SYNONYMS[candidate])
                break

    seen_original = {normalise(t) for t in TOKEN_RE.findall(lowered)}
    out: list[str] = []
    for term in extra:
        if normalise(term) in seen_original:
            continue
        if term not in out:
            out.append(term)
    return out[:max_extra]
