"""Shared plumbing for the CTF-Brain ingestion pipelines.

Every pipeline needs the same four things: a polite cached HTTP session, a way to
guess a category from text, a way to mine tags from text, and a safe frontmatter
writer.  They live here so the pipelines stay short and behave consistently.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
CONTENT = ROOT / "content"
RAW = ROOT / "data" / "raw"

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

CATEGORIES = ["crypto", "web", "pwn", "rev", "forensics", "stego",
              "misc", "osint", "mobile", "hardware", "blockchain", "cloud"]

# ---------------------------------------------------------------- categorisation
# Ordered most-specific-first; the first category to accumulate the highest score wins.
CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "crypto": (
        "crypto", "cryptography", "rsa", "aes", "des", "ecc", "elliptic", "ecdsa", "eddsa",
        "diffie", "discrete log", "dlp", "lattice", "lll", "coppersmith", "modulus",
        "cipher", "ciphertext", "plaintext", "xor", "one-time pad", "otp", "padding oracle",
        "hash collision", "md5", "sha1", "hmac", "prng", "mersenne", "mt19937", "lcg",
        "vigenere", "caesar", "substitution", "factoring", "factordb", "totient", "chacha",
        "salsa20", "rc4", "lfsr", "sagemath", "pycryptodome", "gmpy2", "nonce", "keystream",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "poly1305", "chacha20", "ed25519", "curve25519", "elgamal", "paillier",
        "schnorr", "birthday attack", "quadratic residue", "legendre symbol",
        "modular inverse", "cube root", "getprime(", "bytes_to_long", "long_to_bytes",
        "public exponent", "private exponent", "secret key", "encryption scheme",
        "暗号", "復号", "素因数分解", "秘密鍵", "公開鍵", "楕円曲線", "剰余",
        "密码学", "加密", "解密",
    ),
    "pwn": (
        "pwn", "pwnable", "binary exploitation", "buffer overflow", "stack overflow",
        "rop", "ret2libc", "ret2win", "ret2csu", "srop", "one_gadget", "one gadget",
        "format string", "fmtstr", "heap", "tcache", "fastbin", "unsorted bin", "malloc",
        "use-after-free", "use after free", "uaf", "double free", "glibc", "got overwrite",
        "shellcode", "canary", "aslr", "nx bit", "seccomp", "kernel exploit", "pwntools",
        "libc leak", "stack pivot", "house of", "safe-linking", "__free_hook", "setcontext",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "checksec", "libc.so.6", "ret2shellcode", "tcache poisoning", "/bin/sh",
        "gdb-peda", "vmmap", "stack smashing", "return address", "leave ; ret",
        "ld-linux", "__libc_start_main", "environ leak", "orw shellcode",
        "バッファオーバーフロー", "シェルコード", "栈溢出", "堆溢出",
    ),
    "web": (
        "web", "sqli", "sql injection", "xss", "cross-site scripting", "ssrf", "ssti",
        "csrf", "xxe", "lfi", "rfi", "local file inclusion", "path traversal", "jwt",
        "deserialization", "unserialize", "prototype pollution", "graphql", "nosql",
        "mongodb injection", "command injection", "php", "flask", "django", "express",
        "nodejs", "node.js", "request smuggling", "cache poisoning", "open redirect",
        "webshell", "burp", "sqlmap", "cookie", "session", "http header", "type juggling",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "render_template", "request.args", "request.form", "app.route", "app.get(",
        "app.post(", "res.send", "document.cookie", "innerhtml", "xmlhttprequest",
        "same-origin", "content-security-policy", "sqlite3.connect", "cursor.execute",
        "location.href", "iframe", "urlparse", "fastapi", "werkzeug", "nginx",
        "php://", "<?php", "csrf token", "http/1.1", "content-type: application",
        # -- added by ingest/reference_corpora.py --
        "clickjacking", "crlf injection", "http parameter pollution", "mass assignment",
        "insecure direct object", "idor", "oauth", "saml", "openid connect",
        "xpath injection", "xslt injection", "ldap injection", "csv injection",
        "latex injection", "server side include", "dns rebinding",
        "dependency confusion", "zip slip", "tabnabbing", "xs-leak",
        "web cache deception", "dom clobbering", "css injection", "websocket",
        "virtual host", "reverse proxy", "account takeover", "business logic",
        "headless browser", "hidden parameter", "x-frame-options", "samesite",
        "クッキー", "セッション", "リダイレクト", "文件上传", "命令执行", "反序列化",
    ),
    "rev": (
        "reverse engineering", "reversing", "rev", "crackme", "keygen", "ghidra", "ida pro",
        "idapro", "radare2", "binary ninja", "binaryninja", "angr", "symbolic execution",
        "decompile", "decompiler", "disassembl", "obfuscat", "deobfuscat", "packer", "upx",
        "anti-debug", "antidebug", "bytecode", "dotnet", ".net", "dnspy", "unicorn engine",
        "z3 solver", "pyinstaller", "uncompyle", "webassembly", "wasm", "vm challenge",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "objdump", "il2cpp", "disassembly", "decompiled", "opcode", "instruction set",
        "mov eax", "mov rax", "cmp eax", "jne ", "call rax", "x86-64 assembly",
        "arm assembly", "mips assembly", "elf header", "pe header", "il code",
        "難読化", "逆アセンブル", "逆コンパイル", "反编译",
    ),
    "forensics": (
        "forensics", "forensic", "memory dump", "volatility", "pcap", "wireshark", "tshark",
        "packet capture", "network capture", "disk image", "file carving", "binwalk",
        "foremost", "autopsy", "sleuthkit", "registry hive", "prefetch", "evtx", "mft",
        "usb hid", "keystroke", "timeline", "plaso", "incident response", "malware analysis",
        "email header", "olevba", "macro", "srum", "shellbags", "scapy",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "tcp stream", "dns query", "http object export", "zeek", "netflow", "syslog",
        "hex dump", "file signature", "deleted file", "slack space", "journal entry",
        "パケット", "メモリダンプ", "ログ解析", "流量分析", "内存取证", "取证",
    ),
    "stego": (
        "steganography", "stego", "steghide", "zsteg", "stegsolve", "stegseek", "lsb",
        "least significant bit", "bit plane", "bitplane", "spectrogram", "sonic visual",
        "exiftool", "exif", "png chunk", "jpeg marker", "outguess", "polyglot",
        "zero-width", "zero width", "morse", "sstv", "audacity", "aperisolve",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "hidden message", "embedded image", "alpha channel", "colour plane",
        "ステガノグラフィ", "隐写",
    ),
    "mobile": (
        "android", "apk", "smali", "dalvik", "jadx", "apktool", "frida", "objection",
        "ios ", "ipa file", "swift", "objective-c", "mobile app", "ssl pinning",
        "certificate pinning", "adb shell", "dex2jar", "xposed", "jailbreak",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "androidmanifest", "classes.dex", "libnative", "flutter app", "react native",
    ),
    "hardware": (
        "hardware", "firmware", "uart", "jtag", "swd", "spi flash", "i2c", "logic analyzer",
        "sigrok", "openocd", "flashrom", "sdr", "software defined radio", "rtl-sdr",
        "hackrf", "gnuradio", "side channel", "power analysis", "chipwhisperer",
        "fault injection", "glitching", "can bus", "modbus", "rfid", "nfc", "proxmark",
        "esp32", "stm32", "avr", "arduino", "oscilloscope",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "verilog", "vhdl", "fpga", "bootloader", "u-boot", "bitstream", "eeprom",
        "saleae", "pulseview", "ハードウェア",
    ),
    "blockchain": (
        "blockchain", "smart contract", "solidity", "ethereum", "evm", "web3", "foundry",
        "hardhat", "reentrancy", "delegatecall", "erc20", "erc721", "flash loan",
        "flashloan", "defi", "metamask", "anvil", "cast call", "selfdestruct", "solana",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "msg.sender", "block.timestamp", "pragma solidity", "gas limit", "erc-20",
        "uniswap", "wallet address", "on-chain", "setup.sol",
    ),
    "cloud": (
        "kubernetes", "k8s", "kubectl", "docker escape", "container escape", "aws ",
        "s3 bucket", "iam policy", "lambda function", "gcp", "azure", "cloud metadata",
        "imds", "169.254.169.254", "terraform", "helm chart", "service account",
        "github actions", "ci/cd", "firebase", "serverless",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "eks cluster", "gke cluster", "cloudformation", "pod spec", "sts assume-role",
        # -- added by ingest/reference_corpora.py --
        "aks cluster", "kubelet", "pod security", "cluster-admin", "storage account",
        "azure blob", "gcloud ", "az cli", "cloud function", "workload identity",
        "aws_access_key_id", "presigned url", "cloud run", "app engine",
    ),
    "osint": (
        "osint", "open source intelligence", "geolocation", "geoguess", "reverse image",
        "google dork", "shodan", "wayback machine", "sherlock", "social media",
        "whois lookup", "certificate transparency", "exif gps", "street view",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "google maps", "openstreetmap", "satellite image", "flight tracker",
        "username search", "linkedin profile", "archive.org",
    ),
    "misc": (
        "misc", "jail", "pyjail", "sandbox escape", "esolang", "brainfuck", "whitespace",
        "proof of work", "programming challenge", "gtfobins", "privilege escalation",
        "active directory", "kerberoast", "bloodhound", "nmap", "enumeration",
        # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
        "so_broadcast", "sock.sendto", "recvfrom(", "udp broadcast", "broadcast address",
        "ipv4address", "guessing game", "rock paper scissors", "tic-tac-toe",
        "proof-of-work", "hashcash", "bogosort", "code golf", "obfuscated python",
        # -- added by ingest/reference_corpora.py --
        "reverse shell", "bind shell", "port forwarding", "pivoting", "chisel",
        "ligolo", "socat", "wordlist", "seclists", "ntlm relay", "pass the hash",
        "restricted shell", "suid binary", "sudoers", "tunneling",
        "じゃんけん", "パズル", "杂项",
    ),
}

# Direct tag/word -> category overrides; these beat the scoring table.
STRONG_SIGNALS: dict[str, str] = {
    "crypto": "crypto", "cryptography": "crypto",
    "pwn": "pwn", "pwnable": "pwn", "binaryexploitation": "pwn", "binary-exploitation": "pwn",
    "exploitation": "pwn", "heap": "pwn",
    "web": "web", "webexploitation": "web", "web-exploitation": "web",
    "rev": "rev", "reverse": "rev", "reversing": "rev", "reverseengineering": "rev",
    "reverse-engineering": "rev", "re": "rev",
    "forensics": "forensics", "forensic": "forensics", "networking": "forensics",
    "stego": "stego", "steganography": "stego",
    "osint": "osint",
    "mobile": "mobile", "android": "mobile", "ios": "mobile",
    "hardware": "hardware", "embedded": "hardware", "radio": "hardware",
    "blockchain": "blockchain", "smartcontract": "blockchain", "smart-contract": "blockchain",
    "cloud": "cloud", "kubernetes": "cloud", "devops": "cloud",
    "misc": "misc", "miscellaneous": "misc", "jail": "misc", "ppc": "misc",
    # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
    # A mined tag is a far cleaner signal than raw prose, so the high-precision
    # members of TAG_VOCAB are mapped straight onto their category here.
    "rsa": "crypto", "aes": "crypto", "ecdsa": "crypto", "ecc": "crypto",
    "lattice": "crypto", "lll": "crypto", "coppersmith": "crypto", "wiener": "crypto",
    "boneh-durfee": "crypto", "hastad": "crypto", "franklin-reiter": "crypto",
    "common-modulus": "crypto", "common-factor": "crypto", "batch-gcd": "crypto",
    "padding-oracle": "crypto", "nonce-reuse": "crypto", "length-extension": "crypto",
    "hash-collision": "crypto", "mt19937": "crypto", "lcg": "crypto", "prng": "crypto",
    "discrete-log": "crypto", "pohlig-hellman": "crypto", "chinese-remainder": "crypto",
    "one-time-pad": "crypto", "vigenere": "crypto", "caesar": "crypto",
    "substitution-cipher": "crypto", "frequency-analysis": "crypto",
    "hidden-number-problem": "crypto", "smart-attack": "crypto", "lwe": "crypto",
    "ntru": "crypto", "poly1305": "crypto", "chacha20": "crypto", "ed25519": "crypto",
    "curve25519": "crypto", "elgamal": "crypto", "paillier": "crypto",
    "schnorr": "crypto", "birthday-attack": "crypto", "quadratic-residue": "crypto",
    "cbc-mac": "crypto", "low-exponent": "crypto", "xorshift": "crypto",
    "rsactftool": "crypto", "factordb": "crypto",

    "buffer-overflow": "pwn", "rop": "pwn", "ret2libc": "pwn", "ret2win": "pwn",
    "ret2csu": "pwn", "ret2dlresolve": "pwn", "ret2shellcode": "pwn", "srop": "pwn",
    "stack-pivot": "pwn", "format-string": "pwn", "tcache": "pwn", "fastbin": "pwn",
    "unsorted-bin": "pwn", "largebin": "pwn", "use-after-free": "pwn",
    "double-free": "pwn", "off-by-one": "pwn", "house-of-force": "pwn",
    "house-of-orange": "pwn", "house-of-spirit": "pwn", "house-of-botcake": "pwn",
    "safe-linking": "pwn", "free-hook": "pwn", "malloc-hook": "pwn", "fsop": "pwn",
    "got-overwrite": "pwn", "one-gadget": "pwn", "shellcode": "pwn", "seccomp": "pwn",
    "canary": "pwn", "kernel-pwn": "pwn", "pwntools": "pwn", "pwndbg": "pwn",
    "tcache-poisoning": "pwn", "orw": "pwn",

    "sqli": "web", "blind-sqli": "web", "sqlmap": "web", "nosql-injection": "web",
    "xss": "web", "csp-bypass": "web", "dom-xss": "web", "dom-clobbering": "web",
    "ssrf": "web", "ssti": "web", "jinja2": "web", "xxe": "web", "lfi": "web",
    "path-traversal": "web", "php-filter": "web", "deserialization": "web",
    "ysoserial": "web", "phpggc": "web", "jwt": "web", "alg-none": "web",
    "prototype-pollution": "web", "graphql": "web", "request-smuggling": "web",
    "cache-poisoning": "web", "command-injection": "web", "file-upload": "web",
    "type-juggling": "web", "open-redirect": "web", "cors": "web", "flask": "web",
    "express": "web", "werkzeug": "web", "render-template": "web", "nextjs": "web",
    "laravel": "web", "wordpress": "web", "shellshock": "web", "zip-slip": "web",
    "xpath-injection": "web", "ldap-injection": "web", "log4shell": "web",
    "http-parameter-pollution": "web", "dns-rebinding": "web",

    "ida": "rev", "radare2": "rev", "binaryninja": "rev", "angr": "rev",
    "symbolic-execution": "rev", "unicorn": "rev", "qiling": "rev", "upx": "rev",
    "packer": "rev", "anti-debug": "rev", "obfuscation": "rev",
    "control-flow-flattening": "rev", "custom-vm": "rev", "dotnet": "rev",
    "python-bytecode": "rev", "pyinstaller": "rev", "wasm": "rev",

    "volatility": "forensics", "volatility3": "forensics",
    "memory-forensics": "forensics", "pcap": "forensics", "wireshark": "forensics",
    "tshark": "forensics", "usb-hid": "forensics", "file-carving": "forensics",
    "binwalk": "forensics", "foremost": "forensics", "testdisk": "forensics",
    "mft": "forensics", "evtx": "forensics", "prefetch": "forensics",
    "sleuthkit": "forensics", "olevba": "forensics", "pdf-analysis": "forensics",
    "sqlite-forensics": "forensics", "tls-decryption": "forensics",

    "zsteg": "stego", "steghide": "stego", "stegsolve": "stego", "stegseek": "stego",
    "outguess": "stego", "spectrogram": "stego", "png-chunks": "stego",
    "polyglot": "stego", "zero-width": "stego", "morse": "stego", "sstv": "stego",

    "frida": "mobile", "objection": "mobile", "apktool": "mobile", "smali": "mobile",
    "ssl-pinning": "mobile", "jadx": "mobile",

    "firmware": "hardware", "uart": "hardware", "jtag": "hardware", "sdr": "hardware",
    "side-channel": "hardware", "can-bus": "hardware", "modbus": "hardware",
    "verilog": "hardware", "fpga": "hardware",

    "solidity": "blockchain", "evm": "blockchain", "reentrancy": "blockchain",
    "delegatecall": "blockchain", "foundry": "blockchain", "web3py": "blockchain",
    "flash-loan": "blockchain",

    "docker-escape": "cloud", "imds": "cloud", "terraform": "cloud", "helm": "cloud",

    "pyjail": "misc", "sandbox-escape": "misc", "proof-of-work": "misc",
    "gtfobins": "misc", "privesc": "misc", "kerberoasting": "misc",
    "bloodhound": "misc",
}

# Noise tags every ctftime writeup carries; they say nothing about the challenge.
STOP_TAGS = {"writeup", "ctf", "writeups", "task", "solution", "solutions", "challenge"}

# Words that carry no search value when used as a fallback tag.
WORD_STOPLIST = {
    "the", "and", "for", "with", "from", "this", "that", "into", "your", "you", "are",
    "was", "were", "has", "have", "had", "how", "why", "what", "when", "where", "which",
    "using", "used", "use", "via", "over", "under", "about", "part", "one", "two", "three",
    "new", "old", "get", "got", "can", "will", "not", "but", "all", "any", "its", "his",
    "her", "our", "their", "some", "more", "most", "very", "just", "also", "than", "then",
    "writeup", "writeups", "challenge", "solution", "ctf", "task", "flag", "ctfd",
}

# ------------------------------------------------------------------ tag vocabulary
TAG_VOCAB: dict[str, tuple[str, ...]] = {
    # crypto
    "rsa": ("rsa",), "aes": ("aes",), "des": ("3des", "triple des"),
    "ecc": ("elliptic curve", "elliptic-curve"), "ecdsa": ("ecdsa",),
    "common-modulus": ("common modulus",), "common-factor": ("common factor", "shared prime"),
    "batch-gcd": ("batch gcd", "batch-gcd"), "gcd": ("gcd",),
    "wiener": ("wiener",), "boneh-durfee": ("boneh-durfee", "boneh durfee"),
    "hastad": ("hastad", "håstad", "broadcast attack"),
    "coppersmith": ("coppersmith", "small_roots", "small roots"),
    "franklin-reiter": ("franklin-reiter", "franklin reiter"),
    "fermat": ("fermat factor",), "pollard-rho": ("pollard rho", "pollard's rho"),
    "pollard-p-minus-1": ("pollard p-1", "p-1 method"),
    "lll": ("lll", "lattice reduction"), "lattice": ("lattice",),
    "fpylll": ("fpylll",), "sage": ("sagemath", "sage "),
    "padding-oracle": ("padding oracle",), "bit-flipping": ("bit flip", "bitflip"),
    "ecb": ("ecb",), "cbc": ("cbc",), "ctr": ("ctr mode", "counter mode"),
    "gcm": ("gcm",), "nonce-reuse": ("nonce reuse", "reused nonce"),
    "length-extension": ("length extension",), "hash-collision": ("hash collision",),
    "xor": ("xor",), "one-time-pad": ("one-time pad", "one time pad"),
    "mt19937": ("mt19937", "mersenne twister"), "lcg": ("lcg", "linear congruential"),
    "prng": ("prng", "random number"), "discrete-log": ("discrete log", "dlp"),
    "pohlig-hellman": ("pohlig-hellman", "pohlig hellman"),
    "chinese-remainder": ("chinese remainder", "crt"),
    "factordb": ("factordb",), "rsactftool": ("rsactftool",),
    "vigenere": ("vigenere", "vigenère"), "caesar": ("caesar", "rot13"),
    "substitution-cipher": ("substitution cipher",), "frequency-analysis": ("frequency analysis",),
    "hidden-number-problem": ("hidden number problem", "hnp"),
    "smart-attack": ("smart's attack", "anomalous curve"),
    "invalid-curve": ("invalid curve",), "singular-curve": ("singular curve",),
    "lwe": ("learning with errors", "lwe"), "ntru": ("ntru",),
    # pwn
    "buffer-overflow": ("buffer overflow", "stack overflow"),
    "rop": ("rop chain", "return-oriented", "rop "),
    "ret2libc": ("ret2libc", "ret2 libc"), "ret2win": ("ret2win",),
    "ret2csu": ("ret2csu",), "ret2dlresolve": ("ret2dlresolve",),
    "srop": ("srop", "sigreturn"), "stack-pivot": ("stack pivot",),
    "format-string": ("format string", "%n",),
    "heap": ("heap ",), "tcache": ("tcache",), "fastbin": ("fastbin",),
    "unsorted-bin": ("unsorted bin",), "largebin": ("largebin", "large bin"),
    "use-after-free": ("use-after-free", "use after free", "uaf"),
    "double-free": ("double free",), "off-by-one": ("off-by-one", "off by one"),
    "house-of-force": ("house of force",), "house-of-orange": ("house of orange",),
    "house-of-spirit": ("house of spirit",), "house-of-botcake": ("house of botcake",),
    "safe-linking": ("safe-linking", "safe linking"),
    "free-hook": ("__free_hook", "free_hook"), "malloc-hook": ("__malloc_hook",),
    "fsop": ("fsop", "_io_file", "file struct"),
    "got-overwrite": ("got overwrite", "got hijack"),
    "one-gadget": ("one_gadget", "one gadget"),
    "shellcode": ("shellcode",), "seccomp": ("seccomp",),
    "canary": ("stack canary", "canary"), "aslr": ("aslr",), "pie": ("pie ",),
    "kernel-pwn": ("kernel exploit", "kernel pwn", "modprobe_path", "commit_creds"),
    "pwntools": ("pwntools",), "gef": ("gef ",), "pwndbg": ("pwndbg",),
    "integer-overflow": ("integer overflow",),
    # web
    "sqli": ("sql injection", "sqli"), "union-select": ("union select",),
    "blind-sqli": ("blind sql", "blind sqli"), "sqlmap": ("sqlmap",),
    "nosql-injection": ("nosql injection", "$ne", "$regex"),
    "xss": ("xss", "cross-site scripting"), "csp-bypass": ("csp bypass", "content-security-policy"),
    "dom-xss": ("dom xss", "dom-based"), "dom-clobbering": ("dom clobbering",),
    "ssrf": ("ssrf", "server-side request forgery"),
    "ssti": ("ssti", "template injection"), "jinja2": ("jinja2", "jinja"),
    "xxe": ("xxe", "xml external entity"),
    "lfi": ("lfi", "local file inclusion"), "path-traversal": ("path traversal", "directory traversal"),
    "php-filter": ("php://filter", "filter chain"),
    "deserialization": ("deserialization", "unserialize", "pickle"),
    "pickle": ("pickle.loads", "__reduce__"),
    "ysoserial": ("ysoserial",), "phpggc": ("phpggc",),
    "jwt": ("jwt", "json web token"), "alg-none": ("alg:none", "alg=none", "alg none"),
    "prototype-pollution": ("prototype pollution", "__proto__"),
    "graphql": ("graphql", "introspection"),
    "race-condition": ("race condition", "toctou"),
    "request-smuggling": ("request smuggling", "cl.te", "te.cl"),
    "cache-poisoning": ("cache poisoning", "cache deception"),
    "command-injection": ("command injection", "rce via command"),
    "file-upload": ("file upload", "upload bypass"),
    "type-juggling": ("type juggling", "loose comparison"),
    "open-redirect": ("open redirect",), "cors": ("cors misconfig", "access-control-allow-origin"),
    "flask": ("flask",), "django": ("django",), "express": ("express.js", "expressjs"),
    "werkzeug": ("werkzeug",), "burp": ("burp suite", "burpsuite"),
    # rev
    "ghidra": ("ghidra",), "ida": ("ida pro", "ida free", "hex-rays"),
    "radare2": ("radare2", "r2 "), "binaryninja": ("binary ninja", "binaryninja"),
    "angr": ("angr",), "z3": ("z3 ", "z3-solver", "z3py"),
    "symbolic-execution": ("symbolic execution",), "unicorn": ("unicorn engine",),
    "qiling": ("qiling",), "upx": ("upx",), "packer": ("packed binary", "unpacking"),
    "anti-debug": ("anti-debug", "ptrace detect"),
    "obfuscation": ("obfuscat",), "control-flow-flattening": ("control flow flattening",),
    "custom-vm": ("custom vm", "virtual machine", "bytecode interpreter"),
    "dotnet": ("dnspy", ".net assembly", "ilspy"),
    "golang": ("go binary", "golang"), "rust": ("rust binary",),
    "python-bytecode": ("pyc", "uncompyle", "pycdc", "marshal"),
    "pyinstaller": ("pyinstaller", "pyinstxtractor"),
    "wasm": ("webassembly", "wasm"), "jadx": ("jadx",),
    # forensics
    "volatility3": ("volatility3", "vol3", "volatility 3"),
    "volatility": ("volatility",), "memory-forensics": ("memory dump", "memory forensics"),
    "pcap": ("pcap", "packet capture"), "wireshark": ("wireshark",), "tshark": ("tshark",),
    "scapy": ("scapy",), "usb-hid": ("usb hid", "usb.capdata", "keystroke"),
    "file-carving": ("file carving", "carve"), "binwalk": ("binwalk",),
    "foremost": ("foremost",), "testdisk": ("testdisk", "photorec"),
    "mft": ("$mft", "master file table"), "registry": ("registry hive", "regripper"),
    "evtx": ("evtx", "event log"), "prefetch": ("prefetch",),
    "sleuthkit": ("sleuthkit", "tsk_recover", "fls "),
    "olevba": ("olevba", "oletools"), "pdf-analysis": ("pdf object", "pdfid", "peepdf"),
    "sqlite-forensics": ("sqlite wal", "sqlite journal"),
    "tls-decryption": ("sslkeylogfile", "decrypt tls"),
    # stego
    "lsb": ("lsb", "least significant bit"), "zsteg": ("zsteg",),
    "steghide": ("steghide",), "stegsolve": ("stegsolve",), "stegseek": ("stegseek",),
    "outguess": ("outguess",), "exiftool": ("exiftool",), "exif": ("exif",),
    "spectrogram": ("spectrogram", "sonic visualiser", "audacity"),
    "png-chunks": ("png chunk", "idat", "ihdr"), "jpeg": ("jpeg marker", "jfif"),
    "polyglot": ("polyglot",), "zero-width": ("zero-width", "zero width"),
    "morse": ("morse",), "sstv": ("sstv",), "qr-code": ("qr code",),
    "bkcrack": ("bkcrack", "known plaintext zip"),
    "zip-crack": ("zip2john", "zip password"),
    # mobile / hardware / chain / cloud / misc
    "frida": ("frida",), "objection": ("objection",), "apktool": ("apktool",),
    "smali": ("smali",), "ssl-pinning": ("ssl pinning", "certificate pinning"),
    "adb": ("adb shell", "adb "),
    "firmware": ("firmware",), "uart": ("uart", "serial console"), "jtag": ("jtag",),
    "sdr": ("rtl-sdr", "software defined radio", "hackrf"),
    "side-channel": ("side channel", "power analysis", "dpa"),
    "can-bus": ("can bus", "candump"), "modbus": ("modbus",),
    "solidity": ("solidity",), "evm": ("evm ", "ethereum virtual machine"),
    "reentrancy": ("reentran",), "delegatecall": ("delegatecall",),
    "foundry": ("foundry", "forge script", "cast call"), "web3py": ("web3.py", "web3py"),
    "flash-loan": ("flash loan", "flashloan"),
    "kubernetes": ("kubernetes", "kubectl"), "docker-escape": ("docker escape", "container escape"),
    "imds": ("169.254.169.254", "instance metadata", "imds"),
    "s3": ("s3 bucket",), "iam": ("iam policy", "iam role"),
    "pyjail": ("pyjail", "python jail"), "sandbox-escape": ("sandbox escape",),
    "proof-of-work": ("proof of work", "pow "),
    "gtfobins": ("gtfobins",), "privesc": ("privilege escalation", "privesc"),
    "kerberoasting": ("kerberoast",), "bloodhound": ("bloodhound",),
    "nmap": ("nmap",), "ffuf": ("ffuf",), "gobuster": ("gobuster",),
    "hashcat": ("hashcat",), "john": ("john the ripper", "johntheripper"),
    "cyberchef": ("cyberchef",),
    # ---------------------------------------------------------------------
    # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
    # crypto primitives and attacks the original table did not cover
    "poly1305": ("poly1305",), "chacha20": ("chacha20",),
    "ed25519": ("ed25519",), "curve25519": ("curve25519", "x25519"),
    "elgamal": ("elgamal",), "paillier": ("paillier",), "schnorr": ("schnorr",),
    "birthday-attack": ("birthday attack", "birthday paradox", "誕生日"),
    "meet-in-the-middle": ("meet-in-the-middle", "meet in the middle"),
    "quadratic-residue": ("quadratic residue", "legendre symbol", "tonelli"),
    "cbc-mac": ("cbc-mac", "cbc mac"),
    "low-exponent": ("low public exponent", "small public exponent", "cube root"),
    "xorshift": ("xorshift",), "bit-flip": ("bit flipping",),
    "base64": ("base64",), "base32": ("base32",), "base58": ("base58",),
    # pwn primitives
    "ret2shellcode": ("ret2shellcode",),
    "orw": ("orw shellcode", "open read write"),
    "tcache-poisoning": ("tcache poisoning",),
    "checksec": ("checksec",), "libc-database": ("libc-database", "libc.rip"),
    "strcpy": ("strcpy(",), "gets": ("gets(",), "sprintf": ("sprintf(",),
    "memcpy": ("memcpy(",), "scanf": ("scanf(",),
    # web sinks and stacks
    "render-template": ("render_template", "render_template_string"),
    "eval": ("eval(",), "exec": ("exec(",), "os-system": ("os.system(",),
    "subprocess": ("subprocess.",), "yaml-load": ("yaml.load",),
    "sqlite": ("sqlite3", "sqlite"), "mysql": ("mysql",),
    "postgres": ("postgresql", "psycopg"), "mongodb": ("mongodb", "pymongo"),
    "redis": ("redis",), "nginx": ("nginx",), "apache": ("apache http", "httpd.conf"),
    "nodejs": ("node.js", "nodejs"), "nextjs": ("next.js", "nextjs"),
    "spring": ("spring boot", "springboot"), "rails": ("ruby on rails",),
    "laravel": ("laravel",), "wordpress": ("wordpress",),
    "log4shell": ("log4shell", "log4j"), "xslt": ("xslt",),
    "ldap-injection": ("ldap injection",), "xpath-injection": ("xpath injection",),
    "websocket": ("websocket",), "grpc": ("grpc",),
    "protobuf": ("protobuf", "protocol buffer"),
    "dns-rebinding": ("dns rebinding",),
    "http-parameter-pollution": ("parameter pollution",),
    "unicode-normalization": ("unicode normalization", "nfkc"),
    "zip-slip": ("zip slip", "zipslip"), "symlink": ("symlink",),
    "shellshock": ("shellshock",), "cgi": ("cgi-bin", "cgi script"),
    "redos": ("redos", "catastrophic backtracking"),
    "regex": ("regular expression", "re.fullmatch"),
    "floating-point": ("floating point", "ieee 754", "struct.pack('<d'"),
    "integer-division": ("integer division", "floor division"),
    # rev / hardware / cloud extras
    "objdump": ("objdump",), "il2cpp": ("il2cpp",),
    "jit": ("jit compiler", "turbofan"), "v8": ("v8 engine",),
    "verilog": ("verilog",), "fpga": ("fpga",), "bootloader": ("bootloader", "u-boot"),
    "terraform": ("terraform",), "helm": ("helm chart",),
    "google-dork": ("google dork",), "wayback": ("wayback machine", "archive.org"),
    # ---------------------------------------------------------------------
    # -- added by ingest/reference_corpora.py --
    # the vulnerability names HackTricks / OWASP WSTG / PayloadsAllTheThings use
    "csrf": ("csrf", "cross-site request forgery"),
    "clickjacking": ("clickjacking", "x-frame-options"),
    "crlf-injection": ("crlf injection", "%0d%0a"),
    "mass-assignment": ("mass assignment", "autobinding"),
    "idor": ("idor", "insecure direct object"),
    "oauth": ("oauth", "redirect_uri", "authorization code"),
    "saml": ("saml", "samlresponse", "assertion consumer"),
    "xpath-injection": ("xpath injection",),
    "xslt-injection": ("xslt injection",),
    "csv-injection": ("csv injection", "formula injection"),
    "latex-injection": ("latex injection",),
    "ssi-injection": ("server side include", "<!--#exec"),
    "dependency-confusion": ("dependency confusion",),
    # ("zip-slip" is already defined above by another pipeline; not redefined here)
    "tabnabbing": ("tabnabbing", "rel=noopener"),
    "xs-leak": ("xs-leak", "xsleak", "cross-site leak"),
    "cache-deception": ("cache deception",),
    "websocket": ("websocket", "web socket", "cswsh"),
    "virtual-host": ("virtual host", "vhost"),
    "reverse-proxy": ("reverse proxy", "x-forwarded-host"),
    "account-takeover": ("account takeover",),
    "business-logic": ("business logic",),
    "headless-browser": ("headless browser", "puppeteer", "playwright"),
    "hidden-parameters": ("hidden parameter", "arjun"),
    "api-key-leak": ("api key leak", "leaked credential"),
    "csp": ("csp header", "content-security-policy"),
    "samesite": ("samesite", "same-site cookie"),
    "heap-feng-shui": ("heap feng shui", "heap grooming"),
    "kernel-rop": ("kernel rop", "ret2usr", "kpti"),
    "reverse-shell": ("reverse shell", "bind shell"),
    "pivoting": ("port forwarding", "pivoting", "chisel", "ligolo"),
    "fuzzing": ("fuzzing", "afl++", "libfuzzer", "honggfuzz"),
    "wordlists": ("seclists", "wordlist"),
    "active-directory": ("active directory", "ntlm relay", "pass the hash"),
    "gcp": ("google cloud", "gcloud "),
    "azure": ("azure",),
    "logic-analyzer": ("logic analyzer", "sigrok"),
    "email-forensics": ("email header", "eml file"),
    "geolocation": ("geolocation", "geoguessr"),
}

SUBCATEGORY_HINTS: dict[str, str] = {
    "rsa": "rsa", "aes": "aes", "ecc": "ecc", "ecdsa": "ecdsa", "lattice": "lattice",
    "lll": "lattice", "prng": "prng", "mt19937": "prng", "lcg": "prng",
    "vigenere": "classical", "caesar": "classical", "substitution-cipher": "classical",
    "heap": "heap", "tcache": "heap", "fastbin": "heap", "use-after-free": "heap",
    "double-free": "heap", "rop": "rop", "ret2libc": "rop", "srop": "rop",
    "format-string": "format-string", "buffer-overflow": "stack", "kernel-pwn": "kernel",
    "sqli": "sqli", "xss": "xss", "ssrf": "ssrf", "ssti": "ssti", "xxe": "xxe",
    "lfi": "lfi", "jwt": "jwt", "deserialization": "deserialization",
    "graphql": "graphql", "prototype-pollution": "prototype-pollution",
    "volatility3": "memory", "memory-forensics": "memory", "pcap": "network",
    "wireshark": "network", "usb-hid": "usb", "file-carving": "disk",
    "lsb": "image", "steghide": "image", "spectrogram": "audio",
    "frida": "runtime", "apktool": "static-analysis", "smali": "static-analysis",
    "angr": "symbolic-execution", "ghidra": "static-analysis", "upx": "packers",
    "reentrancy": "reentrancy", "solidity": "smart-contract",
    "kubernetes": "kubernetes", "docker-escape": "container",
    "pyjail": "jail", "sandbox-escape": "jail",
    # -- added by ingest/github_writeups.py + ingest/alpacahack.py --
    "poly1305": "mac", "cbc-mac": "mac", "chacha20": "stream-cipher",
    "xorshift": "prng", "ed25519": "ecc", "curve25519": "ecc", "schnorr": "ecc",
    "elgamal": "asymmetric", "paillier": "asymmetric", "low-exponent": "rsa",
    "common-modulus": "rsa", "common-factor": "rsa", "wiener": "rsa",
    "coppersmith": "rsa", "hastad": "rsa", "boneh-durfee": "rsa",
    "franklin-reiter": "rsa", "batch-gcd": "rsa", "quadratic-residue": "number-theory",
    "chinese-remainder": "number-theory", "discrete-log": "discrete-log",
    "pohlig-hellman": "discrete-log", "hidden-number-problem": "lattice",
    "lwe": "lattice", "ntru": "lattice", "birthday-attack": "hash",
    "hash-collision": "hash", "length-extension": "hash", "padding-oracle": "aes",
    "nonce-reuse": "aes", "one-time-pad": "classical",
    "largebin": "heap", "house-of-force": "heap", "house-of-orange": "heap",
    "house-of-spirit": "heap", "house-of-botcake": "heap", "safe-linking": "heap",
    "free-hook": "heap", "malloc-hook": "heap", "fsop": "heap",
    "tcache-poisoning": "heap", "ret2csu": "rop", "ret2dlresolve": "rop",
    "ret2win": "rop", "one-gadget": "rop", "got-overwrite": "rop",
    "stack-pivot": "rop", "ret2shellcode": "shellcode", "shellcode": "shellcode",
    "orw": "shellcode", "seccomp": "seccomp", "off-by-one": "stack",
    "canary": "stack", "integer-overflow": "integer",
    "blind-sqli": "sqli", "nosql-injection": "nosqli", "dom-xss": "xss",
    "dom-clobbering": "xss", "csp-bypass": "xss", "path-traversal": "lfi",
    "php-filter": "lfi", "pickle": "deserialization", "ysoserial": "deserialization",
    "phpggc": "deserialization", "alg-none": "jwt", "command-injection": "rce",
    "file-upload": "file-upload", "race-condition": "race",
    "request-smuggling": "http", "cache-poisoning": "http", "cors": "cors",
    "open-redirect": "open-redirect", "type-juggling": "php", "render-template": "ssti",
    "z3": "symbolic-execution", "unicorn": "emulation", "qiling": "emulation",
    "wasm": "wasm", "dotnet": "dotnet", "golang": "golang", "rust": "rust",
    "python-bytecode": "python", "pyinstaller": "python", "custom-vm": "vm",
    "obfuscation": "obfuscation", "control-flow-flattening": "obfuscation",
    "anti-debug": "anti-debug", "packer": "packers", "ida": "static-analysis",
    "radare2": "static-analysis", "binaryninja": "static-analysis",
    "objdump": "static-analysis", "jadx": "static-analysis",
    "volatility": "memory", "wireshark": "network", "tshark": "network",
    "scapy": "network", "tls-decryption": "network", "binwalk": "disk",
    "foremost": "disk", "testdisk": "disk", "sleuthkit": "disk", "mft": "disk",
    "evtx": "windows", "registry": "windows", "prefetch": "windows",
    "olevba": "documents", "pdf-analysis": "documents",
    "sqlite-forensics": "database",
    "zsteg": "image", "stegsolve": "image", "stegseek": "image", "outguess": "image",
    "png-chunks": "image", "jpeg": "image", "qr-code": "image", "exif": "metadata",
    "exiftool": "metadata", "morse": "audio", "sstv": "audio",
    "zero-width": "text", "polyglot": "file-format", "zip-crack": "archive",
    "bkcrack": "archive", "objection": "runtime", "ssl-pinning": "runtime",
    "firmware": "firmware", "bootloader": "firmware", "uart": "uart", "jtag": "jtag",
    "sdr": "radio", "side-channel": "side-channel", "can-bus": "can",
    "modbus": "ics", "verilog": "rtl", "fpga": "rtl",
    "evm": "smart-contract", "delegatecall": "smart-contract",
    "foundry": "smart-contract", "web3py": "smart-contract", "flash-loan": "defi",
    "imds": "metadata", "s3": "storage", "iam": "iam", "terraform": "iac",
    "helm": "kubernetes", "proof-of-work": "pow", "privesc": "privesc",
    "kerberoasting": "active-directory", "bloodhound": "active-directory",
    # -- added by ingest/reference_corpora.py --
    "csrf": "csrf", "clickjacking": "clickjacking", "oauth": "oauth", "saml": "saml",
    "idor": "idor", "mass-assignment": "mass-assignment", "crlf-injection": "crlf",
    "xpath-injection": "xpath", "ldap-injection": "ldap", "csv-injection": "csv",
    "ssi-injection": "ssi", "websocket": "websocket", "xs-leak": "xs-leak",
    "cache-deception": "cache", "account-takeover": "account-takeover",
    "redos": "dos", "csp": "csp", "kernel-rop": "kernel", "heap-feng-shui": "heap",
    "reverse-shell": "shells", "pivoting": "pivoting", "fuzzing": "fuzzing",
    "active-directory": "active-directory", "gcp": "gcp", "azure": "azure",
    "email-forensics": "email", "logic-analyzer": "protocols",
    "google-dork": "search", "wayback": "archives", "geolocation": "geolocation",
}


# ---------------------------------------------------------------- matching
# Keywords were originally matched as plain substrings, which produced real
# misclassifications: "defi" fired on "de-fi-ned", "sage" on "mes-sage-", "pie"
# on "reci-pe-". Match on token boundaries instead. The boundary is "not an
# ASCII letter or digit", which keeps `__free_hook`, `$ne`, `169.254.169.254`
# and CJK terms working, and lets needles drop the trailing space some of them
# used as a poor man's boundary.
_BOUNDARY_CACHE: dict[tuple[str, ...], "re.Pattern[str]"] = {}


def _boundary_pattern(needles: tuple[str, ...]) -> "re.Pattern[str]":
    cached = _BOUNDARY_CACHE.get(needles)
    if cached is not None:
        return cached
    parts = []
    for needle in needles:
        cleaned = needle.strip().lower()
        if not cleaned:
            continue
        escaped = re.escape(cleaned)
        left = r"(?<![a-z0-9])" if cleaned[0].isascii() and cleaned[0].isalnum() else ""
        right = r"(?![a-z0-9])" if cleaned[-1].isascii() and cleaned[-1].isalnum() else ""
        parts.append(f"{left}{escaped}{right}")
    pattern = re.compile("|".join(parts) if parts else r"(?!)")
    _BOUNDARY_CACHE[needles] = pattern
    return pattern


def count_matches(blob: str, needles: tuple[str, ...]) -> int:
    """How many times any of `needles` appears in `blob` as a whole token."""
    return len(_boundary_pattern(tuple(needles)).findall(blob))


def has_match(blob: str, needles: tuple[str, ...]) -> bool:
    return _boundary_pattern(tuple(needles)).search(blob) is not None


def categorise(*texts: str, tags: Iterable[str] = ()) -> str:
    """Pick one of the 12 categories from any available text signals."""
    for tag in tags:
        key = re.sub(r"[^a-z0-9-]", "", str(tag).lower())
        if key in STRONG_SIGNALS:
            return STRONG_SIGNALS[key]

    blob = " ".join(t for t in texts if t).lower()
    if not blob:
        return "misc"
    scores: dict[str, int] = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        hits = count_matches(blob, tuple(keywords))
        if hits:
            scores[category] = hits
    if not scores:
        return "misc"
    best = max(scores.values())
    # Tie-break away from `misc`, which is the weakest claim.
    winners = [c for c, s in scores.items() if s == best]
    for candidate in winners:
        if candidate != "misc":
            return candidate
    return winners[0]


def mine_tags(*texts: str, extra: Iterable[str] = (), limit: int = 20) -> list[str]:
    """Derive search tags from free text plus any tags the source already gave us."""
    blob = " ".join(t for t in texts if t).lower()
    found: list[str] = []

    for tag in extra:
        clean = re.sub(r"[^a-z0-9.+-]", "-", str(tag).lower()).strip("-")
        if clean and clean not in STOP_TAGS and clean not in found and len(clean) > 1:
            found.append(clean)

    for tag, needles in TAG_VOCAB.items():
        if tag in found:
            continue
        if has_match(blob, tuple(needles)):
            found.append(tag)

    # Floor: a page with two tags is effectively unfindable. If the vocabulary did not
    # match, fall back to significant words from the title (the first text argument).
    if len(found) < 5 and texts:
        for word in re.findall(r"[A-Za-z][A-Za-z0-9+-]{2,}", str(texts[0] or "")):
            token = word.lower().strip("-")
            if token in WORD_STOPLIST or token in found or len(token) < 3:
                continue
            found.append(token)
            if len(found) >= 8:
                break

    return found[:limit]


def pick_subcategory(tags: Iterable[str], fallback: str = "") -> str:
    for tag in tags:
        if tag in SUBCATEGORY_HINTS:
            return SUBCATEGORY_HINTS[tag]
    return fallback


# ------------------------------------------------------------------- text utils
def slugify(text: str, max_len: int = 60) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", str(text or "")).strip("-").lower()
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].rstrip("-")) or "untitled"


def yaml_quote(value: Any) -> str:
    """Emit a YAML double-quoted scalar that always parses back."""
    text = str(value if value is not None else "")
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    return f'"{text}"'


def first_sentence(markdown: str, limit: int = 200) -> str:
    """A usable one-line summary from a document body.

    Skips fenced code entirely: a note that opens with a solver script would
    otherwise be summarised by a line of Python.
    """
    in_fence = False
    for raw in markdown.splitlines():
        line = raw.strip()
        if line.startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        # Skip structure, but not a paragraph that merely opens with **bold**.
        if not line or line.startswith(("#", "```", ">", "|", "---", "![", "<", "=")):
            continue
        if re.match(r"^([*+-]|\d+\.)\s", line):      # a list item, not prose
            continue
        line = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", line)
        line = re.sub(r"[`*_]", "", line).strip()
        if len(line) < 25:
            continue
        match = re.match(r"(.{25,%d}?[.!?])(\s|$)" % limit, line)
        return (match.group(1) if match else line)[:limit].strip()
    return ""


def truncate(markdown: str, max_lines: int = 1200, source: str = "") -> str:
    lines = markdown.splitlines()
    if len(lines) <= max_lines:
        return markdown
    kept = "\n".join(lines[:max_lines])
    note = f"\n\n---\n\n*Truncated at {max_lines} lines."
    note += f" Full text: <{source}>*\n" if source else "*\n"
    # Never leave a dangling code fence behind.
    if kept.count("```") % 2:
        kept += "\n```"
    return kept + note


def write_doc(path: Path, frontmatter: dict[str, Any], body: str) -> None:
    """Write a CTF-Brain document, emitting YAML that is guaranteed to parse."""
    path.parent.mkdir(parents=True, exist_ok=True)
    out = ["---"]
    for key, value in frontmatter.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            unique = list(dict.fromkeys(str(v) for v in value if str(v).strip()))
            out.append(f"{key}: [{', '.join(yaml_quote(v) for v in unique)}]")
        elif isinstance(value, dict):
            out.append(f"{key}:")
            for sub, subval in value.items():
                if subval in (None, "", []):
                    continue
                rendered = subval if isinstance(subval, int) else yaml_quote(subval)
                out.append(f"  {sub}: {rendered}")
        elif isinstance(value, int) and not isinstance(value, bool):
            out.append(f"{key}: {value}")
        else:
            out.append(f"{key}: {yaml_quote(value)}")
    out.append("---")
    out.append("")
    out.append(body.strip())
    out.append("")
    # Never mirror a live credential, even one already public upstream.
    text, _ = redact_secrets("\n".join(out))
    path.write_text(text, encoding="utf-8")


# ------------------------------------------------------------------ http + cache
class Fetcher:
    """Cached, rate-limited HTTP with retries. Re-runs cost nothing."""

    def __init__(self, cache_dir: Path, rate: float = 2.0, timeout: int = 25):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.min_interval = 1.0 / rate if rate > 0 else 0.0
        self.timeout = timeout
        self._last = 0.0
        self._lock = threading.Lock()
        import requests
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.stats = {"hit": 0, "miss": 0, "fail": 0}

    def _path(self, url: str, suffix: str = ".html") -> Path:
        return self.cache_dir / (hashlib.sha256(url.encode()).hexdigest()[:24] + suffix)

    def _throttle(self) -> None:
        with self._lock:
            wait = self.min_interval - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()

    def get(self, url: str, *, suffix: str = ".html", retries: int = 3,
            force: bool = False) -> str | None:
        cache = self._path(url, suffix)
        if cache.exists() and not force:
            self.stats["hit"] += 1
            text = cache.read_text(encoding="utf-8", errors="replace")
            return None if text == "\x00FAILED" else text

        for attempt in range(retries):
            self._throttle()
            try:
                res = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if res.status_code == 200:
                    ctype = res.headers.get("Content-Type", "")
                    if any(b in ctype for b in ("pdf", "image/", "video/", "zip", "octet-stream")):
                        cache.write_text("\x00FAILED", encoding="utf-8")
                        self.stats["fail"] += 1
                        return None
                    cache.write_text(res.text, encoding="utf-8")
                    self.stats["miss"] += 1
                    return res.text
                if res.status_code in (404, 410, 403, 401):
                    cache.write_text("\x00FAILED", encoding="utf-8")
                    self.stats["fail"] += 1
                    return None
                time.sleep(1.5 * (attempt + 1))
            except Exception:                       # noqa: BLE001 - network is hostile
                time.sleep(1.5 * (attempt + 1))
        cache.write_text("\x00FAILED", encoding="utf-8")
        self.stats["fail"] += 1
        return None


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")


def load_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:                               # noqa: BLE001
        return default


# ------------------------------------------------------------------ redaction
# Ingested writeups sometimes carry real credentials: CTF challenge artifacts,
# or keys from deliberately-vulnerable ranges like flaws.cloud. They are already
# public upstream, but mirroring them verbatim means republishing live-format
# credentials, and GitHub push protection rejects a repository that contains
# them. The value of a writeup is the method, not the key, so redact the value
# and keep the shape so the page still reads correctly.
REDACTIONS: tuple[tuple[str, "re.Pattern[str]", str], ...] = (
    # AWS. Keep the documented examples, which are fake by definition.
    ("aws-access-key-id", re.compile(r"\b(AKIA)(?!IOSFODNN7EXAMPLE|ABCDEFGHIJKLMNOP)[0-9A-Z]{16}\b"),
     r"\1XXXXXXXXXXXXXXXX"),
    ("aws-temp-access-key", re.compile(r"\b(ASIA)(?!IOSFODNN7EXAMPLE)[0-9A-Z]{16}\b"),
     r"\1XXXXXXXXXXXXXXXX"),
    ("aws-secret-access-key", re.compile(
        r"(?i)(\"?(?:aws[_ -]?)?secret[_ -]?(?:access[_ -]?)?key\"?\s*[:=]\s*\"?)"
        r"[A-Za-z0-9/+=]{40}\b"),
     r"\1[REDACTED-AWS-SECRET]"),
    ("aws-secret-bare", re.compile(r"(?i)(\bSecret:\s*)[A-Za-z0-9/+=]{40}\b"),
     r"\1[REDACTED-AWS-SECRET]"),
    ("aws-session-token", re.compile(
        r"(?i)((?:aws_session_)?\"?Token\"?\s*[:=]\s*\"?)(?:IQoJ|FwoG|FQoG)[A-Za-z0-9/+=]{50,}"),
     r"\1[REDACTED-AWS-SESSION-TOKEN]"),
    # Asana personal access token: 1/<16 digits>:<32 hex>
    ("asana-pat", re.compile(r"\b\d/\d{16}:[0-9a-f]{32}\b"), "[REDACTED-ASANA-PAT]"),
    # Google / Firebase API key
    ("google-api-key", re.compile(r"\bAIzaSy[A-Za-z0-9_\-]{33}\b"), "AIzaSy[REDACTED]"),
    # GitHub tokens
    ("github-token", re.compile(
        r"\b(gh[pousr]_)(?!abcdefghijklmnopqrstuvwxyz)[A-Za-z0-9]{36}\b"), r"\1[REDACTED]"),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"), "github_pat_[REDACTED]"),
    # Slack, GitLab, SendGrid, npm, Stripe, OpenAI, Anthropic
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"), "xox[REDACTED]"),
    ("gitlab-pat", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"), "glpat-[REDACTED]"),
    ("sendgrid", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "SG.[REDACTED]"),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "npm_[REDACTED]"),
    ("stripe-key", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b"), "[REDACTED-STRIPE-KEY]"),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{40,}\b"), "sk-[REDACTED]"),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), "sk-ant-[REDACTED]"),
    ("private-key-block", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", re.DOTALL),
     "[REDACTED-PRIVATE-KEY-BLOCK]"),
)


def redact_secrets(text: str) -> tuple[str, dict[str, int]]:
    """Strip credential values from a document. Returns (text, counts_by_kind)."""
    counts: dict[str, int] = {}
    for name, pattern, replacement in REDACTIONS:
        text, n = pattern.subn(replacement, text)
        if n:
            counts[name] = counts.get(name, 0) + n
    return text, counts
