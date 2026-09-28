"""Central configuration for CTF-Brain."""
from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------- paths
ROOT = Path(os.environ.get("CTFBRAIN_ROOT", Path(__file__).resolve().parent.parent))
CONTENT_DIR = Path(os.environ.get("CTFBRAIN_CONTENT", ROOT / "content"))
DATA_DIR = Path(os.environ.get("CTFBRAIN_DATA", ROOT / "data"))
VENDOR_DIR = ROOT / "vendor"
INDEX_DB = Path(os.environ.get("CTFBRAIN_DB", DATA_DIR / "index.db"))

# ---------------------------------------------------------------- taxonomy
CATEGORIES = [
    "crypto", "web", "pwn", "rev", "forensics", "stego",
    "misc", "osint", "mobile", "hardware", "blockchain", "cloud",
    "sherlocks",
]

CATEGORY_META = {
    "crypto":     ("Cryptography",  "#8b5cf6", "RSA, AES, ECC, lattices, PRNG, classical"),
    "web":        ("Web",           "#06b6d4", "Injection, SSTI, deserialization, JWT, SSRF"),
    "pwn":        ("Binary Exploit","#ef4444", "Stack, ROP, heap, kernel, format string"),
    "rev":        ("Reversing",     "#f59e0b", "Ghidra, angr, packers, obfuscation, VMs"),
    "forensics":  ("Forensics",     "#10b981", "Memory, disk, pcap, logs, documents"),
    "stego":      ("Steganography", "#ec4899", "Images, audio, polyglots, archives"),
    "misc":       ("Misc",          "#64748b", "Jails, recon, AD, esolangs, PoW"),
    "osint":      ("OSINT",         "#14b8a6", "People, geolocation, infrastructure"),
    "mobile":     ("Mobile",        "#a3e635", "Android, iOS, Frida, APK"),
    "hardware":   ("Hardware",      "#f97316", "Firmware, UART, JTAG, SDR, side channel"),
    "blockchain": ("Blockchain",    "#eab308", "Solidity, EVM, DeFi, Foundry"),
    "cloud":      ("Cloud",         "#3b82f6", "K8s, containers, AWS/GCP/Azure, CI/CD"),
    "sherlocks":  ("Sherlocks",     "#0ea5e9", "HTB blue team / DFIR: evtx, pcap, AD attack detection"),
}

DOC_TYPES = ["playbook", "cheatsheet", "technique", "script", "writeup", "tool", "reference"]

# Ordering used to break ties: what is most useful when you are mid-CTF.
TYPE_PRIORITY = {
    "playbook": 0, "cheatsheet": 1, "technique": 2, "script": 3,
    "tool": 4, "reference": 5, "writeup": 6,
}

DIFFICULTIES = ["trivial", "easy", "medium", "hard", "insane"]

# ---------------------------------------------------------------- ranking
# BM25 column weights. Order MUST match the FTS5 column order in index.py.
# (title, tags, summary, when_to_use, headings, body, code)
BM25_WEIGHTS = (12.0, 10.0, 6.0, 5.0, 3.0, 1.0, 0.7)

# Additive score bonuses applied after BM25.
BONUS_EXACT_TAG = 6.0      # query term is verbatim one of the doc's tags
BONUS_TITLE_SUB = 4.0      # query appears as a substring of the title
BONUS_SUBCATEGORY = 2.0    # query term matches the subcategory
TYPE_BONUS = {             # nudge the actionable stuff above raw writeups
    "playbook": 3.0, "cheatsheet": 2.5, "technique": 2.0,
    "script": 1.5, "tool": 1.0, "reference": 0.5, "writeup": 0.0,
}

SNIPPET_TOKENS = 28
