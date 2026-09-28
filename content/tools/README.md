---
title: "Reference - Tool Catalog Index"
category: misc
subcategory: tools
type: reference
tags: [tools, tool-index, catalog, which-tool, toolchain, install, ctf-tools, index, readme, what-should-i-use]
summary: "Every tool in CTF-Brain, grouped by category, with one line on what each is for."
related: [ctf-start, stuck, unknown-file, wordlists-and-resources]
---

## How to use this

Find the category you are working in, pick the tool, then `ctfbrain search <slug>` for the install command, the ten invocations that matter, the gotchas and the fallbacks.

If you do not know which category you are in, start from a playbook instead: `ctfbrain search unknown-file`, `ctfbrain search stuck`, or `ctfbrain search ctf-start`.

---

## Reverse engineering

| Tool | One line |
|---|---|
| [`ghidra`](ghidra.md) | Free multi-architecture decompiler with a headless mode for batch analysis |
| [`radare2`](radare2.md) | Scriptable CLI disassembler, debugger and patcher (and its fork rizin / GUI Cutter) |
| [`angr`](angr.md) | Symbolic execution: give it a "win" address and it solves for the input |
| [`z3`](z3.md) | SMT solver: transcribe the binary's checks as equations and get the answer |
| [`jadx`](jadx.md) | Decompile an Android APK or DEX straight to readable Java |
| [`frida`](frida.md) | Inject JavaScript into a live process to hook functions and read real values |

## Binary exploitation

| Tool | One line |
|---|---|
| [`pwntools`](pwntools.md) | The Python exploit framework: tubes, ELF parsing, ROP, shellcode, gdb integration |
| [`gdb-pwndbg-gef`](gdb-pwndbg-gef.md) | The debugger plus the plugins that show you the heap, the registers and the memory map |
| [`ropgadget-ropper`](ropgadget-ropper.md) | Find ROP gadgets, and auto-generate an execve chain for static binaries |
| [`one-gadget`](one-gadget.md) | Find the libc addresses that spawn a shell with a single write, and their constraints |

## Web

| Tool | One line |
|---|---|
| [`burpsuite`](burpsuite.md) | The intercepting proxy: see, modify and replay every request; Repeater and Intruder |
| [`ffuf`](ffuf.md) | Fast fuzzer for directories, files, parameters and vhosts, with precise filtering |
| [`sqlmap`](sqlmap.md) | Automated SQL injection detection, data extraction and sometimes RCE |
| [`jwt-tool`](jwt-tool.md) | Decode, crack and forge JWTs: alg:none, key confusion, weak secrets, kid injection |
| [`nmap`](nmap.md) | Port scanning, service fingerprinting and protocol-specific NSE enumeration |

## Crypto

| Tool | One line |
|---|---|
| [`sagemath`](sagemath.md) | The math system with every algorithm CTF crypto needs: lattices, curves, Coppersmith |
| [`rsactftool`](rsactftool.md) | Throws ~20 classic RSA attacks at a key or an (n, e, c) triple automatically |
| [`factordb`](factordb.md) | Public factorisation database: paste n and you may get p and q for free |
| [`z3`](z3.md) | Also the right tool for constraint-shaped crypto puzzles |
| [`bkcrack`](bkcrack.md) | Breaks ZipCrypto with 12 bytes of known plaintext, no password needed |
| [`hashcat`](hashcat.md) | GPU password cracking, including JWT secrets and archive passwords |
| [`john`](john.md) | CPU cracking with the best format coverage and the `*2john` file converters |

## Forensics

| Tool | One line |
|---|---|
| [`volatility3`](volatility3.md) | Memory-dump analysis: processes, network, files, registry, injected code |
| [`wireshark-tshark`](wireshark-tshark.md) | Read, filter and extract from packet captures; tshark is the scriptable half |
| [`scapy`](scapy.md) | Python packet dissection and crafting, for custom protocols tshark cannot express |
| [`binwalk`](binwalk.md) | Scan any file for embedded signatures and extract what is hidden inside |
| [`exiftool`](exiftool.md) | Read and write metadata in ~100 formats: comments, GPS, thumbnails |

## Steganography

| Tool | One line |
|---|---|
| [`stegsolve-zsteg`](stegsolve-zsteg.md) | zsteg brute-forces LSB encodings; Stegsolve lets you eyeball every bit plane |
| [`aperisolve`](aperisolve.md) | Runs the whole image-stego toolchain at once and shows every result on one page |
| [`binwalk`](binwalk.md) | Also the tool for appended and embedded data in media files |
| [`exiftool`](exiftool.md) | Also the tool for metadata-hidden payloads and EXIF thumbnails |
| [`bkcrack`](bkcrack.md) | For the encrypted ZIP that so often ends a stego chain |

## Mobile

| Tool | One line |
|---|---|
| [`jadx`](jadx.md) | APK/DEX to Java, plus resources and the manifest |
| [`frida`](frida.md) | Runtime hooking on Android and iOS: bypass pinning, read decrypted values |

## Blockchain

| Tool | One line |
|---|---|
| [`foundry-cast`](foundry-cast.md) | cast for RPC and encoding, forge for exploit contracts, anvil for a local fork |

## Encoding, math and glue

| Tool | One line |
|---|---|
| [`cyberchef`](cyberchef.md) | Chain encode/decode/crypto operations, with a Magic auto-detector |
| [`z3`](z3.md) | Constraint solving wherever equations appear |
| [`sagemath`](sagemath.md) | Number theory, polynomials, lattices, finite fields |

---

## The minimum viable toolbox

If you are setting up a machine from scratch before an event, install these first:

```sh
# analysis
pipx install pwntools angr z3-solver ROPgadget ropper volatility3
gem install one_gadget zsteg
sudo apt install gdb radare2 binwalk exiftool tshark foremost sqlmap ffuf \
                 john hashcat nmap p7zip-full libimage-exiftool-perl \
                 steghide outguess pngcheck sox ffmpeg jadx
# then the plugins
git clone --depth 1 https://github.com/pwndbg/pwndbg && ./pwndbg/setup.sh
# and the wordlists
sudo apt install seclists wordlists && sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
```
See `ctfbrain search ctf-start` for the full pre-event checklist and `ctfbrain search wordlists-and-resources` for the wordlist layout.

---

## Picking a tool by symptom

| Symptom | Start with |
|---|---|
| "I have a file and no idea what it is" | `binwalk`, `exiftool`, and `ctfbrain search unknown-file` |
| "I have a binary and a libc" | `pwntools`, `gdb-pwndbg-gef`, `ctfbrain search pwn-triage` |
| "I have a binary to reverse" | `ghidra`, then `z3` or `angr` |
| "I have a URL" | `burpsuite`, `ffuf`, `ctfbrain search web-triage` |
| "I have n, e, c" | `factordb`, `rsactftool`, `ctfbrain search rsa-decision-tree` |
| "I have a pcap" | `wireshark-tshark`, then `scapy` for anything custom |
| "I have a memory dump" | `volatility3` (and `strings` first) |
| "I have an image" | `aperisolve` or `stegsolve-zsteg`, plus `exiftool` and `binwalk` |
| "I have an encrypted ZIP" | `bkcrack` if ZipCrypto, `john`/`hashcat` if AES |
| "I have a token starting with eyJ" | `jwt-tool` |
| "I have an APK" | `jadx`, then `frida` |
| "I have a smart contract" | `foundry-cast` |
| "I have a blob of weird text" | `cyberchef`, `ctfbrain search encoding-detection` |
| "I have `nc host port`" | `pwntools`, `ctfbrain search remote-service` |
| "I have been stuck for 30 minutes" | `ctfbrain search stuck` |
