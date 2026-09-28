---
title: "Booking Key - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "cry", "eval", "booking", "key", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40651"
  url: "https://ctftime.org/writeup/40651"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Crypto/Booking_Key/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Booking Key"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Booking Key
- **Author team:** RootRunners
- **CTFtime tags:** cry
- **CTFtime:** <https://ctftime.org/writeup/40651>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Crypto/Booking_Key/README.md>

---
# Booking Key

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Crypto   
**Points:** 113   
**Service:** `52.59.124.14:5102` 

## Overview  
The service returns a list of integers and asks for the corresponding password. The challenge is a book cipher based on a known text (Alice's Adventures in Wonderland). Each integer is the distance from the current cursor position to the next occurrence of the next password character in the book, wrapping around the end.

## Key Insight  
If the book text is known, each starting position defines a unique walk:  
\- For distance `d`, the next character is `book[(pos + d) % L]`.  
\- The distance must match the next occurrence of that character from the current position.

This allows brute-forcing the starting index and recovering the full password. Line endings matter, so we try both LF and CRLF versions of the book.

## Solution  
1\. Load the book text (or the prompt) and build a distance-to-next-occurrence table for each letter.  
2\. For each possible start index, walk the cipher distances and check consistency.  
3\. Submit the derived password to the server three times.  
4\. Read the final output (flag).

## Exploit Script  
```python  
#!/usr/bin/env python3  
import socket  
import ast  
import string  
import urllib.request  
from pathlib import Path

HOST = "52.59.124.14"  
PORT = 5102

BOOK_URL = "<https://www.gutenberg.org/cache/epub/19033/pg19033.txt>"  
BOOK_FILE = Path(__file__).with_name("book_19033_trimmed.txt")  
BOOK_PROMPT = Path(__file__).with_name("book_prompt.txt")

def load_books():  
if BOOK_PROMPT.exists():  
txt = BOOK_PROMPT.read_text(encoding="utf-8")  
return txt, txt.replace("\n", "\r\n")  
if BOOK_FILE.exists():  
trimmed = BOOK_FILE.read_text(encoding="utf-8")  
return trimmed, trimmed.replace("\n", "\r\n")

raw = urllib.request.urlopen(BOOK_URL, timeout=10).read().decode("utf-8-sig")  
lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")

target = "[Illustration: Alice in the Room of the Duchess.]"  
start_idx = None  
for i, line in enumerate(lines):  
if target in line:  
start_idx = i  
break  
if start_idx is None:  
raise ValueError("illustration line not found")

header = "Produced by Jason Isbell, Irma Spehar, and the Online Distributed Proofreading Team at <http://www.pgdp.net>"  
trimmed = header + "\n\n" + "\n".join(lines[start_idx:])

BOOK_FILE.write_text(trimmed, encoding="utf-8")  
return trimmed, trimmed.replace("\n", "\r\n")

def build_next_dist(book, charset):  
L = len(book)  
next_dist = {c: [0] * L for c in charset}  
for c in charset:  
positions = [i for i, ch in enumerate(book) if ch == c]  
if not positions:  
continue  
idx = 0  
for i in range(L):  
while idx < len(positions) and positions[idx] < i:  
idx += 1  
if idx < len(positions):  
pos = positions[idx]  
next_dist[c][i] = pos - i  
else:  
pos = positions[0]  
next_dist[c][i] = (pos + L) - i  
return next_dist

def derive_password(cipher, book, next_dist, charset):  
L = len(book)  
candidates = []  
for start in range(L):  
current = start  
pwd = []  
ok = True  
for count in cipher:  
target = (current + count) % L  
ch = book[target]  
if ch not in next_dist:  
ok = False  
break  
if next_dist[ch][current] != count:  
ok = False  
break  
pwd.append(ch)  
current = target  
if ok:  
candidates.append("".join(pwd))  
if len(candidates) > 2:  
break  
if not candidates:  
return None  
letters = [p for p in candidates if all(c in charset for c in p)]  
if letters:  
return letters[0]  
return candidates[0]

def recv_until(sock, marker: bytes) -> bytes:  
data = b""  
while marker not in data:  
chunk = sock.recv(4096)  
if not chunk:  
break  
data += chunk  
return data

def main():  
book_lf, book_crlf = load_books()  
books = [book_lf, book_crlf]

precomp = []  
for book in books:  
charset = [c for c in string.ascii_letters if c in book]  
next_dist = build_next_dist(book, charset)  
precomp.append((book, charset, next_dist))

s = socket.create_connection((HOST, PORT), timeout=10)  
for _ in range(3):  
data = recv_until(s, b"]")  
lines = data.decode(errors="ignore").split("\n")  
line = lines[-1]  
if "[" not in line:  
for l in lines:  
if "[" in l and "]" in l:  
line = l  
break  
cipher = ast.literal_eval(line.strip())

password = None  
for book, charset, next_dist in precomp:  
password = derive_password(cipher, book, next_dist, charset)  
if password is not None:  
break  
if password is None:  
raise ValueError("no candidates for cipher")

recv_until(s, b"password:")  
s.sendall(password.encode() + b"\n")  
recv_until(s, b"correct")

out = recv_until(s, b"}")  
print(out.decode(errors="ignore"))

if __name__ == "__main__":  
main()  
```

## Flag  
Not available in the provided files.
