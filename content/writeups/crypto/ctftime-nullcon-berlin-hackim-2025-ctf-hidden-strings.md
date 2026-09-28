---
title: "hidden_strings - Nullcon Berlin HackIM 2025 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "hidden", "strings", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We are given a binary called challenge."
source:
  name: "CTFtime writeup #40403"
  url: "https://ctftime.org/writeup/40403"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "hidden_strings"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** hidden_strings
- **Author team:** numatrixx
- **CTFtime:** <https://ctftime.org/writeup/40403>

---
# Hidden Strings Challenge Writeup

## Challenge Description  
We are given a binary called `challenge`. Running it shows prompts, but when checking with `strings`, we see almost nothing useful. The task is to understand **where these strings are coming from** and to recover the flag.

The challenge note also hints:   
> for the flag use the part of it that looks like it might make sense, slight bug in the challenge :)

\---

## Step 1: Initial Recon  
\- Running `strings challenge` shows very few readable values.  
\- That means the binary is not storing its prompts in cleartext, but rather **encoded/hidden**.

Disassembling reveals a function around `0x1550 – 0x15e0` that loads entries from a table at `.data:0x4160`.   
Each entry has the structure:

```  
struct entry {  
uint64_t ptr_to_bytes;  
uint64_t length;  
uint64_t xor_key_byte;  
}  
```

At runtime, the binary:  
1\. Reads the bytes at `ptr_to_bytes`,  
2\. XORs each byte with `xor_key_byte`,  
3\. Prints the decoded string,  
4\. Then re-applies XOR to restore it.

That’s why the `strings` tool does not show them.

\---

## Step 2: Flag Checking Logic  
The flag verification logic is as follows:

1\. Input must start with `ENO{` and end with `}`.  
2\. The whole input string is **XORed with 0x61**.  
3\. The binary iterates over a small program stored at `.rodata:0x2020`:  
\- 16 pairs of `(index, offset)` bytes.  
\- For each pair:  
\- Decode the string with that `index` from the hidden table.  
\- Take the character at position `offset`.  
\- XOR it with `0x61`.  
\- Compare with the corresponding byte from your input.

Because both sides are XORed with `0x61`, the algebra cancels.   
So the **raw input characters must match those extracted from the hidden table.**

\---

## Step 3: The Bug in the Challenge  
The code mistakenly expects **17 bytes** of payload (`rbx + 0x11`) but there are only **16 `(index, offset)` pairs**.   
The last lookup reads garbage (`index = 0x30` → out of range). This makes the check always fail.   
That is why you never see a "Correct!" output even with the right input.

The challenge author hinted this with:   
> use the part of it that looks like it might make sense

\---

## Step 4: Extracting the Payload  
We decode all entries and apply the 16 valid `(index, offset)` pairs. This yields the candidate payload:

```  
stackxorrockswww  
```

Appending the required format `ENO{...}`:

```  
ENO{stackxorrockswww}  
```

But because of the bug, the sensible intended flag is:

```  
ENO{stackxorrocks}  
```

\---

## Step 5: Python Extraction Script  
Here is a Python script to automate extraction:

```python  
import struct

b = open("challenge", "rb").read()

DATA_VA, DATA_OFF = 0x4000, 0x3000  
TABLE_VA, ENTRY_SZ = 0x4160, 0x18  
table_off = DATA_OFF + (TABLE_VA - DATA_VA)

entries=[]  
for i in range(48):  
off = table_off + i*ENTRY_SZ  
ptr, ln, key = struct.unpack_from("
