---
title: "Eggs Over Easy - BlueHens CTF 2026"
category: "misc"
type: "writeup"
tags: ["misc", "unicode-normalization", "eggs", "easy", "bluehens-ctf", "bluehens-ctf-2026", "2026", "ctf-writeup"]
summary: "In this challenge, I was given a file that appeared to contain no visible text at first glance."
source:
  name: "CTFtime writeup #40699"
  url: "https://ctftime.org/writeup/40699"
original_source: "https://github.com/pnimtsovych/WriteUp/tree/main/Eggs%20Over%20Easy(BlueHens%20CTF%202026)"
ctf:
  name: "BlueHens CTF 2026"
  year: 2026
  challenge: "Eggs Over Easy"
---

## Metadata

- **CTF:** BlueHens CTF 2026
- **Task:** Eggs Over Easy
- **Author team:** LeetSh4d0ws
- **CTFtime:** <https://ctftime.org/writeup/40699>
- **Original writeup:** <https://github.com/pnimtsovych/WriteUp/tree/main/Eggs%20Over%20Easy(BlueHens%20CTF%202026)>

---
# Eggs Over Easy — Writeup

## Description

In this challenge, I was given a file that appeared to contain no visible text at first glance. After closer inspection, I noticed that the file consisted only of two types of whitespace characters:

\- `space`  
\- `tab`

Since there were only two possible symbols, this strongly suggested binary encoding.

I mapped them as follows:

\- `space = 0`  
\- `tab = 1`

## Solution

First, I converted the full sequence of spaces and tabs into a bitstring using that mapping.   
Then I split the bitstring into groups of 8 bits and converted each group into its ASCII representation.

This produced the following intermediate result:

```text  
ff35 ff24 ff23 ff34 46 ff5b ff22 ff14 ff43 ff4f ff4e ff5d  
```

This was not the final flag yet, but it clearly looked like a sequence of hexadecimal Unicode code points.   
Most of the values started with `FF`, which is commonly associated with fullwidth Unicode characters.

After converting each hexadecimal value into its corresponding Unicode character, I obtained:

```text  
ＵＤＣＴF｛Ｂ４ｃｏｎ｝  
```

At this point, it became clear that the text was written mostly with fullwidth Unicode symbols instead of standard ASCII characters.   
By applying Unicode normalization with `NFKC`, those fullwidth symbols were converted into normal ASCII text.

The final decoded flag was:

```text  
UDCTF{B4con}  
```

## Hint Analysis

The challenge hint said:

> If you know what goes well with eggs, this will be over easily...

This points to **bacon**, which matches the last part of the decoded flag and confirms that the solution is correct.

## Final Flag

```text  
UDCTF{B4con}  
```

## Solver Script

```python  
from pathlib import Path  
import unicodedata

filename = "txt (7)"

data = Path(filename).read_text()

# space = 0, tab = 1  
bits = ''.join('0' if ch == ' ' else '1' for ch in data)

# Convert every 8 bits into ASCII  
hex_text = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))

# Split hex tokens  
tokens = hex_text.split()

# Convert hex -> Unicode characters  
decoded = ''.join(chr(int(token, 16)) for token in tokens)

# Normalize fullwidth Unicode characters into normal ASCII  
flag = unicodedata.normalize("NFKC", decoded)

print("Intermediate:", hex_text)  
print("Decoded:", decoded)  
print("Flag:", flag)  
```
