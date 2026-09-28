---
title: "Peel Carefully - CTF@CIT 2026"
category: "crypto"
subcategory: "audio"
type: "writeup"
tags: ["crypto", "morse", "base64", "peel", "carefully", "audio", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "challenge.txt is plain Morse code."
source:
  name: "CTFtime writeup #40744"
  url: "https://ctftime.org/writeup/40744"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Peel Carefully"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Peel Carefully
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40744>

---
# Peel Carefully — Writeup

\- Category: Misc  
\- Value: 995  
\- Author: 10splayaSec

## Challenge

> It's all there, just buried.  
>  
> One layer at a time, the message reveals itself... can you read it?  
>  
> **SHA1:** `b7ac0151a536f150b4a2c41e456482513125267c`

## Recon

`challenge.txt` is plain Morse code.  
Decoding it does not give English text; it gives a long DNA-looking string made only of `A`, `C`, `G`, and `T`.

Splitting that DNA into codons shows one obvious oddity: `ATG` appears over and over.  
Treating `ATG` as a separator/start codon and removing it leaves a stream built from exactly 16 distinct codons:

```text  
GGA GGC GGG GGT GTA GTC TCG TCT TGA TGC TGG TGT TTA TTC TTG TTT  
```

That is the right size for a 4-bit alphabet.

## Solve

The clean decoding chain is:

1\. Morse -> DNA string.  
2\. DNA -> codons, dropping every `ATG`.  
3\. Sort the 16 remaining codons alphabetically.  
4\. Map each sorted codon to a nibble with a rotation of `6`, i.e. `value = (index - 6) mod 16`.  
5\. Join those nibbles into hex and decode the bytes.

Those bytes are not the flag yet; they form this Base64 string:

```text  
5ZWJ6bW08JONr+m1p+WVtOm1tPCTgaXllaXpqbfpqbLmrKDmqLXmrLPwkoSg8JOBr/CThbTllKzwk42i5ZW05ZWJ8JONp/CThaXllbPllYnpmbfllbPwk4G38JCZr+aFp+m4oOWVtOmZt+WVs+aotuagteaMteO4jeO4jee5g/CghZTqlLPmoaLpkaTqjYDpkazwkJiz5pWj5pmk6bGu8KCMtQ==  
```

Base64-decoding that yields a 50-character Unicode string:

```text  
啉鵴?鵧啴鵴?啥驷驲欠樵欳???唬?啴啉??啳啉陷啳??慧鸠啴陷啳樶栵挵㸍㸍繃?ꔳ桢鑤ꍀ鑬?散晤鱮?  
```

That glyph soup is valid `base65536`.  
Decoding it directly produces the final plaintext:

```text  
I thought there were 65536 ports, but I guess I was wrong, it was 65535.

CIT{3mb3d_@ll_3nc0d1ng5}  
```

The `65536` clue is the giveaway: the Unicode layer is not meant to be read by eye or stripped by byte, it is a `base65536` payload.

## Flag

```text  
CIT{3mb3d_@ll_3nc0d1ng5}  
```

## Files

\- [scripts/[solve.py](http://solve.py)](scripts/[solve.py](http://solve.py))  
\- [solution/flag.txt](solution/flag.txt)  
\- [other/unicode_layer.txt](other/unicode_layer.txt)  
\- [other/final_phrase.txt](other/final_phrase.txt)
