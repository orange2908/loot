---
title: "Larping 101 - CTF@CIT 2026"
category: "crypto"
type: "writeup"
tags: ["crypto", "larping", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "The PowerPoint file is a normal OOXML container."
source:
  name: "CTFtime writeup #40732"
  url: "https://ctftime.org/writeup/40732"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Larping 101"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Larping 101
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40732>

---
# Writeup: Larping 101

## TL;DR

The PowerPoint file is a normal OOXML container.  
The flag is hidden in an extra XML part inside the archive:

```text  
ppt/slides/transitions.xml  
```

That file contains:

```text  
CIT{l4rp_l4rp_l4rp_s4hur}  
```

## Recon

The attachment is `challenge.pptx`.  
Since `.pptx` files are zip archives, the fastest path is to inspect the internal XML parts directly.

Useful checks:

```bash  
sha1sum files/challenge.pptx  
unzip -l files/challenge.pptx  
zipinfo -1 files/challenge.pptx  
```

The package is small:

\- 4 slides  
\- 5 images  
\- no notes  
\- no comments  
\- no embedded files

That makes hidden XML metadata the most likely place to look.

## Solve

Dumping the XML parts shows an unusual file:

```text  
ppt/slides/transitions.xml  
```

It is not a standard slide content file and contains debug-style fields:

```xml  
<p:debug>  
<p:log level="info">transition engine initialized</p:log>  
<p:log level="warning">compatibility mode enabled</p:log>  
<p:reserved>  
CIT{l4rp_l4rp_l4rp_s4hur}  
</p:reserved>  
</p:debug>  
```

So the flag is directly embedded in that hidden archive member.

## Artifacts

\- `scripts/[solve.py](http://solve.py)` verifies the SHA1 and extracts the flag from the OOXML zip  
\- `other/transitions.xml` stores the interesting hidden XML part  
\- `solution/flag.txt` stores the solved flag

## Flag

`CIT{l4rp_l4rp_l4rp_s4hur}`
