---
title: "rdctd 1-6 - Nullcon Goa HackIM 2026 CTF"
category: "rev"
subcategory: "metadata"
type: "writeup"
tags: ["rev", "exiftool", "qr-code", "rdctd", "metadata", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Analyze a PDF document to find the flag containing the digit 1."
source:
  name: "CTFtime writeup #40632"
  url: "https://ctftime.org/writeup/40632"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "rdctd 1-6"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** rdctd 1-6
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40632>

---
### rdctd 1

**Challenge Description**:  
Analyze a PDF document to find the flag containing the digit `1`.

**Analysis**:  
The PDF `Planned-Flags-signed-2.pdf` contains several flags in different states of redaction. By searching the uncompressed PDF streams, we found:  
\- An unredacted flag in Section 3.4: `ENO{stability_gradient_1_disrupted}`.

**Flag**:  
`ENO{stability_gradient_1_disrupted}`

### rdctd 2

**Challenge Description**:  
Analyze same PDF document to find the flag containing the digit `2`.

**Analysis**:  
Searching the uncompressed PDF revealed URI annotations (links) that contained a flag:  
\- `<https://ctf.nullcon.net/ENO>{input_sanitization_2_is_overrated}`

**Flag**:  
`ENO{input_sanitization_2_is_overrated}`

### rdctd_3

**Challenge Description**:  
Analyze an image `image-000.png` extracted from the PDF to find the flag containing the digit `3`.

**Analysis**:  
The image contains blurred text which was identified as `ENO{semantic_3_inference_initialized}`. This flag fits the pattern and contains the digit `3`.

**Flag**: `ENO{semantic_3_inference_initialized}`

### rdctd_4

**Challenge Description**:  
Analyze the PDF to find the flag containing the digit `4`.

**Analysis**:  
The PDF contained a hidden QR code. Scanning the QR code revealed the flag.

**Flag**: `ENO{We_should_have_an_Ontology_to_4_categorize_our_ontologies}`

### rdctd_5

**Challenge Description**:  
Analyze the PDF to find the flag containing the digit `5`.

**Analysis**:  
Iterating through all objects in the PDF's cross-reference table (xref) and searching for the string format `ENO{...}` revealed the flag hidden within a raw object.

**Flag**: `ENO{SIGN_HERE_TO_GET_ALL_FLAGS_5}`

### rdctd 6

**Challenge Description**:  
Analyze same PDF document to find the flag containing the digit `6`.

**Analysis**:  
Inspecting the PDF metadata using `exiftool` revealed a flag in the `Producer` field which contains the digit `6` (as part of `76`):  
\- `ENO{secureflaghidingsystem76}`

**Flag**:  
`ENO{secureflaghidingsystem76}`
