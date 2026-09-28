---
title: "Stego (HackTricks)"
category: "stego"
subcategory: "stego"
type: "reference"
tags: ["hacktricks", "stego", "lsb", "spectrogram", "zero-width", "entry-point", "entry", "point"]
summary: "This section focuses on finding and extracting hidden data from images, audio, video, documents, archives, and text."
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/stego/README.md"
license: "CC BY-NC 4.0"
---

# Stego


This section focuses on **finding and extracting hidden data** from images, audio, video, documents, archives, and text. Steganography conceals the existence of a communication by embedding data inside other data.<sup>[[1]](#references)</sup>

If you're here for cryptographic attacks, go to the **Crypto** section.

## Entry Point

Approach steganography as a forensics problem: identify the real container, enumerate high-signal locations (metadata, appended data, embedded files), and only then apply content-level extraction techniques.

### Workflow & triage

A structured workflow that prioritizes container identification, metadata/string inspection, carving, and format-specific branching.

workflow/README.md

### Images

Where most CTF stego lives: LSB/bit-planes (PNG/BMP), chunk/file-format weirdness, JPEG tooling, and multi-frame GIF tricks.

images/README.md

### Audio

Spectrogram messages, sample LSB embedding, and telephone keypad tones (DTMF) are recurring patterns.

audio/README.md

### Text

If text renders normally but behaves unexpectedly, consider Unicode homoglyphs, zero-width characters, or whitespace-based encoding.

text/README.md

### Documents

PDFs and Office files are containers first; attacks usually revolve around embedded files/streams, object/relationship graphs, and ZIP extraction.

documents/README.md

### Malware and delivery-style steganography

Payload delivery can use valid-looking files, such as GIF or PNG images, that carry marker-delimited text payloads rather than hiding data in pixels.

malware-and-network/README.md

## References

- [1] [NIST CSRC Glossary - Steganography](https://csrc.nist.gov/glossary/term/steganography)

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/stego/README.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.
