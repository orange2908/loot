---
title: "?twinkle-twinkle-trx-star? - TRX CTF 2026"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "xor", "twinkle-twinkle-trx-star", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "The MP3 does not hide the flag in decoded PCM samples or ID3 metadata."
source:
  name: "CTFtime writeup #40720"
  url: "https://ctftime.org/writeup/40720"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-twinkle-twinkle-trx-star-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "?twinkle-twinkle-trx-star?"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** ?twinkle-twinkle-trx-star?
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40720>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-twinkle-twinkle-trx-star-writeup>

---
TL;DR  
The MP3 does not hide the flag in decoded PCM samples or ID3 metadata. The encoder stores encrypted flag bytes in the MP3 frame side-info field main_data_begin.

The supplied song.mp3 contains a sequence of 9-bit main_data_begin values. Reversing the encoder's cumulative/reset transform gives a 68-byte AES-CTR ciphertext. The AES-CTR keystream is controlled by a weak seed:

time.Now().UnixMilli() % 1024  
So there are only 1024 possible keystreams. Patch the encoder to force each seed, encrypt a known plaintext of the same length, recover the keystream, and XOR it with the target ciphertext.

Initial inspection
