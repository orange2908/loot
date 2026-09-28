---
title: "Hand-Work - ShadowCTF"
category: "crypto"
subcategory: "audio"
type: "writeup"
tags: ["crypto", "morse", "hand-work", "audio", "cryptography", "shadowctf"]
summary: "crypto writeup for \"Hand-Work\" from ShadowCTF - techniques: morse, hand-work, audio, cryptography, shadowctf."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/ShadowCTF/Crypto/Hand-Work/README.md"
ctf:
  name: "ShadowCTF"
  challenge: "Hand-Work"
---

## Source

- **CTF:** ShadowCTF
- **Challenge:** Hand-Work
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/ShadowCTF/Crypto/Hand-Work/README.md>

---
* This is clearly spoken morse code
* I uploaded the file to a [Speech-to-text engine](https://speech-to-text-demo.ng.bluemix.net/) and got all the words
* I then put it into a file and used python to convert to actual dots, spaces, and dashes: 

```python3
x = "dotdotdotspacedotdotdotdotspacedotdashspacedashdotdotspacedashdashdashspacedotdashdashspacedashdotdashdotspacedashdotdotdashdotspacedotspacedotdotdotdotdashspacedotdotdotspacedashdotdashdashspacedashdotdashdotspacedotdashdotspacedashdotdashdashspacedotdashdashdotspacedashspacedashdashdashdashdash"

newString = x.replace("dot",".").replace("space"," ").replace("dash","-")

print(newString)
```
* That gave me: `... .... .- -.. --- .-- -.-. -..-. . ....- ... -.-- -.-. .-. -.-- .--. - -----`

* We can then translate the morse code [here](https://morsecode.world/international/translator.html)
	* This got me `SHADOWC/E4SYCRYPT0`

* The flag is `ShadowCTF{e4sycrypt0}`
