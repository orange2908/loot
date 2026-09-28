---
title: "cybergrabs - CTFs"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "jwt", "steghide", "hashcat", "sqlite", "wordlists"]
summary: "apt-get install linux-headers-$(uname -r) build-essential"
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/cybergrabs/README.md"
ctf:
  name: "CTFs"
  challenge: "cybergrabs"
---

## Source

- **CTF:** CTFs
- **Challenge:** cybergrabs
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/cybergrabs/README.md>

---
# Random
`apt-get install linux-headers-$(uname -r) build-essential`

# Forensics

### Jasper
* strings and grep

### stargazer

* recup_dir.16/f2131472.sqlite
* recup_dir.16/f2121232.sqlite


# Crypto
### Easiest One
* `cybergrabs{1S_TH1S_A_M0RS3_C0D3?}`
* Run it through site a few times

### everyone insterested in my secret life
* jwt crack
* `john secret_life.txt --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt`

# Misc
### Salt is the Important incrident
* use hashcat with the hash and 0namak0
* steghide the images in the directory
* look at the hint and use that to make the password for the pdf
