---
title: "0 Introduction - 2 Labs"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "introduction", "cryptography", "0-introduction", "2-labs", "adamkadaban"]
summary: "crypto writeup for \"0 Introduction\" from 2 Labs - techniques: introduction, cryptography, 0-introduction, 2-labs, adamkadaban."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/2.Labs/CryptoHack/0.Introduction/README.md"
ctf:
  name: "2 Labs"
  challenge: "0 Introduction"
---

## Source

- **CTF:** 2 Labs
- **Challenge:** 0 Introduction
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/2.Labs/CryptoHack/0.Introduction/README.md>

---
# Finding Flags
* Submit the given flag: `crypto{y0ur_f1rst_fl4g}`

# Great Snakes
* Download the program with `wget "https://cryptohack.org/static/challenges/great_snakes_35381fca29d68d8f3f25c9fa0a9026fb.py -O program.py"`
* Run it with `python3 program.py` to get the flag: `crypto{z3n_0f_pyth0n}`

# Network Attacks
* The program asks to `Send a JSON object with the key buy and value flag`
	* Thus, connect with `nc socket.cryptohack.org 11112` and type in `{"buy": "flag"}` to get the flag: `crypto{sh0pp1ng_f0r_fl4g5}`

* We could also download the python file and download the code in the `request` variable to look like the following:
```python3
request = {
    "buy": "flag"
}
```
