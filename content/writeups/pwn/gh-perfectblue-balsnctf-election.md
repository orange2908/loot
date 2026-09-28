---
title: "election - BalsnCTF 2020"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "election", "binary-exploitation", "balsnctf", "perfectblue", "ctf-writeups"]
summary: "pwn writeup for \"election\" from BalsnCTF - techniques: election, binary-exploitation, balsnctf, perfectblue, ctf-writeups."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/BalsnCTF/election/README.md"
ctf:
  name: "BalsnCTF"
  year: 2020
  challenge: "election"
---

## Source

- **CTF:** BalsnCTF 2020
- **Challenge:** election
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/BalsnCTF/election/README.md>

---
# Election

TLDR:
![](https://raw.githubusercontent.com/perfectblue/ctf-writeups/db9b964bf35c210567ea508383e91a9c423adaee/2020/BalsnCTF/election/sice.png)

- One issue was to the call to `proposal()` from the customFallback had a different method signature, but the way arguments are encoded in the ABI, you could control the `value` in the customFallback to control the offset for the Proposal struct in `propose()`
- Then you can create an arbitrary Proposal in the data parameter.
- Look at `add_proposal()` in [exploit.js](https://raw.githubusercontent.com/perfectblue/ctf-writeups/db9b964bf35c210567ea508383e91a9c423adaee/2020/BalsnCTF/election/exploit.js) for more details. 
- I also modified the Election.sol and added a couple helper functions to encode the parameters.
