---
title: "Git is Fun - ShadowCTF"
category: "misc"
subcategory: "aes"
type: "writeup"
tags: ["misc", "aes", "caesar", "base32", "git", "fun"]
summary: "misc writeup for \"Git is Fun\" from ShadowCTF - techniques: aes, caesar, base32, git, fun."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/ShadowCTF/misc/Git%20is%20Fun/README.md"
ctf:
  name: "ShadowCTF"
  challenge: "Git is Fun"
---

## Source

- **CTF:** ShadowCTF
- **Challenge:** Git is Fun
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/ShadowCTF/misc/Git%20is%20Fun/README.md>

---
* Going to the git repo, we can look at all previous commits
	* [This](https://github.com/purabparihar/test/commit/45cd54d1d02059dc976947a486fc1e0761c38ea9) one has a base32 string: `PFXGO2TVMNEVUTD3IUYGCX3NGBNF66SOGF4V6TBBORAFEUTFPU======`
	* We can decode that with `echo PFXGO2TVMNEVUTD3IUYGCX3NGBNF66SOGF4V6TBBORAFEUTFPU====== | base32 -d` to get `yngjucIZL{E0a_m0Z_zN1y_L!t@RRe}`

* This looks like it could be a shift cipher, so we can put it [here](https://www.dcode.fr/caesar-cipher) to autosolve
	* The shift is 6 and the flag is `shadowCTF{Y0u_g0T_tH1s_F!n@LLy}`
