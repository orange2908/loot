---
title: "semaphore - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "substitution-cipher", "semaphore", "classical", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We were given a GIF of a person waving a flag."
source:
  name: "CTFtime writeup #39976"
  url: "https://ctftime.org/writeup/39976"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/BkBcs18Yyg"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "semaphore"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** semaphore
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39976>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/BkBcs18Yyg>

---
We were given a GIF of a person waving a flag. The objective was to extract the hidden flag from the GIF. Extracted each frame from the GIF Observing the frames, the person was waving the flag in a pattern resembling semaphore signaling Using a military semaphore flag reference, we translated the positions of the flags in each frame into letters. The decoded sequence gave the following string: QBAAAEFAAAAGOADBEEAAAEAAGDENPAKADABAEAKAAAAABOBIOHKLHGPOAHPKGAPKNNBMEIABIAAPLJDIOAAAAABABAIAKLPENIEAIONHODKKAEHEFFECACPGGGMGBGHCOHEHIHECAEIFEFEFACPDBCODAANAKEMGJGOGLCNEMGBHJGFHCDKCAFCEGEDCNDEDIDCDECNHDGFGNGBHAGIGPHCGFANAKANAKAAAAR The decoded text seemed like an encoded format identified it as a substitution cipher It gave a hex value After converting the hex values into text, we found a file name flag.txt The content of flag.txt contained the final flag for the challenge ![image](https://hackmd.io/_uploads/Hyk56kUYJx.png) 

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
