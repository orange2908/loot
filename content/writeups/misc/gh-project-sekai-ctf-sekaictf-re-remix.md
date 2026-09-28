---
title: "re remix - sekaictf 2023"
category: "misc"
subcategory: "ecdsa"
type: "writeup"
tags: ["misc", "ecdsa", "solidity", "reentrancy", "remix", "miscellaneous"]
summary: "misc writeup for \"re remix\" from sekaictf - techniques: ecdsa, solidity, reentrancy, remix, miscellaneous."
source:
  name: "project-sekai-ctf/sekaictf-2023"
  url: "https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/misc/re-remix/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2023
  challenge: "re remix"
---

## Source

- **CTF:** sekaictf 2023
- **Challenge:** re remix
- **Repository:** [project-sekai-ctf/sekaictf-2023](https://github.com/project-sekai-ctf/sekaictf-2023)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/misc/re-remix/solution/README.md>

---
## Solution

> Due to some design carelessness, it can be solved using only the read-only reentrancy vulnerability > <
> 
> ~~But yeah, we can remix a song without changing its tempo or adding any special material~~ uwu

- [ECDSA signature malleability](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h)
  - The signature and signer are generated following [keyless method](https://weka.medium.com/how-to-send-ether-to-11-440-people-187e332566b7)

    ```js
    // .gitmodules
    [submodule "lib/openzeppelin-contracts"]
    path = lib/openzeppelin-contracts
    url = https://github.com/openzeppelin/openzeppelin-contracts
    branch = v4.7.0

    // MusicRemixer.sol:L58
    ECDSA.recover(hash, redemptionCode) != SIGNER
    ```

- SampleEditor: [Layout of State Variables in Storage](https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html)
- Equalizer: [Curve read-only reentrancy](https://chainsecurity.com/heartbreaks-curve-lp-oracles/)
