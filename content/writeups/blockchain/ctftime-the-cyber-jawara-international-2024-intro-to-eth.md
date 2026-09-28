---
title: "Intro to ETH - The Cyber Jawara International 2024"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["blockchain", "solidity", "foundry", "intro", "eth", "smart-contract", "the-cyber-jawara-international", "the-cyber-jawara-international-202", "2024", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #39596"
  url: "https://ctftime.org/writeup/39596"
original_source: "https://miraicantsleep.gitbook.io/notes/ctf/cyber-jawara-international-2024/intro-to-eth"
ctf:
  name: "The Cyber Jawara International 2024"
  year: 2024
  challenge: "Intro to ETH"
---

## Metadata

- **CTF:** The Cyber Jawara International 2024
- **Task:** Intro to ETH
- **Author team:** dimas fans club
- **CTFtime:** <https://ctftime.org/writeup/39596>
- **Original writeup:** <https://miraicantsleep.gitbook.io/notes/ctf/cyber-jawara-international-2024/intro-to-eth>

---
For the complete documentation index, see [llms.txt](https://miraicantsleep.gitbook.io/notes/llms.txt). This page is also available as [Markdown](https://miraicantsleep.gitbook.io/notes/ctf/cyber-jawara-international-2024/intro-to-eth.md).

## Description

> Author: Chovid99 Welcome to the world of Ethereum smart contracts! This warmup challenge is designed to introduce newcomers to the basics of interacting with Ethereum blockchain technology. You'll get hands-on experience with a simple smart contract, learning how to read and interact with it. No prior blockchain knowledge is required – just bring your curiosity and problem-solving skills. Are you ready to take your first steps into the exciting realm of decentralized applications?
> 
> <http://152.42.183.87:59117>

We are given a file `Setup.sol`

Copy

```
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.0;
    
    contract Setup {
        bool private solved;
    
        constructor() payable {
        }
    
        function solve(bytes calldata secret) public {
            require(keccak256(secret) == keccak256(bytes("CJ_INTERNATIONAL_2024-CHOVID99")), "Wrong password");
            solved = true;
        }
    
        function isSolved() external view returns (bool) {
            return solved;
        }
    }
```

Looking at the source code above, there are some functions we can interact with.

## Functions

### solve(bytes calldata secret)

This function takes a `bytes` parameter called secret. Then it uses the `keccak256` hash to match the hash of secret with the hash of the string `CJ_INTERNATIONAL_2024-CHOVID99`, if it matches, then it flips the variable `solved` to true.

### isSolved()

This function will return a true/false boolean value. If it returns true, then the challenge is solved and otherwise if it returns false, the challenge is not solved.

### Ethernet Launcher

We were also given a web to launch our private blockchain server.

![](https://miraicantsleep.gitbook.io/notes/~gitbook/image?url=https%3A%2F%2F887347025-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FkjvWV0riaI4IlYjeGWEH%252Fuploads%252FWDxf4IZKZz1ZKT2nJXDt%252Fimage.png%3Falt%3Dmedia%26token%3Dd442501d-f718-4090-9095-7880cccdaa62&width=768&dpr=3&quality=100&sign=f4b0cbb1aad352ccff30d2a0dba06a69&sv=3)

Ethernet Launcher

## Solve

To solve this, it is very straightforward. We just need to do `cast send` (because we are altering the blockchain state and we need our private key to do that) to the `solve` function with the parameter `CJ_INTERNATIONAL_2024-CHOVID99` converted to hex.

We can use the help of foundry to do that.

First we call the solve function.

![](https://miraicantsleep.gitbook.io/notes/~gitbook/image?url=https%3A%2F%2F887347025-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FkjvWV0riaI4IlYjeGWEH%252Fuploads%252FhjtBHzt1YVQWcrAjgUAU%252Fimage.png%3Falt%3Dmedia%26token%3Db67e6c2d-4fcc-48a4-b364-d8c7dfc5af61&width=768&dpr=3&quality=100&sign=802cd039fdf8724c382e6e418e9cf88a&sv=3)

Successful transaction

And we check if our challenge is solved by calling the `isSolved()` function.

![](https://miraicantsleep.gitbook.io/notes/~gitbook/image?url=https%3A%2F%2F887347025-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FkjvWV0riaI4IlYjeGWEH%252Fuploads%252FUAmRW2rUWhRhUhdjDsvU%252Fimage.png%3Falt%3Dmedia%26token%3D2d81116c-7893-4af1-8e7b-52aef0f040f5&width=768&dpr=3&quality=100&sign=43e034e8d79ab59a3955836b572a63be&sv=3)

And with that, our challenge is solved!

![](https://miraicantsleep.gitbook.io/notes/~gitbook/image?url=https%3A%2F%2F887347025-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FkjvWV0riaI4IlYjeGWEH%252Fuploads%252FnAh3oGp6WvNuG1s20jcp%252Fimage.png%3Falt%3Dmedia%26token%3D97ad6edc-5efd-49b1-b49b-2dca0458cb9c&width=768&dpr=3&quality=100&sign=f2e9af15c70caacb8463dd464f643325&sv=3)

Solved!

_**Flag: CJ{m0mMy_I_s0lv3d_bL0cKch41n_ch4ll3ng3zZ}**_

[ PreviousCyber Jawara International 2024](https://miraicantsleep.gitbook.io/notes/ctf/cyber-jawara-international-2024)

Last updated 1 year ago
