---
title: "random song - sekaictf 2022"
category: "misc"
subcategory: "prng"
type: "writeup"
tags: ["misc", "prng", "random", "song", "miscellaneous", "random-song"]
summary: "misc writeup for \"random song\" from sekaictf - techniques: prng, random, song, miscellaneous, random-song."
source:
  name: "project-sekai-ctf/sekaictf-2022"
  url: "https://github.com/project-sekai-ctf/sekaictf-2022/blob/383b16da68c438c5d516e6f00b2716210141f7a4/misc/random-song/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2022
  challenge: "random song"
---

## Source

- **CTF:** sekaictf 2022
- **Challenge:** random song
- **Repository:** [project-sekai-ctf/sekaictf-2022](https://github.com/project-sekai-ctf/sekaictf-2022)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2022/blob/383b16da68c438c5d516e6f00b2716210141f7a4/misc/random-song/solution/README.md>

---
# Writeup

> Rollback Attack

- We are required to guess 3 times correctly, with only 3 chances in this challenge.
- Chainlink VRF is a verifiable random number generator, so we cannot predict the `songSeq`.
- Bonuses are sent every time we guess. The wallet account can receive with no effort. But the contract needs to have a `receive()` function with `payable` modifier to receive.
- So, we can revert the transaction in function `receive()` if we guessed wrong and try again.
