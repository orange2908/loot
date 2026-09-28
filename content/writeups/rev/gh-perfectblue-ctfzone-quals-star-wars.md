---
title: "Star-Wars - ctfzone quals 2019"
category: "rev"
subcategory: "rev"
type: "writeup"
tags: ["rev", "star-wars", "reverse-engineering", "ctfzone-quals", "perfectblue", "ctf-writeups"]
summary: "This was a reversing/ppc challenge."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2019/ctfzone-quals-2019/Star-Wars/README.md"
ctf:
  name: "ctfzone quals"
  year: 2019
  challenge: "Star-Wars"
---

## Source

- **CTF:** ctfzone quals 2019
- **Challenge:** Star-Wars
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2019/ctfzone-quals-2019/Star-Wars/README.md>

---
# StarWars

This was a reversing/ppc challenge. Reversing the exe was pretty painful, but doable. You find that 16 threads are created for each starship, and actions are controlled by a list of Events. Each ship attacks passive ships every turn deterministically, based on hardcoded values, and your ship does the same. You can choose whether or not to attack other ships on a given turn. When two ships attack each other, the winner ship gains stats. When your ship loses a fight you lose. On round 24, your ship faces an unbeatable passive ship, so you have to defeat all other 16 ships before this round. We need to find the combination of actions to reach the state of 16 kills by round 24. We do this by reimplementing the ship simulations based on the reversed code, keeping track of the player ship's state (health, attack, kills etc), and running DFS with DP to search for the desired win state.
