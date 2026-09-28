---
title: "Slot Machine - UIUCTF 2024"
category: "misc"
subcategory: "pow"
type: "writeup"
tags: ["misc", "proof-of-work", "slot", "machine", "pow", "uiuctf", "uiuctf-2024", "2024", "ctf-writeup"]
summary: "<https://github.com/Samik081/ctf-writeups/blob/master/UIUCTF%202024/misc/slotmachine.md>"
source:
  name: "CTFtime writeup #39297"
  url: "https://ctftime.org/writeup/39297"
original_source: "https://github.com/Samik081/ctf-writeups/blob/master/UIUCTF%202024/misc/slot_machine.md"
ctf:
  name: "UIUCTF 2024"
  year: 2024
  challenge: "Slot Machine"
---

## Metadata

- **CTF:** UIUCTF 2024
- **Task:** Slot Machine
- **Author team:** my_cat_is_fat3
- **CTFtime tags:** misc
- **CTFtime:** <https://ctftime.org/writeup/39297>
- **Original writeup:** <https://github.com/Samik081/ctf-writeups/blob/master/UIUCTF%202024/misc/slot_machine.md>

---
### Original writeup

[<https://github.com/Samik081/ctf-writeups/blob/master/UIUCTF%202024/misc/slot_machine.md>](<https://github.com/Samik081/ctf-writeups/blob/master/UIUCTF%202024/misc/slot_machine.md>)

## Slot Machine (453 points)

### Description

We have onboard entertainment! Try your luck on our newly installed slot machine.

```sh  
ncat --ssl [slot-machine.chal.uiuc.tf](http://slot-machine.chal.uiuc.tf) 1337  
```

### Source

```python  
from hashlib import sha256   
  
hex_alpha = "0123456789abcdef"   
  
print("== Welcome to the onboard slot machine! ==")   
print("If all the slots match, you win!")   
print("We believe in skill over luck, so you can choose the number of slots.")   
print("We'll even let you pick your lucky number (little endian)!")   
  
lucky_number = input("What's your lucky (hex) number: ").lower().strip()   
lucky_number = lucky_number.rjust(len(lucky_number) + len(lucky_number) % 2, "0")   
if not all(c in hex_alpha for c in lucky_number):   
print("Hey! That's not a hex number! -999 luck!")   
exit(1)   
hash = sha256(bytes.fromhex(lucky_number)[::-1]).digest()[::-1].hex()   
  
length = min(32, int(input("How lucky are you feeling today? Enter the number of slots: ")))   
print("=" * (length * 4 + 1))   
print("|", end="")   
for c in hash[:length]:   
print(f" {hex_alpha[hex_alpha.index(c) - 1]} |", end="")   
print("\n|", end="")   
for c in hash[:length]:   
print(f" {c} |", end="")   
print("\n|", end="")   
for c in hash[:length]:   
print(f" {hex_alpha[hex_alpha.index(c) - 15]} |", end="")   
print("\n" + "=" * (length * 4 + 1))   
  
if len(set(hash[:length])) == 1:   
print("Congratulations! You've won:")   
flag = open("flag.txt").read()   
print(flag[:min(len(flag), length)])   
else:   
print("Better luck next time!")  
```

### Challenge analysis

This *looks* pretty simple, let's analyze the code:

1\. We input `lucky_number` string which must be a valid hex number.  
2\. We input the `slots` number.  
3\. The `lucky_number` gets hashed in the following way:  
\- It gets padded with `0` if it's of odd length.  
\- It gets reversed.  
\- `sha256` is calculated from it.  
\- It gets reversed again.

If the hash has X (X = `slots`) repeating characters in the beginning, we get the flag.

In short, to get the flag we must find the number in hex format whose `sha256` hash results in a string ending (because it gets reversed in the end) with X repeating characters (where X is the flag length or a higher value), and then reverse it.

### Finding the solution

#### Do I actually understand Python?

As I'm not super confident with Python (I am not a Python dev on daily basis), I spent some time trying to understand if it's possible to reveal the flag partially using some funky `slots` values like negative numbers, etc., but did not succeed.

#### Bruteforce attempt

Being out of ideas, I also tried to find such a number myself by simply bruteforcing it but managed to only find a number which after hashing gave me a maximum of 7 repeating characters in the beginning of a string. Definitely not enough for a flag.

#### Bitcoin to the rescue?!

Then, I started searching the web to know more about `sha256` nature and to see if it's possible to find such hashes (with repeating characters in the beginning) in some existing lists. After a few hours (and a few coffee breaks), I finally found something that shed more light on this problem: a question and an answer on Bitcoin Stack Exchange: [<https://bitcoin.stackexchange.com/questions/121920/is-it-always-possible-to-find-a-number-whose-hash-starts-with-a-certain-number-o>](<https://bitcoin.stackexchange.com/questions/121920/is-it-always-possible-to-find-a-number-whose-hash-starts-with-a-certain-number-o>) and specifically this comment:

> "Due to these characteristics, it is statistically almost certain that a valid input exists which will generate a hash with a specific number of leading zeros. It is just a matter of trying enough inputs (or "nonces" in the case of ₿ mining) until you find one. This is what ₿ miners do in the proof-of-work system - they try billions of different inputs every second until they find one that generates a hash with the required number of leading zeros."

Looks like finding the solution to this challenge is what Bitcoin miners actually do! Well, they actually try to find hex strings whose `sha256` hash (as a number) is lower value than X (this value depends on the difficulty of the blockchain), but that results in numbers with a lot of leading 0s in the beginning. I was not very familiar with Bitcoin Proof of Work algorithm, so I wasn't aware of that ?

### Bitcoin PoW and lowest hash

Let's find the lowest Bitcoin block hash ever mined and try to recreate the algorithm and find a solution.

I've found this answer about the lowest hash on the same Stack Exchange: [<https://bitcoin.stackexchange.com/questions/65478/which-is-the-smallest-hash-that-has-ever-been-hashed>](<https://bitcoin.stackexchange.com/questions/65478/which-is-the-smallest-hash-that-has-ever-been-hashed>). Looks like block `756951` had the lowest (as of Jan 22, 2023) hash value with 24 leading zeros. I hope it will do!

I've also found a nonce verifying algorithm written in Python here: [<https://stackoverflow.com/questions/66944273/bitcoin-verify-a-single-block-in-python>](<https://stackoverflow.com/questions/66944273/bitcoin-verify-a-single-block-in-python>) and modified it a little for my needs, so it outputs my "lucky number":

```python  
header = (struct.pack("
