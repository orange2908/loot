---
title: "Sillygoose - n00bzCTF 2024"
category: "misc"
subcategory: "pow"
type: "writeup"
tags: ["misc", "proof-of-work", "sillygoose", "pow", "n00bzctf", "n00bzctf-2024", "2024", "ctf-writeup"]
summary: "Simple binary search number guessing game."
source:
  name: "CTFtime writeup #39376"
  url: "https://ctftime.org/writeup/39376"
original_source: "https://moormaster.github.io/CtfWriteups/sillygoose.html"
ctf:
  name: "n00bzCTF 2024"
  year: 2024
  challenge: "Sillygoose"
---

## Metadata

- **CTF:** n00bzCTF 2024
- **Task:** Sillygoose
- **Author team:** zwiebel
- **CTFtime:** <https://ctftime.org/writeup/39376>
- **Original writeup:** <https://moormaster.github.io/CtfWriteups/sillygoose.html>

---
Simple binary search number guessing game. You guess a number and the challenge tells you whether the goal is lower or higher.

```
    import sys
    
    lower_bound = 1
    upper_bound = pow(10, 100)
    
    f = open("sillygoose.log", "w")
    
    found = False
    while not found:
        attempt = lower_bound + (upper_bound - lower_bound)//2
        print(str(attempt))
        f.write("> " + str(attempt) + "\n")
    
        answer = input()
        f.write("< " + answer + "\n")
    
        if "too small" in answer:
            lower_bound = attempt
            continue
        if "too large" in answer:
            upper_bound = attempt
            continue
        break
    
    flag = input()
    f.write("< " + flag + "\n")
    print(flag, file=sys.stderr)
    
    print("yay")
    f.write("> yay\n")
    
    f.close()
```
