---
title: "algorithm multitool - sekaictf 2023"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "gcd", "heap", "use-after-free", "binary-exploitation", "algorithm-multitool"]
summary: "pwn writeup for \"algorithm multitool\" from sekaictf - techniques: gcd, heap, use-after-free, binary-exploitation, algorithm-multitool."
source:
  name: "project-sekai-ctf/sekaictf-2023"
  url: "https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/pwn/algorithm-multitool/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2023
  challenge: "algorithm multitool"
---

## Source

- **CTF:** sekaictf 2023
- **Challenge:** algorithm multitool
- **Repository:** [project-sekai-ctf/sekaictf-2023](https://github.com/project-sekai-ctf/sekaictf-2023)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/pwn/algorithm-multitool/solution/README.md>

---
# Algorithm Multitool - Solution

1. If result of a fast algo is > 16 digits, we get a UAF on a string so we can leak heap. This can be done by doing gcd on large numbers

2. If we create any algo then create slow algo, then delete the first algo, the lambda-coroutine capture variable will point to where the SavedTask is stored in the vector :face_with_spiral_eyes:. With this, we can massage the heap a bit to create a face result string for this pointer (this must be done by creating fast algos). With this, we can get an arbitrary read.

3. If we create enough algos, we cause the vector to allocate a new chunk, so we can allocate enough fast algos to overwrite the vtable address for the capture variable. From there, we can use COP to get a shell.
