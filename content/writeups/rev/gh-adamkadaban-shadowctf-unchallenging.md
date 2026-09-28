---
title: "unchallenging - ShadowCTF"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "ghidra", "gets", "unchallenging", "static-analysis", "reverse-engineering"]
summary: "rev writeup for \"unchallenging\" from ShadowCTF - techniques: ghidra, gets, unchallenging, static-analysis, reverse-engineering."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/ShadowCTF/rev/unchallenging/README.md"
ctf:
  name: "ShadowCTF"
  challenge: "unchallenging"
---

## Source

- **CTF:** ShadowCTF
- **Challenge:** unchallenging
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/ShadowCTF/rev/unchallenging/README.md>

---
* We can disassemble the binary in ghidra

* The main function looks like this:
```c
undefined8 main(void)

{
  int iVar1;
  char local_108 [256];
  
  puts("What is the password?");
  gets(local_108);
  iVar1 = strcmp(local_108,"op3n_se5ame");
  if (iVar1 == 0) {
    puts("{Ar@b1an_night5}");
  }
  else {
    puts("Wrong!!");
  }
  return 0;
}
```
* Here, we can see that the password is `op3n_se5ame`, which outputs `{Ar@b1an_night5}`

* The flag is `shadowCTF{Ar@b1an_night5}`
