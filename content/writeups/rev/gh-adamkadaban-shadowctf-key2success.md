---
title: "Key2success - ShadowCTF"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "ghidra", "radare2", "obfuscation", "static-analysis", "reverse-engineering"]
summary: "rev writeup for \"Key2success\" from ShadowCTF - techniques: ghidra, radare2, obfuscation, static-analysis, reverse-engineering."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/ShadowCTF/rev/Key2success/README.md"
ctf:
  name: "ShadowCTF"
  challenge: "Key2success"
---

## Source

- **CTF:** ShadowCTF
- **Challenge:** Key2success
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/ShadowCTF/rev/Key2success/README.md>

---
* We can disassemble the binary in ghidra

* The main function looks like this:

```c
ulong main(void)

{
  int iVar1;
  
  print_intro();
  iVar1 = check_password();
  if (iVar1 == 0) {
    slow_type("Hmm. This not the key.\n");
  }
  else {
    slow_type("Great. Well here is your key:\n");
    print_flag();
  }
  return (ulong)(iVar1 == 0);
}
```

* The `print_flag` function is obfuscated just a tiny bit, so let's look at `check_password` first:

```c
ulong check_password(void)

{
  int iVar1;
  size_t sVar2;
  undefined8 uStack272;
  char local_108 [256];
  
  uStack272 = 0x1012f9;
  printf("> ");
  uStack272 = 0x101314;
  fgets(local_108,0xff,stdin);
  uStack272 = 0x101323;
  sVar2 = strlen(local_108);
  *(undefined *)((long)&uStack272 + sVar2 + 7) = 0;
  uStack272 = 0x101348;
  iVar1 = strcmp(local_108,the_password);
  return (ulong)(iVar1 == 0);
}
```
* We can see that some input is being compared with a constant called `the_password`
	* If we double-click on that in ghidra, it shows us that the constant is `Constant_learning_is_the_key`

* Thus, we can run `echo Constant_learning_is_the_key | ./key2sucess` to get the flag

* The flag is `shadowCTF{Never_stop_learning}`
