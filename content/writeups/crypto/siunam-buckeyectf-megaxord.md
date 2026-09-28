---
title: "megaxord - BuckeyeCTF 2022"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "xor", "cyberchef", "megaxord", "cryptography", "buckeyectf"]
summary: "Hint: the wizard used the same magic on every character..."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/BuckeyeCTF-2022/Crypto/megaxord/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/BuckeyeCTF-2022/Crypto/megaxord/README.md"
ctf:
  name: "BuckeyeCTF"
  year: 2022
  challenge: "megaxord"
---

## Source

- **CTF:** BuckeyeCTF 2022
- **Challenge:** megaxord
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/BuckeyeCTF-2022/Crypto/megaxord/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/BuckeyeCTF-2022/Crypto/megaxord/README.md>

---
# megaxord

## Overview

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

> Some pesky wizard stole the article I was writing. I got it back, but it's all messed up now :(

Hint: the wizard used the same magic on every character...

> Author: gsemaj

> Difficulty: Beginner

## Find the flag

**In this challenge, we can download a file:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104220038.png)

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Crypto/megaxord]
└─# cat megaxord.txt 
7/=*x
96?=*+x1+x96x5=*1;96x=6,=*,9165=6,x96<x5=*;096<1+16?x>*96;01+=x:-14,x9*7-6<x9x41.=u9;,176x+-(=*0=*7x,=4=.1+176x+=*1=+tx:9+=<x76x,0=x9(96=+=x,73-+9,+-x>*96;01+=x
                                                     -(=*x
                                                          =6,91v*7<-;=<x>1*+,x:!x
                                                                                 9:96x6,=*,9165=6,tx+=;76<x:!x�
    x6,=*,9165=6,tx49,=*x:!x
                            9:96x�*96<+tx96<x,7<9!x:!x
                                                     7/=*x
96?=*+x96<x1,+x(9*=6,x;75(96!tx9+:*7tx,0=7/=*x
96?=*+x,=4=.1+176x+=*1=+x,93=+x5-;0x7>x1,+x>77,9?=x>*75x,0=x
                                                            -(=*x
                                                                 =6,91x,=4=.1+176x+=*1=+tx(*7<-;=<x:!x
                                                                                                      7=1x5(96!vix
       0=x>1*+,7/=*x

```

Hmm... **As the challenge name suggested, this txt file has been XOR'ed!**

**Now, we can upload this file to [CyberChef](https://gchq.github.io/CyberChef/) to brute force to XOR keys:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104220251.png)

**Looks like key `58` is the XOR key!**

**Let's use that key to reverse back to plaintext!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221104220446.png)

Found it!

**Flag:**
```
buckeye{m1gh7y_m0rph1n_w1k1p3d14_p4g3}
```

# Conclusion

What we've learned:

1. Brute Forcing XOR Key
