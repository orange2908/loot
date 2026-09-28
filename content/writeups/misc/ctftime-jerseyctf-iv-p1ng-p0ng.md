---
title: "p1ng-p0ng - JerseyCTF IV"
category: "misc"
type: "writeup"
tags: ["misc", "nping", "icmp", "nmap", "p1ng-p0ng", "jerseyctf-iv", "ctf-writeup"]
summary: "TLDR: We are given a server that communicates over ICMP, like the ping command."
source:
  name: "CTFtime writeup #38963"
  url: "https://ctftime.org/writeup/38963"
original_source: "https://meashiri.github.io/ctf-writeups/posts/202403-jerseyctf/#p1ng-p0ng"
ctf:
  name: "JerseyCTF IV"
  challenge: "p1ng-p0ng"
---

## Metadata

- **CTF:** JerseyCTF IV
- **Task:** p1ng-p0ng
- **Author team:** Weak But Leet
- **CTFtime tags:** nping, icmp
- **CTFtime:** <https://ctftime.org/writeup/38963>
- **Original writeup:** <https://meashiri.github.io/ctf-writeups/posts/202403-jerseyctf/#p1ng-p0ng>

---
TLDR: We are given a server that communicates over ICMP, like the `ping` command. Use a utility that is capable of crafting custom ICMP packets and interact with a TinyDB on the remote machine to obtain the flag. I 

Full writeup here:   
<https://meashiri.github.io/ctf-writeups/posts/202403-jerseyctf/#p1ng-p0ng>

```  
$ sudo nping --icmp -c1 -v3 --data-string "(HELP)" 3.87.129.162  
Starting Nping 0.7.94 ( <https://nmap.org/nping> ) at 2024-03-24 16:25 EDT  
SENT (0.0071s) ICMP [192.168.1.225 > 3.87.129.162 Echo request (type=8/code=0) id=37623 seq=1] IP [ver=4 ihl=5 tos=0x00 iplen=34 id=49455 foff=0 ttl=64 proto=1 csum=0x7229]  
0000 45 00 00 22 c1 2f 00 00 40 01 72 29 c0 a8 01 e1 E.."./[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection))....  
0010 03 57 81 a2 08 00 a7 49 92 f7 00 01 28 48 45 4c .W.....I....(HEL  
0020 50 29 P)   
RCVD (0.5894s) ICMP [3.87.129.162 > 192.168.1.225 Echo reply (type=0/code=0) id=37623 seq=1] IP [ver=4 ihl=5 tos=0x00 iplen=144 id=63958 flg=D foff=0 ttl=55 proto=1 csum=0x0214]  
0000 45 00 00 90 f9 d6 40 00 37 01 02 14 03 57 81 a2 [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)..  
0010 c0 a8 01 e1 00 00 6c 63 92 f7 00 01 43 6f 6e 6e ......lc....Conn  
0020 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 ection.successfu  
0030 6c 2e 20 41 76 61 69 6c 61 62 6c 65 20 63 6f 6d l..Available.com  
0040 6d 61 6e 64 73 3a 20 22 28 48 45 4c 50 29 22 2c mands:."(HELP)",  
0050 20 22 28 47 45 54 3b 49 44 3b 45 4e 54 52 59 5f ."(GET;ID;ENTRY_  
0060 4e 55 4d 29 22 2c 20 22 28 41 44 44 3b 49 44 3b NUM)",."(ADD;ID;  
0070 45 4e 54 52 59 5f 43 4f 4e 54 45 4e 54 29 22 2c ENTRY_CONTENT)",  
0080 20 22 28 45 4e 54 52 59 5f 43 4f 55 4e 54 29 22 ."(ENTRY_COUNT)"  
```
