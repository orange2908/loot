---
title: "Pwn: babypwn - WolvCTF 2024"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["buffer-overflow", "pwn", "babypwn", "stack", "wolvctf", "wolvctf-2024", "2024", "ctf-writeup"]
summary: "\\- Description: Just a little baby pwn."
source:
  name: "CTFtime writeup #38971"
  url: "https://ctftime.org/writeup/38971"
original_source: "https://github.com/archv1le/CTF-Write-Ups/blob/main/WolvCTF%202024/babypwn/Solution.md"
ctf:
  name: "WolvCTF 2024"
  year: 2024
  challenge: "Pwn: babypwn"
---

## Metadata

- **CTF:** WolvCTF 2024
- **Task:** Pwn: babypwn
- **Author team:** r1p3rS
- **CTFtime tags:** buffer-overflow, pwn
- **CTFtime:** <https://ctftime.org/writeup/38971>
- **Original writeup:** <https://github.com/archv1le/CTF-Write-Ups/blob/main/WolvCTF%202024/babypwn/Solution.md>

---
## babypwn  
\- Tags: pwn  
\- Description: Just a little baby pwn. nc [babypwn.wolvctf.io](http://babypwn.wolvctf.io) 1337

## Solution  
\- To solve this question you need to download the following files and open the source code. You will see the following:

```  
#include <stdio.h>  
#include <string.h>  
#include <unistd.h>

struct __attribute__((__packed__)) data {  
char buff[32];  
int check;  
};

void ignore(void)  
{  
setvbuf(stdout, NULL, _IONBF, 0);  
setvbuf(stdin, NULL, _IONBF, 0);  
}

void get_flag(void)  
{  
char flag[1024] = { 0 };  
FILE *fp = fopen("flag.txt", "r");  
fgets(flag, 1023, fp);  
printf(flag);  
}

int main(void)   
{  
struct data name;  
ignore(); /* ignore this function */

printf("What's your name?\n");  
fgets(name.buff, 64, stdin);  
sleep(2);  
printf("%s nice to meet you!\n", name.buff);  
sleep(2);  
printf("Binary exploitation is the best!\n");  
sleep(2);  
printf("Memory unsafe languages rely on coders to not make mistakes.\n");  
sleep(2);  
printf("But I don't worry, I write perfect code :)\n");  
sleep(2);

if (name.check == 0x41414141) {  
get_flag();  
}

return 0;  
}  
```

\- The struct data allocates 32 bytes for buffer and 8 bytes for the check. However, fgets reads in 64 bytes from the standard input into name.buff. Since check is after buffer on the stack, we can perform a buffer overflow by sending 32 random bytes and then 4 bytes of AAAA to pass the check in the code (A = 0x41).  
\- The payload is: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
\- After some time we will get the flag.

```  
wctf{pwn_1s_th3_best_Categ0ry!}  
```
