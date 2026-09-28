---
title: "Back to the past - PwnMe CTF Quals 2025"
category: "rev"
type: "writeup"
tags: ["rev", "engineering", "reverse", "memcpy", "back", "past", "pwnme-ctf-quals", "pwnme-ctf-quals-2025", "2025", "ctf-writeup"]
summary: "static unsigned long long seed = 0;"
source:
  name: "CTFtime writeup #40060"
  url: "https://ctftime.org/writeup/40060"
original_source: "https://medium.com/@hackthena/back-to-the-past-writeup-229c486e768f"
ctf:
  name: "PwnMe CTF Quals 2025"
  year: 2025
  challenge: "Back to the past"
---

## Metadata

- **CTF:** PwnMe CTF Quals 2025
- **Task:** Back to the past
- **Author team:** 3ndByt3
- **CTFtime tags:** engineering, reverse
- **CTFtime:** <https://ctftime.org/writeup/40060>
- **Original writeup:** <https://medium.com/@hackthena/back-to-the-past-writeup-229c486e768f>

---
```  
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <time.h>

#define MAX_FILE_SIZE 1024  
static unsigned long long seed = 0;

void srandX(int arg1) {  
seed = (unsigned long long)arg1 - 1;   
}

int randX() {  
seed = 0x5851f42d4c957f2d * seed + 1;  
return (int)(seed >> 33);  
}

int main() {  
unsigned long start = 1715198460; //Wed May 08 2024 22:01:00  
unsigned long end = 1715198519; //Wed May 08 2024 22:01:59

  
FILE *file = fopen("flag.enc", "rb");  
if (!file) {  
perror("Error opening encrypted file");  
return 0;  
}

char encrypted_data[MAX_FILE_SIZE];  
size_t file_size = fread(encrypted_data, 1, sizeof(encrypted_data), file);  
fclose(file);

if (file_size == 0) {  
printf("Error: File is empty.\n");  
return 0;  
}

  
for (unsigned long i = start; i <= end; i++) {  
srandX(i);  
printf("Testing seed: %ld\n", i);

char decrypted_data[MAX_FILE_SIZE];  
memcpy(decrypted_data, encrypted_data, file_size);

for (char j = 0; j < file_size; j++) {  
//int rax_15 = randX();  
//int rdx = rax_15 / 0x7f;  
//int key = rax_15 - ((rdx << 7) - rdx);  
int keyy = randX()%127;  
decrypted_data[j] ^= keyy;  
}  
if (strstr((char*)decrypted_data, "PWNME{")) {  
printf("Flag found with seed %ld: %s\n", i, decrypted_data);  
return 0;  
}  
}

printf("No valid flag found.\n");  
return 0;  
}  
```
