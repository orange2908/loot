---
title: "flag checker - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "static-analysis"
type: "writeup"
tags: ["crypto", "xor", "ghidra", "checker", "static-analysis", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We first reversed the given executable with Ghidra."
source:
  name: "CTFtime writeup #39873"
  url: "https://ctftime.org/writeup/39873"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "flag checker"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** flag checker
- **Author team:** BrHackeuses
- **CTFtime:** <https://ctftime.org/writeup/39873>

---
We first reversed the given executable with Ghidra. 

We observe tha the program takes an input string and performs some checks on it to check if it corresponds to the flag. 

The first check gives us that the flag length is **34**. 

Then, some bitwise XOR operations are performed on the input which result is compared to   
```  
0xF8, 0xA8, 0xB8, 0x21, 0x60, 0x73, 0x90, 0x83, 0x80, 0xC3, 0x9B, 0x80, 0xAB, 0x09, 0x59, 0xD3,  
0x21, 0xD3, 0xDB, 0xD8, 0xFB, 0x49, 0x99, 0xE0, 0x79, 0x3C, 0x4C, 0x49, 0x2C, 0x29, 0xCC, 0xD4, 0xDC  
```

Finally, we extracted the flag using the following script which reverses the bitwise operations :   
```  
#include <stdio.h>  
#include <stdint.h>

void reverse_FUN_001011e9(uint8_t *param_2, uint8_t *param_1) {  
int local_c;  
  
for (local_c = 0; local_c < 0x22; local_c++) {  
// Reverse the bitwise rotation  
param_1[local_c] = (param_2[local_c] >> 3) | (param_2[local_c] << 5);  
  
// Reverse the arithmetic transformation  
param_1[local_c] = (param_1[local_c] - local_c) ^ 0x5A;  
}  
}

int main() {  
uint8_t encrypted_data[34] = {  
0xF8, 0xA8, 0xB8, 0x21, 0x60, 0x73, 0x90, 0x83, 0x80, 0xC3, 0x9B, 0x80, 0xAB, 0x09, 0x59, 0xD3,  
0x21, 0xD3, 0xDB, 0xD8, 0xFB, 0x49, 0x99, 0xE0, 0x79, 0x3C, 0x4C, 0x49, 0x2C, 0x29, 0xCC, 0xD4, 0xDC  
};  
uint8_t original_data[34] = {0};  
  
reverse_FUN_001011e9(encrypted_data, original_data);  
  
printf("Original string: ");  
for (int i = 0; i < 34; i++) {  
printf("%c", original_data[i]);  
}  
printf("\n");  
  
return 0;  
}  
```

And flag ! `ENO{R3V3R53_3NG1N33R1NG_M45T3R!!!}`
