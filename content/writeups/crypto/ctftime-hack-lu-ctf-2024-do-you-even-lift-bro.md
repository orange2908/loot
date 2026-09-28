---
title: "Do you even lift bro? - Hack.lu CTF 2024"
category: "crypto"
subcategory: "prng"
type: "writeup"
tags: ["crypto", "prng", "madmonday", "gfuzz", "xor", "memcpy", "hack-lu-ctf", "hack-lu-ctf-2024", "2024", "ctf-writeup"]
summary: "Things I tried to persue initially, that did not work out and thus won't be covered in detail here:"
source:
  name: "CTFtime writeup #39654"
  url: "https://ctftime.org/writeup/39654"
ctf:
  name: "Hack.lu CTF 2024"
  year: 2024
  challenge: "Do you even lift bro?"
---

## Metadata

- **CTF:** Hack.lu CTF 2024
- **Task:** Do you even lift bro?
- **Author team:** Mad Monday
- **CTFtime tags:** c, prng, madmonday, gfuzz, c
- **CTFtime:** <https://ctftime.org/writeup/39654>

---
Things I tried to persue initially, that did not work out and thus won't be covered in detail here:

* decompile LLVM low level code and try to get it running  
* adding missing code and statements to still get it running  
* understand all the code, after converting from .ll to C thanks to (yes) ChatGPT

In the end, from all those efforts, I figured out the following way, which avoids brute-forcing.  
The even() function basically is a pseudo random number generator (PRNG) which was used to encode the original flag.  
There is some encrypted data in the code. To reverse, run even() to get the proper (pseudo-)random bits, and decode.

In a first step, this worked for the first few rounds, but after calling even() 16 times it gave non-working values.  
Using another translation run from .ll to C gave a slightly different C implementation, which eventually worked.

Here's the final run:

```  
kali:~/Hack.lu2024/Rev-DoYouEvenLiftBro% gcc s3.c -o s3  
kali:~/Hack.lu2024/Rev-DoYouEvenLiftBro% ./s3  
flag{l1ftiN6_p41d_0ff!}  
```

Here is the C code for s3.c:

```  
/* HF: * from .ll to .c via chatgpt  
* gcc s3.c -o s3  
* ./s3  
* flag{l1ftiN6_p41d_0ff!}  
*/

#include <stdint.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <string.h>

int16_t do_you = -8531; /* -8531 = 0xdead */  
/*  
@__const.lift_bro.valid = private unnamed_addr constant [23 x i8] c"\D3\06\07\BBk\A2\FD<`\C99\1A\A8\16I2\A55\D2\AC@\D6)", align 16  
*/  
static uint8_t __const_lift_bro_valid[23] = {  
/* \D3 \06 \07 \BB k \A2 \FD < */  
0xD3, 0x06, 0x07, 0xBB, 0x6B, 0xA2, 0xFD, 0x3C,

/* ` \C9 9 \1A \A8 \16 I 2 */  
0x60, 0xC9, 0x39, 0x1A, 0xA8, 0x16, 0x49, 0x32,

/* \A5 5 \D2 \AC @ \D6 ) */  
0xA5, 0x35, 0xD2, 0xAC, 0x40, 0xD6, 0x29  
};

static char __const_lift_bro_input[24] = "flag{fakefakefake!}";

static const char str_invalid_length[] = "Invalid input length\n"; // @.str  
static const char str_correct[] = "Correct!\n"; // @.str.1  
static const char str_incorrect[] = "Incorrect!\n"; // @.str.2

/* translated via ChatGPT from swo.ll */  
uint8_t even() {  
#if 0 /* v1 - broken after 16 calls! */  
uint8_t temp;

// Schritt 1: Lese die 16-Bit-Wert von `do_you` und prüfe, ob die unterste Bit 0 oder 1 ist.  
temp = (do_you & 1); // Speichert das unterste Bit in `temp`

// Schritt 2: Rechter Shift um 1 Bit und Konvertiere es zurück zu einem 16-Bit-Wert.  
int64_t shifted_value = (int16_t)(do_you >> 1); // %9

// Schritt 3: Invertiere `temp` (falls 1) und maskiere mit 46080.  
int64_t mask_value = (-(int64_t)temp) & 46080; /* %13 0xB400 */

// Schritt 4: XOR des maskierten Werts mit dem geshifteten Wert.  
do_you = (uint16_t)(shifted_value ^ mask_value); // %15

// Schritt 5: Rückgabe des Werts von `temp`.  
#else /* v2 - works even after 16 calls, no idea why */  
uint8_t temp;

// Lade do_you und berechne den Wert  
uint16_t value = do_you;

// (value & 1) wird den letzten Bitwert erhalten (0 oder 1)  
temp = (uint8_t)(value & 1);

// Schiebe value um 1 nach rechts  
value >>= 1;

// Negative Umkehrung von temp  
int64_t neg_temp = -((int64_t)temp);

// Berechne (neg_temp & 46080)  
int64_t result = neg_temp & 46080;

// XOR mit dem geschobenen Wert  
result ^= (int64_t)value;

// Truncate auf 16 Bit  
do_you = (uint16_t)(result & 0xFFFF);  
#endif  
return temp;  
}

int main(void)  
{  
int index;  
int length=23;  
unsigned char valid[23]; // %2 /* HF: was char */  
uint8_t temp_byte; // %8  
uint32_t loop_index = 0; // %9

memcpy(valid, __const_lift_bro_valid, sizeof(valid));

/* translated via ChatGPT from swo.ll */  
for (index = 0; index < length; index++) { // %24  
if (index < length) {  
temp_byte = 0; // %8  
loop_index = 0; // %9

while (loop_index < 8) { // %29  
if (loop_index < 8) {  
uint8_t byte_value = (temp_byte << 1) | (even() ? 1 : 0); // %36  
temp_byte = (uint8_t)byte_value; // %39  
}  
loop_index++;  
}

}  
printf("%c", valid[index] ^ temp_byte);  
}  
printf("\n");

return 0;  
}  
```
