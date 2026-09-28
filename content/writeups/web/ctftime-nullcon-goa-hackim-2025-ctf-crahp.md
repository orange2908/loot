---
title: "crahp - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "crahp", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "In this challenge, the target PHP application requires a 15-character password that passes two checksum validations: a custom CRC16 and a CRC8."
source:
  name: "CTFtime writeup #40005"
  url: "https://ctftime.org/writeup/40005"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "crahp"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** crahp
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/40005>

---
## Challenge Overview

In this challenge, the target PHP application requires a 15-character password that passes two checksum validations: a custom CRC16 and a CRC8. The twist is that the provided password (`AdM1nP@assW0rd!`) is hardcoded and, if submitted as-is, triggers a “try harder” message. Instead, the attacker must generate a **collision**: a different string with the exact same CRC16 and CRC8 values as the original password.

## Source Code Analysis

The PHP source code performs the following operations:

1\. **Error Suppression and Source Code Disclosure:**   
The script disables error reporting and provides a `?source` GET parameter that highlights the source code.

2\. **Checksum Functions:**   
Two custom checksum functions are defined:  
\- `crc16($string)`: Implements a 16-bit CRC calculation based on a standard algorithm.  
\- `crc8($input)`: Implements an 8-bit CRC using a predefined lookup table.

Both functions process the input string byte-by-byte and produce checksum values.

3\. **Password Validation:**   
The script stores a hardcoded password in the variable `$MYPASSWORD` set to `"AdM1nP@assW0rd!"` and includes a file (`flag.php`) that holds the flag. When a POST request is made with a `password` field, the following checks occur:  
\- **Length Check:** The provided password must have the same length as `$MYPASSWORD` (15 characters).  
\- **Equality Check:** If the provided password is exactly equal to `$MYPASSWORD`, the script responds with “oops. Try harder!” to force the attacker to find a collision.  
\- **Checksum Checks:**   
\- The script computes `crc16` and `crc8` for both `$MYPASSWORD` and the supplied password.  
\- If either checksum does not match, it outputs an error message.  
\- **Access Granted:**   
If all checks pass (i.e., the string is not the original password but has identical CRC16 and CRC8 values), the flag is printed.

## Solving the Challenge

The objective is to find a 15-character string, different from `"AdM1nP@assW0rd!"`, that yields:  
\- `crc16("AdM1nP@assW0rd!") == 25010`  
\- `crc8("AdM1nP@assW0rd!") == 167`

### The Collision Approach

Because both checksum functions are relatively simple (and non-cryptographic), it is feasible to generate a collision by brute-forcing random strings. The provided solve script does exactly this:  
  
\- **Random Generation:**   
A helper function generates random strings of length 15 from a pool of letters, digits, and punctuation.  
  
\- **Checksum Calculation:**   
For every generated string, the script computes its CRC16 and CRC8 values using implementations that mirror those in the PHP code.

\- **Comparison:**   
The script compares the computed values against the target checksums (25010 for CRC16 and 167 for CRC8). When a match is found, the string is printed as the solution.

### Solve Script

Below is the Python solve script used to find a collision:

```python  
import random  
import string

def crc16(data):  
crc = 0xFFFF  
for byte in data:  
crc ^= byte  
for _ in range(8):  
if crc & 0x0001:  
crc = (crc >> 1) ^ 0xA001  
else:  
crc >>= 1  
return crc

def crc8(data):  
crc8_table = [  
0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,  
0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,  
0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,  
0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,  
0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,  
0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,  
0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,  
0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,  
0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2,  
0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,  
0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2,  
0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,  
0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32,  
0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,  
0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42,  
0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,  
0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C,  
0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,  
0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC,  
0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,  
0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C,  
0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,  
0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C,  
0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,  
0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B,  
0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,  
0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B,  
0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,  
0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB,  
0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,  
0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB,  
0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3  
]  
crc = 0  
for byte in data:  
crc = crc8_table[(crc ^ byte) & 0xff]  
return crc & 0xff

def generate_random_string(length):  
return ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))

def main():  
target_crc16 = 25010  
target_crc8 = 167  
length = 15

while True:  
random_string = generate_random_string(length)  
random_string_bytes = random_string.encode('utf-8')

crc16_val = crc16(random_string_bytes)  
crc8_val = crc8(random_string_bytes)

if crc16_val == target_crc16 and crc8_val == target_crc8:  
print(f"Found matching string: {random_string}")  
break

if __name__ == "__main__":  
main()
