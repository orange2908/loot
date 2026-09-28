---
title: "backtrack - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "backtrack", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Decompiling the binary, we can find the function responsible for connverting input.bin to keylogger."
source:
  name: "CTFtime writeup #39950"
  url: "https://ctftime.org/writeup/39950"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "backtrack"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** backtrack
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39950>

---
# Backtrack

Decompiling the binary, we can find the function responsible for connverting `input.bin` to `keylogger`.

```cpp  
_DWORD *__cdecl sub_401690(_BYTE *a1, int a2, _BYTE *a3, _DWORD *a4)  
{  
_DWORD *result; // eax  
_BYTE *i; // [esp+8h] [ebp-1Ch]  
int v7; // [esp+Ch] [ebp-18h]  
int v8; // [esp+10h] [ebp-14h]  
int v9; // [esp+10h] [ebp-14h]  
int v10; // [esp+14h] [ebp-10h]  
unsigned int v11; // [esp+18h] [ebp-Ch]  
_BYTE *v12; // [esp+1Ch] [ebp-8h]  
_BYTE *v13; // [esp+20h] [ebp-4h]  
unsigned __int8 *v14; // [esp+20h] [ebp-4h]

v10 = 0;  
v13 = a1 + 4;  
v12 = a3;  
if ( *a1 == 1 )  
{  
sub_4012F0(a1 + 4, a3, a2 - 4);  
result = a4;  
*a4 = a2 - 4;  
}  
else  
{  
while ( v13 != &a1[a2] )  
{  
if ( !v10 )  
{  
v11 = *(unsigned __int16 *)v13;  
v13 += 2;  
v10 = 16;  
}  
if ( (v11 & 1) != 0 )  
{  
v8 = 16 * (*v13 & 0xF0);  
v7 = (*v13 & 0xF) + 1;  
v14 = v13 + 1;  
v9 = v8 + *v14;  
v13 = v14 + 1;  
for ( i = &v12[-v9]; v7--; ++i )  
*v12++ = *i;  
}  
else  
{  
*v12++ = *v13++;  
}  
v11 >>= 1;  
\--v10;  
}  
result = a4;  
*a4 = v12 - a3;  
}  
return result;  
}  
```  
Challenge description mentioned that we only need to apply this function on `data.bin` to get the required file. 

Here is the python script to do just that  
```python  
def copy_bytes(src: bytes, length: int) -> bytes:  
return src[:length]

def decompression_maybe(data: bytes) -> bytes:  
a2 = len(data)  
output = bytearray()  
if data[0] == 1:

uncompressed = copy_bytes(data[4:], a2 - 4)  
return uncompressed

pos = 4 # This is equivalent to v13 = a1 + 4.  
flag_bits = 0 # This will hold our 16-bit flag word.  
flag_count = 0 # How many bits remain in the current flag word.  
  
while pos < a2:  
if flag_count == 0:  
if pos + 1 >= a2:  
raise ValueError("Unexpected end of input while reading flag word.")  
flag_bits = data[pos] | (data[pos+1] << 8)  
pos += 2  
flag_count = 16

if (flag_bits & 1) != 0:  
if pos >= a2:  
raise ValueError("Unexpected end of input while reading control byte.")  
ctrl = data[pos]  
pos += 1  
length = (ctrl & 0x0F) + 1  
if pos >= a2:  
raise ValueError("Unexpected end of input while reading offset byte.")  
offset_low = data[pos]  
pos += 1  
offset = ((ctrl & 0xF0) << 4) + offset_low  
start = len(output) - offset  
if start < 0:  
raise ValueError("Back-reference offset out of range.")  
for _ in range(length):  
output.append(output[start])  
start += 1  
else:  
if pos >= a2:  
raise ValueError("Unexpected end of input while reading literal byte.")  
output.append(data[pos])  
pos += 1  
flag_bits >>= 1  
flag_count -= 1

return bytes(output)

if __name__ == '__main__':  
import sys

if len(sys.argv) != 3:  
print("Usage: python [decompress.py](http://decompress.py) <input_file> <output_file>")  
sys.exit(1)

input_file = sys.argv[1]  
output_file = sys.argv[2]

with open(input_file, 'rb') as f:  
input_data = f.read()

try:  
decompressed_data = decompression_maybe(input_data)  
except ValueError as e:  
print("Error during decompression:", e)  
sys.exit(1)

with open(output_file, 'wb') as f:  
f.write(decompressed_data)

print(f"Decompression complete. Output written to {output_file}")  
```

Running this script will give us the required flag in `jpg` format
