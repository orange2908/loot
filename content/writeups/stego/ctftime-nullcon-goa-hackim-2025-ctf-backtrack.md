---
title: "backtrack - Nullcon Goa HackIM 2025 CTF"
category: "stego"
subcategory: "image"
type: "writeup"
tags: ["stego", "lsb", "backtrack", "image", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This was a custom LZSS like compression method."
source:
  name: "CTFtime writeup #40032"
  url: "https://ctftime.org/writeup/40032"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "backtrack"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** backtrack
- **Author team:** 🐧‎
- **CTFtime:** <https://ctftime.org/writeup/40032>

---
This was a custom LZSS like compression method.

```  
#!/usr/bin/env python3  
import sys  
import struct

def decompress_lzss(data: bytes) -> bytes:  
"""  
Decompresses data using a custom LZSS-like scheme.  
  
The input data is assumed to have a 4-byte header.  
\- If the first byte is 1, the data is uncompressed and the output is simply data[4:].  
\- Otherwise, the compressed stream starts at offset 4.  
  
In the compressed stream:  
\- A 16–bit flag word (little–endian) is read. Its 16 bits (LSB first) tell whether the next token is  
a literal (bit=0) or a copy–command (bit=1).  
\- For a literal, one byte is copied directly to the output.  
\- For a copy–command, two bytes are read:  
length = (first_byte & 0x0F) + 1  
offset = second_byte + ((first_byte & 0xF0) << 4)  
Then 'length' bytes are copied from output[ current_output_position - offset : ].  
"""  
# Make sure the data is long enough to have a header.  
if len(data) < 4:  
raise ValueError("Input data too short; missing header.")  
  
header_flag = data[0]  
if header_flag == 1:  
# Uncompressed mode: simply return data from offset 4 onward.  
return data[4:]  
  
# Compressed mode: start at offset 4.  
in_ptr = 4  
output = bytearray()  
  
flag_word = 0  
flag_bits_remaining = 0  
  
# Process until we run out of input.  
while in_ptr < len(data):  
# If no flag bits remain, read a new 16-bit flag word.  
if flag_bits_remaining == 0:  
if in_ptr + 2 > len(data):  
break # not enough bytes for a flag word  
flag_word = struct.unpack_from("<H", data, in_ptr)[0]  
in_ptr += 2  
flag_bits_remaining = 16  
  
# Process one flag bit (LSB first).  
flag_bit = flag_word & 1  
flag_word >>= 1  
flag_bits_remaining -= 1  
  
if flag_bit == 0:  
# Literal byte: copy one byte directly.  
if in_ptr >= len(data):  
break  
output.append(data[in_ptr])  
in_ptr += 1  
else:  
# Copy command: read two bytes.  
if in_ptr + 2 > len(data):  
break  
first_byte = data[in_ptr]  
second_byte = data[in_ptr+1]  
in_ptr += 2  
  
# Decode length and offset.  
length = (first_byte & 0x0F) + 1  
# (first_byte & 0xF0) << 4 equals (first_byte & 0xF0) * 16.  
offset = second_byte + ((first_byte & 0xF0) << 4)  
  
# The source for the copy is offset bytes back from the current end of output.  
copy_from = len(output) - offset  
if copy_from < 0:  
raise ValueError("Invalid offset encountered during decompression.")  
for i in range(length):  
output.append(output[copy_from + i])  
  
return bytes(output)

def main():  
if len(sys.argv) != 3:  
print(f"Usage: {sys.argv[0]} <input_file> <output_file>")  
sys.exit(1)  
  
input_filename = sys.argv[1]  
output_filename = sys.argv[2]  
  
# Read input file in binary mode.  
with open(input_filename, "rb") as f:  
data = f.read()  
  
try:  
decompressed = decompress_lzss(data)  
except Exception as e:  
print("Error during decompression:", e)  
sys.exit(1)  
  
# Write output file.  
with open(output_filename, "wb") as f:  
f.write(decompressed)  
  
print(f"Decompression complete. Output written to {output_filename}")

if __name__ == "__main__":  
main()  
```
