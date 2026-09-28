---
title: "What type of image - Z3R0 D4Y CTF"
category: "forensics"
subcategory: "jwt"
type: "writeup"
tags: ["forensics", "jwt", "type", "image", "z3r0-d4y-ctf", "ctf-writeup"]
summary: "Description: What is the data of the image."
source:
  name: "CTFtime writeup #39586"
  url: "https://ctftime.org/writeup/39586"
original_source: "https://github.com/BogusForlorn/CTF_Writeups/blob/main/Z3R0%20D4Y%20CTF/Forensics/What%20type%20of%20image.md"
ctf:
  name: "Z3R0 D4Y CTF"
  challenge: "What type of image"
---

## Metadata

- **CTF:** Z3R0 D4Y CTF
- **Task:** What type of image
- **Author team:** C0UGH1NGB4BY
- **CTFtime:** <https://ctftime.org/writeup/39586>
- **Original writeup:** <https://github.com/BogusForlorn/CTF_Writeups/blob/main/Z3R0%20D4Y%20CTF/Forensics/What%20type%20of%20image.md>

---
Description: What is the data of the image.

First, some recon to see what we're working with.  
The challenge file with a .png extension isn't a PNG file at all, but rather a text file. I used the cat command to read what values are actually inside the PNG file.

![](<https://private-user-images.githubusercontent.com/136268503/380563734-20fd0568-358b-4aea-b3c0-a03833b7b085.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzAxNjU1NDMsIm5iZiI6MTczMDE2NTI0MywicGF0aCI6Ii8xMzYyNjg1MDMvMzgwNTYzNzM0LTIwZmQwNTY4LTM1OGItNGFlYS1iM2MwLWEwMzgzM2I3YjA4NS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMDI5JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTAyOVQwMTI3MjNaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT1hNTk3YmJmNDVhYzA5ZWZmYWQ1ZjI1ZmEwODg2NjY2ZDI5ZWU0YWExZmU0OTZlODNjMjQxNjc5ZTNiMDNiZWNjJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.4d4nHDg5qtnhMnWf9A-n1VQrGjtpBL9jPGFRKjdo_g4>)

These numbers look very familiar especially, after finishing the rock&roll challenge. These are the magic numbers for a PNG file, but their order is odd. Every 4 bytes are flipped. Using a python script to reverse the bytes:

def invert_hex_bytes(input_file, output_file):  
with open(input_file, 'r') as f:  
hex_data = f.read().strip()

hex_data = hex_data.replace(" ", "").replace("\n", "")

if len(hex_data) % 8 != 0:  
print("Error: Hex data length is not a multiple of 4 bytes (8 hex characters).")  
return

inverted_hex = ""  
for i in range(0, len(hex_data), 8):  
chunk = hex_data[i:i+8]  
inverted_chunk = chunk[6:8] + chunk[4:6] + chunk[2:4] + chunk[0:2]  
inverted_hex += inverted_chunk

with open(output_file, 'w') as f:  
for i in range(0, len(inverted_hex), 8):  
f.write(inverted_hex[i:i+8] + "\n")

print(f"Inverted hex dump written to {output_file}.")

input_file = 'hex_dump.txt'  
output_file = 'inverted_hex_dump.txt'

invert_hex_bytes(input_file, output_file)  
We get the corrected output of the text file as a hex dump. Now we turn the hex dump back into a PNG by using [hexed.it](http://hexed.it)

![](<https://private-user-images.githubusercontent.com/136268503/380564907-43107683-78d3-4f23-a80e-364b4b34fa41.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzAxNjU1NDMsIm5iZiI6MTczMDE2NTI0MywicGF0aCI6Ii8xMzYyNjg1MDMvMzgwNTY0OTA3LTQzMTA3NjgzLTc4ZDMtNGYyMy1hODBlLTM2NGI0YjM0ZmE0MS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMDI5JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTAyOVQwMTI3MjNaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT1mZDA2YmU3YmI4YzJlNjZkMzcxMjUzZjdkMTBkMWExNzZjN2IzODlhMTdjODUyNDgzY2FmYmY2NWZjMTRjYTU3JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.ztdAlKWZDXwPT8SB0djvxcGHWE0PljpVDbVm60623JQ>)

And we get the flag.
