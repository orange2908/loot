---
title: "rock&roll - Z3R0 D4Y CTF"
category: "forensics"
subcategory: "jwt"
type: "writeup"
tags: ["forensics", "jwt", "binwalk", "rock", "roll", "z3r0-d4y-ctf", "ctf-writeup"]
summary: "First order of business, before we even conduct our usual reconnaissance."
source:
  name: "CTFtime writeup #39584"
  url: "https://ctftime.org/writeup/39584"
original_source: "https://github.com/BogusForlorn/CTF_Writeups/blob/main/Z3R0%20D4Y%20CTF/Forensics/rock%26roll.md"
ctf:
  name: "Z3R0 D4Y CTF"
  challenge: "rock&roll"
---

## Metadata

- **CTF:** Z3R0 D4Y CTF
- **Task:** rock&roll
- **Author team:** C0UGH1NGB4BY
- **CTFtime:** <https://ctftime.org/writeup/39584>
- **Original writeup:** <https://github.com/BogusForlorn/CTF_Writeups/blob/main/Z3R0%20D4Y%20CTF/Forensics/rock%26roll.md>

---
First order of business, before we even conduct our usual reconnaissance. This "JPEG" file is way too big. Why is this file 17 MB big? There's definitely some files hidden here as a part of binwalk so let's extract them.

![](<https://private-user-images.githubusercontent.com/136268503/380558882-b62d18e0-0bb0-4a0f-9f52-17f3a1ebfff6.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzAxNjY1MTUsIm5iZiI6MTczMDE2NjIxNSwicGF0aCI6Ii8xMzYyNjg1MDMvMzgwNTU4ODgyLWI2MmQxOGUwLTBiYjAtNGEwZi05ZjUyLTE3ZjNhMWViZmZmNi5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMDI5JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTAyOVQwMTQzMzVaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT1mY2I4MTkzN2I2YzExMTEyMGU4ZWU0NDA1MWEyNjllYzg5YjI2Y2ZiN2I1OTVmYzllOGU5OWMwNTEzNTIyNDQ4JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.2YwfHaWDrpQPcuHakJ0g-Txu-hiemFskVdV3JkhGIEs>)

Taking a look at the zip that's been embedded in the binwalk, we can definitely see why it is 17MB

![](<https://private-user-images.githubusercontent.com/136268503/380559091-021b0124-fcf5-4862-bebb-c867a5b0cba6.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzAxNjY1MTUsIm5iZiI6MTczMDE2NjIxNSwicGF0aCI6Ii8xMzYyNjg1MDMvMzgwNTU5MDkxLTAyMWIwMTI0LWZjZjUtNDg2Mi1iZWJiLWM4NjdhNWIwY2JhNi5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMDI5JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTAyOVQwMTQzMzVaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0yNmZlOWViMzU0YTkzZTZlNzdkOThjM2YyYTMyNTJkNDJhYjkxM2VlN2QzZmE0MjE5MzQ3Yzk3NDNkNjYyYzIxJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.hyEsH4aYwIPFT6gkBw_xfxX1VHOb9zJ1hxj3kcHTTQ0>)

Within the zip is another zip titled htq.zip and a text file. This seems to be the case for every zip hidden inside; there's another zip and a text file. And this seemingly continues until it reaches a.zip. Yikes. At first I thought maybe the flag was just at the end of a.zip. So using my initial python script, I unzipped everything until I reached a.zip. Unfortunately, in a.zip, there wasn't a flag.txt as I was hoping but rather a text file 'a.zip'. And the contents of the file isn't the flag format either, but a hexadecimal number. We all know where this is going... So then I started over. I changed my python script to extract the zip and concatenate the text file as it goes.

import zipfile  
import os

def extract_nested_zip(zip_file_path, extract_to_dir):  
current_zip_path = zip_file_path

if not os.path.exists(extract_to_dir):  
os.makedirs(extract_to_dir)

while True:  
with zipfile.ZipFile(current_zip_path, 'r') as zip_ref:  
zip_ref.extractall(extract_to_dir)  
extracted_files = os.listdir(extract_to_dir)  
zip_files = [f for f in extracted_files if f.endswith('.zip')]  
if not zip_files:  
print('Reached the last level. No more zip files to extract.')  
break

current_zip_path = os.path.join(extract_to_dir, zip_files[0])  
os.remove(current_zip_path)  
for file in extracted_files:  
if file.lower().startswith("flag") and file.endswith(".txt"):  
with open(os.path.join(extract_to_dir, file), 'r') as flag_file:  
flag_content = flag_file.read()  
print(f"Flag found: {flag_content}")

zip_file_path = 'htq.zip'  
extract_to_dir = 'extracted_files_dir'  
extract_nested_zip(zip_file_path, extract_to_dir)  
And the result of that? We got a hex dump. I tried to see what this hex dump is by decoding it from hexadecimal into ASCII.

![](<https://private-user-images.githubusercontent.com/136268503/380560713-b8501c47-72aa-42af-a99e-38adebc17312.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzAxNjY1MTUsIm5iZiI6MTczMDE2NjIxNSwicGF0aCI6Ii8xMzYyNjg1MDMvMzgwNTYwNzEzLWI4NTAxYzQ3LTcyYWEtNDJhZi1hOTllLTM4YWRlYmMxNzMxMi5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMDI5JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTAyOVQwMTQzMzVaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0yNDA1NTNmZWViYjY1ZmMwZTkxMTZmNTg3MWVjOGQ2ZmViOGRiYTRlYWNkNTI4OTE3NDg1NDg2MTYxOTg3ZTdmJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.wG8W-KMn8JmuzGbkW5yySK9aVS4ikZPIG2OcXVKhJiM>)

Going to the bottom, we see that its actually a hex dump for a PNG image... in reverse.

![](<https://private-user-images.githubusercontent.com/136268503/380560965-d0b9d7d9-5a02-4c76-a8c2-b3bf22284405.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzAxNjY1MTUsIm5iZiI6MTczMDE2NjIxNSwicGF0aCI6Ii8xMzYyNjg1MDMvMzgwNTYwOTY1LWQwYjlkN2Q5LTVhMDItNGM3Ni1hOGMyLWIzYmYyMjI4NDQwNS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMDI5JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTAyOVQwMTQzMzVaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0yMDhhZjRlNzQ3MjQ4MzY0N2JmMWQ2MmFjZDdkY2Y5OTcyNGRhM2Y4YWJlNjQyNWMyM2Q0MGNjYmU4YzA3OTIzJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.NZVBJkThAcBwMdDx160aJi4I70TY-5VE1qQhZRgtIHM>)

No worries! Just reverse it, turn it back into a hex dump, and paste it into [hexed.it](http://hexed.it), then export it.

![](<https://private-user-images.githubusercontent.com/136268503/380561621-804b6c33-2753-475f-8de4-41e6d5a41197.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzAxNjY1MTUsIm5iZiI6MTczMDE2NjIxNSwicGF0aCI6Ii8xMzYyNjg1MDMvMzgwNTYxNjIxLTgwNGI2YzMzLTI3NTMtNDc1Zi04ZGU0LTQxZTZkNWE0MTE5Ny5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMDI5JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTAyOVQwMTQzMzVaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0xMTc0MzJhYjNjNmY3OGQzMDJhZDRhNTE3MThiODMxNDEwNWQ1YWRlNjA0YzkwN2I4MGRjYmY1YTBmYTM2NzI3JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.cUYPbnePI7UuzNNFlPFy0h5SiFCn4rX4iKVi7d9g8Nk>)

And that's our flag.

Author's note: This challenge wasn't particularly hard. Just very, very, very annoying.  
[Orignal Writeup](<https://github.com/BogusForlorn/CTF_Writeups/blob/main/Z3R0%20D4Y%20CTF/Forensics/rock%26roll.md>)
