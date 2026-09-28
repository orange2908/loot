---
title: "Petey the Panther's Guide to the Galaxy - Space Heroes 2024"
category: "forensics"
subcategory: "disk"
type: "writeup"
tags: ["forensics", "binwalk", "forensic", "qrcode", "qr-code", "petey", "panther", "guide", "galaxy", "disk", "space-heroes", "space-heroes-2024", "2024", "ctf-writeup"]
summary: "binwalk -e ARealSpaceHero.jpg"
source:
  name: "CTFtime writeup #39061"
  url: "https://ctftime.org/writeup/39061"
original_source: "https://www.youtube.com/watch?v=H8vgWWbN2Uk"
ctf:
  name: "Space Heroes 2024"
  year: 2024
  challenge: "Petey the Panther's Guide to the Galaxy"
---

## Metadata

- **CTF:** Space Heroes 2024
- **Task:** Petey the Panther's Guide to the Galaxy
- **Author team:** bdhxgrp
- **CTFtime tags:** binwalk, forensic, qrcode
- **CTFtime:** <https://ctftime.org/writeup/39061>
- **Original writeup:** <https://www.youtube.com/watch?v=H8vgWWbN2Uk>

---
binwalk -e A_Real_Space_Hero.jpg 

python code to merge all images into single image

from PIL import Image

Define the dimensions of the final image  
final_width = 4000  
final_height = 4000

Create a new blank image with the final dimensions  
final_image = Image.new('RGB', (final_width, final_height), (255, 255, 255))

Iterate through all 400 images  
for i in range(20):  
for j in range(20):  
Open each PNG image  
img = Image.open(f'piece_{i * 20 + j}.png')

Calculate the position to paste the image  
x_position = j * 20  
y_position = i * 20

Paste the image onto the final image  
final_image.paste(img, (x_position, y_position))

Save the final image  
final_image.save('final_image.png')

scan image from qr code and get flag from <https://scanqr.org/image-qr-code-scan>...

flag  
shctf{s0_l0ng_4nd_th4nks_f0r_4ll_th3_flags}
