---
title: "Puzzled - Insomni'hack 2024"
category: "misc"
subcategory: "image"
type: "writeup"
tags: ["misc", "qr-code", "puzzled", "image", "insomni-hack", "insomni-hack-2024", "2024", "ctf-writeup"]
summary: "The challenge was an image of a QR code, that was cut in a 3x3 grid and shuffled around."
source:
  name: "CTFtime writeup #39113"
  url: "https://ctftime.org/writeup/39113"
ctf:
  name: "Insomni'hack 2024"
  year: 2024
  challenge: "Puzzled"
---

## Metadata

- **CTF:** Insomni'hack 2024
- **Task:** Puzzled
- **Author team:** /mnt/ain
- **CTFtime:** <https://ctftime.org/writeup/39113>

---
# Task  
The challenge was an image of a QR code, that was cut in a 3x3 grid and shuffled around. It also contained the python code that created the shuffling.

# Solution  
One way is to try to guess there every peace belongs by eye. But this took to long, so lets just run the original script multiple times and check using the pyzbar library, if a valid QR code is in the image. Since there are not that many possibilities, the flag was found pretty quickly:

```  
[(0, 1), (0, 2), (1, 2), (2, 1), (2, 2), (1, 1), (1, 0), (2, 0), (0, 0)]  
[Decoded(data=b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. INS{Im-puzzl3d-6c2bd4d3-e739-4f8d-b8cd-6bd663bde735} Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.', type='QRCODE', rect=Rect(left=0, top=0, width=234, height=234), polygon=[Point(x=0, y=0), Point(x=0, y=234), Point(x=234, y=234), Point(x=234, y=0)], quality=1, orientation='UP')]  
```

Full code:

```python  
from PIL import Image  
import random  
from pyzbar.pyzbar import decode

# function of the original challenge, slightly modified to also return the image to directly check it  
def shuffle3x3GridImage(image_path, output_path):  
# Open the image  
original_image = Image.open(image_path)  
  
# Get the size of the image  
width, height = original_image.size  
assert(width == 234 and height == 234)  
  
# Calculate the size of each grid cell  
cell_width = width // 3  
cell_height = height // 3  
  
# Create a new image to store rearranged pieces  
new_image = Image.new("RGB", (width, height))  
  
# Create a list to store shuffled grid positions  
positions = [(x, y) for x in range(3) for y in range(3)]  
random.shuffle(positions)  
print(positions)  
  
# Split the original image into 16 pieces and rearrange them  
for i, pos in enumerate(positions):  
# Calculate the coordinates of the current grid cell  
x1 = pos[0] * cell_width  
y1 = pos[1] * cell_height  
x2 = x1 + cell_width  
y2 = y1 + cell_height  
  
# Crop the corresponding part of the original image  
cropped_piece = original_image.crop((x1, y1, x2, y2))  
  
# Calculate the coordinates to paste the cropped piece  
new_x = (i % 3) * cell_width  
new_y = (i // 3) * cell_height  
  
# Paste the cropped piece onto the new image  
new_image.paste(cropped_piece, (new_x, new_y))  
  
# Save the rearranged image  
new_image.save(output_path)  
return new_image

for x in range(10000):  
img = shuffle3x3GridImage("puzzledVersion25QRcode.png", "unpuzzled.png")  
barcodes = decode(img)  
print(barcodes)  
```
