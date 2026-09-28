---
title: "Puzzled - Insomni'hack 2024"
category: "misc"
type: "writeup"
tags: ["brute", "qrcode", "misc", "puzzled", "insomni-hack", "insomni-hack-2024", "2024", "ctf-writeup"]
summary: "We get an image of a scrambled QR-Code, and the code that was used to generate it."
source:
  name: "CTFtime writeup #39109"
  url: "https://ctftime.org/writeup/39109"
ctf:
  name: "Insomni'hack 2024"
  year: 2024
  challenge: "Puzzled"
---

## Metadata

- **CTF:** Insomni'hack 2024
- **Task:** Puzzled
- **Author team:** organizers
- **CTFtime tags:** brute, qrcode, misc
- **CTFtime:** <https://ctftime.org/writeup/39109>

---
## Puzzled: Challenge Setup  
We get an image of a scrambled QR-Code, and the code that was used to generate it.

```python  
from PIL import Image  
import random

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

key = "Not the real key!"  
random.seed(key)  
shuffle3x3GridImage("fullVersion25QRcode.png", "puzzledVersion25QRcode.png")  
```

## Solving  
The comment says it cuts it into 16 pieces, I am pretty sure it's just 9, but whatever. We were all tired, no need to do math or thinking. Just reuse the same code for the solve script.

Basic idea: try all possible combinations and see which ones are valid.

### Solve Script  
```python  
from PIL import Image  
import random  
import itertools as it  
from pyzbar import pyzbar

def original_rearrange_fun(positions, cell_width, cell_height, width, height, original_image):  
# Create a new image to store rearranged pieces  
new_image = Image.new("RGB", (width, height))  
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
return new_image

def brute(image_path):  
# Open the image  
original_image = Image.open(image_path)  
  
# Get the size of the image  
width, height = original_image.size  
assert(width == 234 and height == 234)  
  
# Calculate the size of each grid cell  
cell_width = width // 3  
cell_height = height // 3

positions = [(x, y) for x in range(3) for y in range(3)]  
for attempt in it.permutations(positions, len(positions)):  
print(f"{attempt=}")  
original_image = Image.open(image_path)  
image_attempt = original_rearrange_fun(attempt, cell_width, cell_height, width, height, original_image)  
bruh = pyzbar.decode(image_attempt, symbols=[pyzbar.ZBarSymbol.QRCODE])  
if bruh:  
print(bruh)  
breakpoint()  


if __name__ == "__main__":  
brute("puzzledVersion25QRcode.png")  
```

### Output  
```  
attempt=((0, 1), (0, 2), (1, 2), (0, 0), (2, 2), (2, 0), (1, 0), (1, 1), (2, 1))  
[Decoded(data=b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. INS{Im-puzzl3d-6c2bd4d3-e739-4f8d-b8cd-6bd663bde735} Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.', type='QRCODE', rect=Rect(left=0, top=0, width=234, height=234), polygon=[Point(x=0, y=0), Point(x=0, y=234), Point(x=233, y=233), Point(x=234, y=0)], quality=1, orientation=None)]  
> /home/generic/Downloads/ctf/inso/puzzled/[solve.py](http://solve.py)(41)brute()  
-> for attempt in it.permutations(positions, len(positions)):  
```
