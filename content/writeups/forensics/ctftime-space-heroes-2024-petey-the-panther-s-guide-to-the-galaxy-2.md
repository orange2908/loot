---
title: "Petey the Panther's Guide to the Galaxy - Space Heroes 2024"
category: "forensics"
subcategory: "disk"
type: "writeup"
tags: ["forensics", "binwalk", "exiftool", "qr-code", "cyberchef", "petey", "panther", "guide", "galaxy", "disk", "space-heroes", "space-heroes-2024", "2024", "ctf-writeup"]
summary: "We're given an image file named ARealSpaceHero.jpg."
source:
  name: "CTFtime writeup #39055"
  url: "https://ctftime.org/writeup/39055"
ctf:
  name: "Space Heroes 2024"
  year: 2024
  challenge: "Petey the Panther's Guide to the Galaxy"
---

## Metadata

- **CTF:** Space Heroes 2024
- **Task:** Petey the Panther's Guide to the Galaxy
- **Author team:** D0M BU$TЄR$
- **CTFtime:** <https://ctftime.org/writeup/39055>

---
We're given an image file named `A_Real_Space_Hero.jpg`. Because this is forensics, we're dealing with something hidden inside the image.

![image](<https://raw.githubusercontent.com/FITSEC/spaceheroes_ctf_24/main/forensics/Petey%20the%20Panther's%20Guide%20to%20the%20Galaxy/src/A_Real_Space_Hero.jpg>)

We can start with checking the file with `exiftool`.

```bash  
\--- redacted due to brevity ---  
Warning : Invalid JUMBF sequence number  
```

It looks like there is something strange with this image. Let's look further, and run `binwalk` against the image.

```bash  
258102 0x3F036 Zip archive data, at least v2.0 to extract, compressed size: 114, uncompressed size: 124, name: secrets/piece_104.png  
258267 0x3F0DB Zip archive data, at least v2.0 to extract, compressed size: 150, uncompressed size: 198, name: secrets/piece_105.png  
258468 0x3F1A4 Zip archive data, at least v2.0 to extract, compressed size: 146, uncompressed size: 183, name: secrets/piece_106.png

# redacted due to brevity  
```

Okay we've definetly found something. Let's extract the zip archive again using `binwalk`.

```bash  
binwalk -e A_Real_Space_Hero.jpg  
```

We're now given a directory, conveniently named "secrets", with hundreds of image files hidden within that directory. These files are named `piece_[number].png`, and as the name suggests, they are pieces of a larger image. There's a total of 400 pieces in the directory, and we can assume the image is 200px by 200px (as each piece is 20px by 20px).

```python  
from PIL import Image  
import os

pieces = [filename for filename in os.listdir("./secrets")]  
pieces.sort(key=lambda x: int(x.split("_")[1][:-4]))

first_piece = Image.open(os.path.join("./secrets", pieces[0]))  
width, height = first_piece.size

rows = len(pieces) // width  
columns = width

assembled_image = Image.new("RGB", (width * columns, height * rows))

for i, filename in enumerate(pieces):  
piece = Image.open(os.path.join("./secrets", filename))  
x = (i % columns) * width  
y = (i // columns) * height  
assembled_image.paste(piece, (x, y))

assembled_image.save("final.png")  
print("saved")  
```

We're now given a QR code, which we can scan to get the flag. I just dragged the image onto CyberChef and got the flag.

![image](<https://raw.githubusercontent.com/FITSEC/spaceheroes_ctf_24/main/forensics/Petey%20the%20Panther's%20Guide%20to%20the%20Galaxy/src/small.png>)

```  
shctf{s0_l0ng_4nd_th4nks_f0r_4ll_th3_flags}  
```

(hey look, it's a reference!)
