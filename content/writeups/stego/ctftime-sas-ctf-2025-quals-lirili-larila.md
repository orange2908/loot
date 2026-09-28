---
title: "Lirili Larila - SAS CTF 2025 Quals"
category: "stego"
subcategory: "image"
type: "writeup"
tags: ["stego", "stegsolve", "lirili", "larila", "image", "sas-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "No captcha required for preview."
source:
  name: "CTFtime writeup #40317"
  url: "https://ctftime.org/writeup/40317"
original_source: "https://sevcankazdag.com.tr/sas-ctf-2025-quals-writeups-lirili-larila/"
ctf:
  name: "SAS CTF 2025 Quals"
  year: 2025
  challenge: "Lirili Larila"
---

## Metadata

- **CTF:** SAS CTF 2025 Quals
- **Task:** Lirili Larila
- **Author team:** kuzu_kaykayi
- **CTFtime tags:** stego
- **CTFtime:** <https://ctftime.org/writeup/40317>
- **Original writeup:** <https://sevcankazdag.com.tr/sas-ctf-2025-quals-writeups-lirili-larila/>

---
No captcha required for preview. Please, do not write just a link to original writeup here.

Categories: Stego

Please rate up my recent artwork made in a 10-hour lungo-infused drawing session

The challenge gives us a gif file. When we download and examine the gif file, we see a strange elephant wearing slippers (something like you can only see in Salvador Dali paintings or in your nightmares xd )

I tried several online steganography tools but nothing came up. So, the best way to further investigate the problem would be to examine with steganography tools in local.

In this stage, I decided to use stegosolve.jar tool.

It is used to analyze images in different planes by taking off bits of the image.  
Installation

It is used to analyze images in different planes by taking off bits of the image.

$ wget <http://www.caesum.com/handbook/Stegsolve.jar> -O stegsolve.jar  
$ chmod +x stegsolve.jar  
$ mkdir bin  
$ mv stegsolve.jar bin/

Usage

Stegsolve can be invoked by placing the image in the /bin folder and running stegsolve.

$ java -jar stegsolve.jar

When we load the gif file into the Stegsolve tool, it gave it us the beginning of the flag.

Even though I tried different color filters, unfortunately I couldn’t continue. I thought it would be better to split the gif into frames and look at it. I split the gif file into frames using GIMP, examined it and saved the frames. In this case I decided to continue with a different tool and used Stegoveritas tool as a tool to change the color map and experiment with different color palettes.

$ stegoveritas stego-3bba3d3b5aa82c35929f971310390edf.gif 

Unlike stegsolve, stegoveritas also gives all hidden frames. When we examine all the results gave it to us without using any parameters, it was possible to see the first part of the flag among the hidden frames, also as given by the stegsolve tool. Let’s try to apply the same color palette to all frames as the hidden frame containing the first part of the flag.

But in this way, the remaining part of the flag does not come out, most likely the remaining parts are stored in the local palette (LCT) structures in other GIF frames.Because StegoVeritas only works on the Global Palette or the Local Palette in the first frame, it cannot show the remaining flag parts hidden in other frames. The hidden frames make up the color palette and consist of 256 frames. Then it is possible to rearrange the gif using random color palettes.

import os

with open('stego.gif', 'rb') as f:  
data = f.read()

white_palette = b'\xff\xff\xff' * 256

random_palette = os.urandom(3 * 256)

modified_data = data.replace(white_palette, random_palette)

with open('output.gif', 'wb') as f:  
f.write(modified_data)

print("modified GIF: output.gif")

When we examined the modified gif frames with GIMP, we found that 7 frames contained the flag.

SAS{50m3_3leph4n7s_c4n_h1d3_7h31r_53cr3ts

However, apparently the random color palette script did not achieve a successful result for all of these frames. Although half of the flag is complete, the other half needs more research and deeper knowledge of the GIF structure.  
Revealing Hidden Flags in GIFs: Palette Manipulation

The first 13 bytes of a GIF file are usually the header and logical screen descriptor. If a Global Color Table exists, it typically starts after this 13th byte. We are making an assumption to locate the GCT. The GCT typically comes after the GIF header and Logical Screen Descriptor. It usually starts at offset 0x0D (So, 6 bytes (Header) + 7 bytes (Logical Display Descriptor) = 13 bytes. In hexadecimal, the number 13 corresponds to 0x0D) and is 768 bytes long (256 colors * 3 bytes for RGB). This step can be a more general version of your previous “replace white palette” approach. First, let’s manually inspect the file using a hex editor and look for repeating patterns, anomalies, or suspicious byte sequences outside of the known file structure.

The getFlags section in the Pattern Data of İmhex carries the secret marker for us. The LCT marker specified for flag in the original problem is: b’\x80\x01\x80\x01\x87′.

This marker usually precedes each Image Descriptor block. The LCT starts 5 bytes after this marker and is 768 bytes long. This is exactly what we are looking for in flag. Let’s edit the code so that it will look for the next marker starting from the position after the current LCT, bypassing this LCT and avoiding endless loops. Using i+1 instead of LCT_START_POS + LCT_LENTH will help prevent finding the same marker again.

import os

with open('stego.gif', 'rb') as f:  
s = f.read()

try:  
# For a more robust approach, deeper parsing of the GIF format would be required.  
gct_start_offset = 0x0D  
gct_length = 768 # 256 colors * 3 bytes/color (RGB)

if len(s) >= gct_start_offset + gct_length:  
s = s[:gct_start_offset] + os.urandom(gct_length) + s[gct_start_offset + gct_length:]  
else:  
print("Warning: Not enough data found to locate or corrupt Global Color Table (GCT).")

except Exception as e:  
print(f"An error occurred while corrupting GCT: {e}")

marker = b'\x80\x01\x80\x01\x87'  
lct_length = 768 # Local Color Table is also 256 colors * 3 bytes/color = 768 bytes

i = s.find(marker)

while i != -1:  
# The starting position of the LCT is 5 bytes after the marker  
lct_start_pos = i + 5

if lct_start_pos + lct_length <= len(s):  
# Replace the LCT with random data  
s = s[:lct_start_pos] + os.urandom(lct_length) + s[lct_start_pos + lct_length:]  
else:  
print(f"Warning: Not enough data for LCT at offset {lct_start_pos}, skipping replacement.")  
i = s.find(marker, i + 1)  
continue # move to the next iteration

  
i = s.find(marker, i + 1)

with open('stego_modified_all_palettes.gif', 'wb') as f:  
f.write(s)

print("GIF with all detected palettes corrupted: stego_modified_all_palettes.gif")

After the code is running, we can open the “stego_modified_all_palettes.gif” with GIMP and find the remaining flag pieces among the frames. But in this part, I was expecting to see a clear curly brackets in the last flag frame. So I thought it was still not over. I tried and yes, finally.

Flag: SAS{50m3_3leph4n7s_c4n_h1d3_7h31r_53cr3ts_1n_l0c4l_p4ll3tes}

Full writeup: <https://sevcankazdag.com.tr/sas-ctf-2025-quals-writeups-lirili-larila/>
