---
title: "Secret Code - VishwaCTF 2024"
category: "misc"
subcategory: "disk"
type: "writeup"
tags: ["misc", "binwalk", "john", "wordlists", "secret", "code", "disk", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "Upon analyzing letter.txt, we understand that we need to find a password for Akshay's account to withdraw currency."
source:
  name: "CTFtime writeup #39517"
  url: "https://ctftime.org/writeup/39517"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Steganography/Secret%20Code.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "Secret Code"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** Secret Code
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39517>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Steganography/Secret%20Code.pdf>

---
### Solution:

Upon analyzing letter.txt, we understand that we need to find a password for Akshay's account to withdraw currency.

* Step 1:

The file confidential.jpg appears to be a pitch-black image. Analyzing the image using binwalk reveals that it contains hidden files.  
Run the following command to extract data from the image:  
bash  
Copy code  
binwalk -e confidential.jpg  
* Step 2:

After extracting, two files are found:  
5ecr3t_c0de.zip  
helper.txt  
* Step 3:

The 5ecr3t_c0de.zip file is password-protected, and helper.txt reveals that the password is a 6-digit number.  
To brute-force the password, we create a wordlist of all possible 6-digit numbers using the following Python script:  
python

```  
Create a wordlist of all 6-digit numbers  
with open('6_digit_wordlist.txt', 'w') as f:  
for i in range(100000, 1000000):  
f.write(str(i) + '\n')  
```  
* Step 4:

Use John The Ripper to brute-force the zip file with the created wordlist:

john --wordlist=6_digit_wordlist.txt --format=zip 5ecr3t_c0de.zip  
The password for the zip file is 945621. After extracting the zip file, we find a text file named 5ecr3t_c0de.txt, which contains some coordinates.

* Step 5:

The next step is to plot the coordinates on the confidential.jpg image by changing the pixel colors at the specified points. The following Python script performs this task:  
python  
Copy code  
from PIL import Image

Load the image  
img = Image.open('confidential.jpg')  
pixels = img.load()

List of coordinates extracted from 5ecr3t_c0de.txt  
coordinates = [(x1, y1), (x2, y2), ...] # Replace with actual coordinates

Change the pixel color at the specified coordinates  
for coord in coordinates:  
pixels[coord] = (255, 0, 0) # Example: change pixel to red

Save the modified image  
img.save('flag_image.png')  
After running the script, the hidden flag appears in the image.

Flag:  
`VishwaCTF{th15_15_4_5up3r_53cr3t_c0d3_u53_1t_w153ly_4nd_d0nt_5h4re_1t_w1th_4ny0ne}`
