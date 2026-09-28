---
title: "driving - Nullcon Goa HackIM 2025 CTF"
category: "stego"
subcategory: "metadata"
type: "writeup"
tags: ["stego", "exiftool", "driving", "metadata", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "From exiftool we can find the artist name gives us a clue and how the flag is hidden."
source:
  name: "CTFtime writeup #39934"
  url: "https://ctftime.org/writeup/39934"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "driving"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** driving
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39934>

---
From exiftool we can find the artist name gives us a clue and how the flag is hidden.  
`Artist : 2+(10*n) for all n>=10`

```python=  
import cv2  
import os

def extract_frames(video_path):  
cap = cv2.VideoCapture(video_path)  
if not cap.isOpened():  
print("[!] Error: Could not open video file")  
return

frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))  
print(f"[*] Total frames in video: {frame_count}")

saved_count = 0  
frame_number = 0

while True:  
ret, frame = cap.read()  
if not ret:  
break

# Check if this frame should be saved based on the formula: 2+(10*n) for n>=10  
# Which means frames that are 2 more than multiples of 10, starting from frame 102  
if frame_number >= 102 and (frame_number - 2) % 10 == 0:  
output_filename = f'output_{saved_count+1:04d}.png'  
cv2.imwrite(output_filename, frame)  
print(f"[+] Saved frame {frame_number} as {output_filename}")  
saved_count += 1

frame_number += 1

cap.release()  
print(f"\n[*] Extraction complete. Saved {saved_count} frames.")

video_path = 'driving.mp4'  
if not os.path.exists(video_path):  
print(f"[!] Error: Video file '{video_path}' not found")  
else:  
extract_frames(video_path)  
```

Now checking the corners of each frame clockwise gives us the flag.
