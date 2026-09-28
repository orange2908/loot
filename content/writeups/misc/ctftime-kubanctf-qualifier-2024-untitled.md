---
title: "Изменен, но не сломлен. - KubanCTF Qualifier 2024"
category: "misc"
type: "writeup"
tags: ["misc", "kubanctf-qualifier", "kubanctf-qualifier-2024", "2024", "ctf-writeup"]
summary: "File -> export object -> HTTP"
source:
  name: "CTFtime writeup #39479"
  url: "https://ctftime.org/writeup/39479"
original_source: "https://github.com/zer00d4y/writeups/blob/main/CTF%20events/KubanCTF/KubanCTF%20Qualifier%202024.md"
ctf:
  name: "KubanCTF Qualifier 2024"
  year: 2024
  challenge: "Изменен, но не сломлен."
---

## Metadata

- **CTF:** KubanCTF Qualifier 2024
- **Task:** Изменен, но не сломлен.
- **Author team:** RedNet
- **CTFtime:** <https://ctftime.org/writeup/39479>
- **Original writeup:** <https://github.com/zer00d4y/writeups/blob/main/CTF%20events/KubanCTF/KubanCTF%20Qualifier%202024.md>

---
# KubanCTF Qualifier 2024 Write-up

![image](<https://github.com/user-attachments/assets/aadb302f-e910-4f33-ac24-ef0ba71a2355>)

## Not broken

File -> export object -> HTTP

![image](<https://github.com/user-attachments/assets/48f099bc-54bd-4ef4-aaf6-5dcd30c35410>)

Save largest packet and open it

![image](<https://github.com/user-attachments/assets/efd0be5b-9507-4357-ba2e-1f198689b7e1>)

We can see that is request to image

![image](<https://github.com/user-attachments/assets/ae510eff-c398-41c9-b681-03047ea8723a>)

Delete everything up to %PNG and save as a png file
