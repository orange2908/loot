---
title: "Silent Visitor - Securinets CTF Quals 2025"
category: "forensics"
type: "writeup"
tags: ["forensics", "silent", "visitor", "securinets-ctf-quals", "securinets-ctf-quals-2025", "2025", "ctf-writeup"]
summary: "Input: 122b2b4bf1433341ba6e8fefd707379a98e6e9ca376340379ea42edb31a5dba2"
source:
  name: "CTFtime writeup #40467"
  url: "https://ctftime.org/writeup/40467"
original_source: "https://github.com/NEMO246/WRITEUP_CTF/tree/main/Securinets%20CTF%20Quals%202025/Silent%20Visitor"
ctf:
  name: "Securinets CTF Quals 2025"
  year: 2025
  challenge: "Silent Visitor"
---

## Metadata

- **CTF:** Securinets CTF Quals 2025
- **Task:** Silent Visitor
- **Author team:** milworms
- **CTFtime tags:** forensics
- **CTFtime:** <https://ctftime.org/writeup/40467>
- **Original writeup:** <https://github.com/NEMO246/WRITEUP_CTF/tree/main/Securinets%20CTF%20Quals%202025/Silent%20Visitor>

---
![Silent_Visitor Title](<https://github.com/NEMO246/WRITEUP_CTF/raw/main/Securinets%20CTF%20Quals%202025/Silent%20Visitor/image/Silent_Visitor.png>)

![alt text](<https://github.com/NEMO246/WRITEUP_CTF/raw/main/Securinets%20CTF%20Quals%202025/Silent%20Visitor/image/1.jpg>)

```nc [foren-1f49f8dc.p1.securinets.tn](http://foren-1f49f8dc.p1.securinets.tn) 1337```

### Step 1: What is the SHA256 hash of the disk image provided?  
Input: ```122b2b4bf1433341ba6e8fefd707379a98e6e9ca376340379ea42edb31a5dba2```

### Step 2: Identify the OS build number of the victimтАЩs system?  
Input: ```19045```

### Step 3: What is the ip of the victim's machine?  
Input: ```192.168.206.131```

### Step 4: What is the name of the email application used by the victim?  
Input: ```Thunderbird```

### Step 5: What is the email of the victim?  
Input: ```[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)```

### Step 6: What is the email of the attacker?  
Input: ```[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)```

### Step 7: What is the URL that the attacker used to deliver the malware to the victim?  
Input: ```<https://tmpfiles.org/dl/23860773/sys.exe>```

### Step 8: What is the SHA256 hash of the malware file?  
Input: ```be4f01b3d537b17c5ba7dc1bb7cd4078251364398565a0ca1e96982cff820b6d```

### Step 9: What is the IP address of the C2 server that the malware communicates with?  
Input: ```40.113.161.85```

### Step 10: What port does the malware use to communicate with its Command & Control (C2) server?  
Input: ```5000```

### Step 11: What is the url if the first Request made by the malware to the c2 server?  
Input: ```http://40.113.161.85:5000/helppppiscofebabe23```

### Step 12: The malware created a file to identify itself. What is the content of that file?  
Input: ```3649ba90-266f-48e1-960c-b908e1f28aef```

### Step 13: Which registry key did the malware modify or add to maintain persistence?  
Input: ```HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\MyApp```

### Step 14: What is the content of this registry?  
Input: ```C:\Users\ammar\Documents\sys.exe```

### Step 15: The malware uses a secret token to communicate with the C2 server. What is the value of this key?  
Input: ```e7bcc0ba5fb1dc9cc09460baaa2a6986```
