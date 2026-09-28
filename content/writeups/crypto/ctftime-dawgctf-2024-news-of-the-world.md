---
title: "news of the world - DawgCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "hashcat", "news", "world", "dawgctf", "dawgctf-2024", "2024", "ctf-writeup"]
summary: "DawgCTF{cipheroneasymode}"
source:
  name: "CTFtime writeup #39106"
  url: "https://ctftime.org/writeup/39106"
original_source: "https://radham0wn1ka.github.io/dawgCTF/"
ctf:
  name: "DawgCTF 2024"
  year: 2024
  challenge: "news of the world"
---

## Metadata

- **CTF:** DawgCTF 2024
- **Task:** news of the world
- **Author team:** m0wn1ka
- **CTFtime:** <https://ctftime.org/writeup/39106>
- **Original writeup:** <https://radham0wn1ka.github.io/dawgCTF/>

---
##  ctftime scoreboard 

![image](https://github.com/m0wn1ka/ctf/assets/127676379/60859d5e-9f9c-4ae5-a0aa-bacdd5bbfa7f)

##  crypto 

![image](https://github.com/m0wn1ka/ctf/assets/127676379/f765be57-32d9-4abc-b29f-ad863947ee81)

  * here it is just mapping of alpabets to the numbers like a-1 b-2 ![image](https://github.com/m0wn1ka/ctf/assets/127676379/d0d3d4c3-fe70-4f2c-9532-ec3f4ccfadd8)

DawgCTF{cipher_on_easy_mode} 

##  crypto 2 

![image](https://github.com/m0wn1ka/ctf/assets/127676379/6e73284e-7ba1-4b14-98e7-70dce37852e5)

  * unzip the zip file
  * we see a dumster file with names and hashes
  * this is the dumpster file ![image](https://github.com/m0wn1ka/ctf/assets/127676379/88296ab6-91e7-4cfb-b60b-e7956d4aa465)
  * we write a python script to get the hashes ``` fp=open(“dumpsterfire”,”r”) i=0 while True: line=fp.readline() if not line: break d=line.split(“:”)[1] d=d.strip() name=”file”+str(i) i+=1 f=open(name,”w”) f.write(d)


```
    - we use john to crack the hashes
    ![image](https://github.com/m0wn1ka/ctf/assets/127676379/b0f8f099-3451-474d-8cce-b07f8437640f)
    ` hashcat -m 0 -a 0 file11 rockyou.txt`
    - we use 7z x to unzip
    - ![image](https://github.com/m0wn1ka/ctf/assets/127676379/07ace1a0-2e3c-4f16-9ab6-f0e24e4950b6)
    - out of all cracked hashes the second one worked
```

serendipity astonvilla poiuytrewq gusanito guadalajara gallardo hellfire wisinyyandel nuncateolvidare systemofadown friends4eva ``` ![image](https://github.com/m0wn1ka/ctf/assets/127676379/5b23aac3-8ab9-4fc7-8a81-1f2005961d5a)

  * `DawgCTF{W3W1llR0ckY0u}`
