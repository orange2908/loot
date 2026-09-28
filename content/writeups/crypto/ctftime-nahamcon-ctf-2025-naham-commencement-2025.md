---
title: "Naham-Commencement 2025 - NahamCon CTF 2025"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "vigenere", "caesar", "naham-commencement", "classical", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "In this challenge there is a login page which we need to access to get the flag."
source:
  name: "CTFtime writeup #40274"
  url: "https://ctftime.org/writeup/40274"
original_source: "https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/warmup/NahamCommencement2025"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "Naham-Commencement 2025"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** Naham-Commencement 2025
- **Author team:** twc
- **CTFtime:** <https://ctftime.org/writeup/40274>
- **Original writeup:** <https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/warmup/NahamCommencement2025>

---
> Solved by Legend

In this challenge there is a login page which we need to access to get the flag. Seeing the source code I found that the `username` and `passowrd` is in the `main.js`.

function a(t) {  
let r = '';  
for (let i = 0; i < t.length; i++) {  
const c = t[i];  
if (/[a-zA-Z]/.test(c)) {  
const d = c.charCodeAt(0);  
const o = (d >= 97) ? 97 : 65;  
const x = (d - o + 16) % 26 + o;  
r += String.fromCharCode(x);  
} else {  
r += c;  
}  
}  
return r;  
}  
  
function b(t, k) {  
let r = '';  
let j = 0;  
for (let i = 0; i < t.length; i++) {  
const c = t[i];  
if (/[a-zA-Z]/.test(c)) {  
const u = c === c.toUpperCase();  
const l = c.toLowerCase();  
const d = l.charCodeAt(0) - 97;  
const m = k[j % k.length].toLowerCase();  
const n = m.charCodeAt(0) - 97;  
const e = (d + n) % 26;  
let f = String.fromCharCode(e + 97);  
if (u) {  
f = f.toUpperCase();  
}  
r += f;  
j++;  
} else {  
r += c;  
}  
}  
return r;  
}  
  
function c(s) {  
return btoa(s);  
}  
  
document.addEventListener('DOMContentLoaded', function () {  
const x1 = "dqxqcius";  
const x2 = "YeaTtgUnzezBqiwa2025";  
const x3 = "ZHF4cWNpdXM=";  
const k = "nahamcon";  
  
  
const f = document.getElementById('loginForm');  
const u = document.getElementById('username');  
const p = document.getElementById('password');  
const s = document.getElementById('spinner');  
const d = document.getElementById('result');  
  
f.addEventListener('submit', function (e) {  
e.preventDefault();  
  
const q = u.value;  
const w = p.value;  
  
  
const q1 = a(q);  
  
const w1 = b(w, k);  
  
if (q1 !== x1 || w1 !== x2) {  
d.textContent = "Access denied. Client-side validation failed. Try again.";  
d.className = "error";  
d.style.display = "block";  
return;  
}  
  
s.style.display = "block";  
d.style.display = "none";  
  
const g = new FormData();  
g.append('username', q);  
g.append('password', w);  
  
fetch('/login', {  
method: 'POST',  
body: g  
})  
.then(h => h.json())  
.then(z => {  
s.style.display = "none";  
d.style.display = "block";  
  
if (z.success) {  
console.log("? Server authentication successful!");  
d.innerHTML = `  


${z.message}

  


??${z.flag}??

  
`;  
d.className = "success";  
} else {  
console.log("❌ Server authentication failed");  
d.textContent = z.message;  
d.className = "error";  
}  
})  
.catch(err => {  
console.error("? Network error:", err);  
s.style.display = "none";  
d.style.display = "block";  
d.textContent = "An error occurred while processing your request.";  
d.className = "error";  
});  
});  
  
}); 

It is just that those are encrypted. Tried a bunch of algorithms, then figured it out `username` was encrypted with Caesar cipher and `password` was `Vigenère cipher`.

![](<https://i.imgur.com/P90IFbu.png>)

![](<https://i.imgur.com/bYM8awB.png>)

Putting them on the website we get the flag.

![](<https://i.imgur.com/xGMELtt.png>)

**Key Learning & Takeaways**

\- Always check linked JavaScript files they often contain important logic or hidden data.  
\- Classic ciphers like `Caesar` and `Vigenère` are still common in CTFs; learn how to recognize and decode them.  
\- If credentials look encrypted, try simple cipher tools first before overthinking it.
