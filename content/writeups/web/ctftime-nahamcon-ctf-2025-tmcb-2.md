---
title: "TMCB - NahamCon CTF 2025"
category: "web"
subcategory: "websocket"
type: "writeup"
tags: ["web", "websocket", "tmcb", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "In this challenge there are two million checkboxes that we need to check to get the flag."
source:
  name: "CTFtime writeup #40279"
  url: "https://ctftime.org/writeup/40279"
original_source: "https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/web/TMCB"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "TMCB"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** TMCB
- **Author team:** twc
- **CTFtime:** <https://ctftime.org/writeup/40279>
- **Original writeup:** <https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/web/TMCB>

---
> Solved by Legend

In this challenge there are two million checkboxes that we need to check to get the flag.

![](<https://i.imgur.com/BuowCay.png>)

The website is using web socket's to send the checked boxes and update it on server. I tired bash script to send 300000 at a time in burp but at around 1700000 the connection got reset, so I had to make a script.

I tried using JavaScript to send the checked boxes in batch and it worked.

const ws = new WebSocket('ws://' + location.host + '/ws');  
ws.onopen = () => {  
let i = 0;  
function send() {  
if (i >= 2000000) return;  
let numbers = [];  
for (let j = 0; j < 200000; j++) {  
numbers.push(i + j);  
}  
ws.send(JSON.stringify({ action: 'check', numbers: numbers }));  
i += 200000;  
setTimeout(send, 250);  
}  
send();  
};

Accidentally sent way more than required, but it worked.

![](<https://i.imgur.com/DGjYRvj.png>)

**Key Learning and Takeaways**

\- Web sockets are different from HTTP; learning how they work is useful for web challenges.  
\- Sending too much data at once can crash the connection; break it into smaller parts and add a delay.  
\- You don't need to fully know a programming language to write useful scripts experimenting helps.  
\- Automating tasks with code is often more effective than using manual tools like Burp.  
\- Code doesn’t need to be perfect, if it works, it works.
