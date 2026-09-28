---
title: "ws 1 - portswigger labs"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "burp", "websocket", "web-exploitation", "ws-1"]
summary: "web writeup for \"ws 1\" from portswigger labs - techniques: xss, burp, websocket, web-exploitation, ws-1."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/WebSockets/ws-1/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/WebSockets/ws-1/README.md"
ctf:
  name: "portswigger labs"
  challenge: "ws 1"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** ws 1
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/WebSockets/ws-1/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/WebSockets/ws-1/README.md>

---
# Manipulating WebSocket messages to exploit vulnerabilities | Dec 19, 2022

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities), you'll learn: Manipulating WebSocket messages to exploit vulnerabilities! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This online shop has a live chat feature implemented using [WebSockets](https://portswigger.net/web-security/websockets).

Chat messages that you submit are viewed by a support agent in real time.

To solve the lab, use a WebSocket message to trigger an `alert()` popup in the support agent's browser.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219005653.png)

**Live chat:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219005746.png)

**To intercept WebSocket messages, we can use Burp Suite:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010108.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010127.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010139.png)

As you can see, the live chat feature is using WebSockets.

**Let's try to send some messages:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010229.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010241.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010255.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010311.png)

In here, we can see that the a WebSocket message is being sent to the server, and **the contents of the message are transmitted to another chat user!**

**Hmm... What if I send a XSS payload to another chat user?**

**Payload:**
```html
<img src=error onerror='alert(document.domain)'>
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010722.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010752.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010840.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219010958.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/WebSockets/WS-1/images/Pasted%20image%2020221219011042.png)

We did it!

# What we've learned:

1. Manipulating WebSocket messages to exploit vulnerabilities
