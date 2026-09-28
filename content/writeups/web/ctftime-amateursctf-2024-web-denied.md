---
title: "web/denied - AmateursCTF 2024"
category: "web"
type: "writeup"
tags: ["burp", "cyberchef", "nodejs", "web", "denied", "amateursctf", "amateursctf-2024", "2024", "ctf-writeup"]
summary: "Hi All, As we can notice little bit later, “what options do i have?” is kind of a tip (at this moment we don’t know about this, yet)."
source:
  name: "CTFtime writeup #39346"
  url: "https://ctftime.org/writeup/39346"
original_source: "https://medium.com/@embossdotar/amateursctf-2024-web-denied-challenge-writeup-a2964c67b665"
ctf:
  name: "AmateursCTF 2024"
  year: 2024
  challenge: "web/denied"
---

## Metadata

- **CTF:** AmateursCTF 2024
- **Task:** web/denied
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39346>
- **Original writeup:** <https://medium.com/@embossdotar/amateursctf-2024-web-denied-challenge-writeup-a2964c67b665>

---
Hi All, As we can notice little bit later, “what options do i have?” is kind of a tip (at this moment we don’t know about this, yet).  
At start we should take a look at attached code and be a more familiar with given website.

So let’s check <http://denied.amt.rs/> with DevTools. Looks ‘clear’. The same about source code (CTRL+U) and few tries of enumerations (recon).

For example “<http://denied.amt.rs/robots.txt”> gives:  
Cannot GET /robots.txt

Similar, checking ‘.git’:

<http://denied.amt.rs/.git> gives  
Cannot GET /.git

Let’s take a look at the attached part of code named ‘index.js’ and analyse it.

File “index.js”:

```  
const express = require(‘express’)  
const app = express()  
const port = 3000

app.get(‘/’, (req, res) => {  
if (req.method == “GET”) return res.send(“Bad!”);  
res.cookie(‘flag’, process.env.FLAG ?? “flag{fake_flag}”)  
res.send(‘Winner!’)  
})

app.listen(port, () => {  
console.log(`Example app listening on port ${port}`)  
})  
```

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*zq0kL0ONJpSXWlCytfihAQ.png>)

Code index.js — “web/denied” task, AmateursCTF 2024. Source: <https://beautifier.io/>

This CTF challenge is a Node.js application that listens for incoming HTTP requests on port 3000. When a GET request is received at the root endpoint (“/”), it sends back a response with the text “Bad!”.

However, there’s a catch. The application sets a cookie named “flag” with the value of the environment variable FLAG, which contains the flag. But this only happens if the HTTP method of the request is not GET.

To get the flag, you need to send a request to the server using a method other than GET.

You can try to send a POST request to the server, triggering the setting of the “flag” cookie. Then you can inspect the cookie to retrieve the flag.

Using Burp — for case with POST answer is “Cannot POST /”

In addition to the common [HTTP verbs](<https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods>) like GET and POST, there are several other HTTP methods that can be used in web applications. Some of these methods include:

PUT: Typically used to update or create a resource at a specific URI. It replaces the current representation of the target resource with the request payload.

DELETE: Removes the specified resource at the given URI.

PATCH: Applies partial modifications to a resource. It’s often used when you want to apply a partial update to a resource.

HEAD: Similar to GET but only returns the HTTP headers and no message body. It’s often used to retrieve meta-information about a resource without transferring the entire content.

OPTIONS: Requests information about the communication options available for the target resource, such as supported methods or server capabilities.

TRACE: Echoes the received request so that the client can see what changes or additions have been made by intermediate servers.

For mentioned CTF challenge, you might want to try some of these HTTP methods, especially if the application is designed to respond differently based on the method used. For example, if the application only allows POST requests to a specific endpoint, trying other methods like PUT or DELETE may yield different results.

There is many ways of approach, as well as you can use different [tools](<https://www.postman.com/>).

You can use your Kali machine <https://www.kali.org/> for example

Repro steps to get a Flag are like below:

\- Open [Firefox](<https://www.mozilla.org/pl/firefox/>) and enable [FoxyProxy](<https://getfoxyproxy.org/>). Use [Burp Suite](<https://portswigger.net/burp>) to get first request (Forward).  
  
\- Check HTTP History tab and use Send to Repeater (CTRL+R).

\- Change HTTP verb from GET to HEAD and click Send.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*H0YPkG6A4OfofUKIGHwEZw.png>)

Step 1 - with GET (Request — Response), Burp Suite

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*OyzrxLqtTZ39uBUqyoFPWg.png>)

Step 2 — with HEAD (Request — Response), Burp Suite

```  
Request:  
HEAD / HTTP/1.1  
Host: [denied.amt.rs](http://denied.amt.rs)  
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Accept-Encoding: gzip, deflate  
Connection: close  
Upgrade-Insecure-Requests: 1  
```

and the:

```  
Response:  
HTTP/1.1 200 OK  
Content-Length: 7  
Content-Type: text/html; charset=utf-8  
Date: Thu, 11 Apr 2024 11:16:25 GMT  
Etag: W/”7-skdQAtrqJAsgWjDuibJaiRXqV44"  
Server: Caddy  
Set-Cookie: flag=amateursCTF%7Bs0_m%40ny_0ptions…%7D; Path=/  
X-Powered-By: Express  
Connection: close  
```

You can mark a value of the Flag and Send to Decoder.  
Decode as URL:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*T-tNKS90mP_zMzdJjTvpIg.png>)

Decoder (Burp Suite) — FLAG value

As mentioned before, you can also use [CyberChef](<https://gchq.github.io/CyberChef/>) and other solutions.

Result — the Flag:  
**amateursCTF{s0_m@ny_0ptions…}**

I hope you enjoy!
