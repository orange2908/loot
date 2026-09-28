---
title: "Meowy - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["web", "ssrf", "flask", "werkzeug", "meowy", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The \"Meowy\" challenge presents a web application with a \"CatBoard\" functionality."
source:
  name: "CTFtime writeup #40578"
  url: "https://ctftime.org/writeup/40578"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Meowy"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Meowy
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40578>

---
**Challenge Description**:  
The "Meowy" challenge presents a web application with a "CatBoard" functionality. It allows users to fetch external content via a URL, which introduces a Server-Side Request Forgery (SSRF) vulnerability. The application is running in debug mode with the Werkzeug debugger enabled but protected by a PIN code and middleware that seemingly restricts access to localhost.

**Analysis**:  
1\. **SSRF and Local File Read**: The `/fetch` endpoint takes a `url` parameter. We confirmed it supports `file://` scheme, allowing us to read local files (e.g., `/proc/self/cmdline`, `/etc/machine-id`).  
2\. **Information Gathering**: To exploit the Werkzeug debugger (accessible at `http://127.0.0.1:5000/console`), we needed to bypass the PIN protection. We gathered:  
\- **Username**: `ctfplayer` (from `/etc/passwd`).  
\- **Modname**: `flask.app`. The application runs as a standard Flask app instance, defaults to `flask.app`.  
\- **App Name**: `Flask`.  
\- **App File**: `/usr/local/lib/python3.11/site-packages/flask/[app.py](http://app.py)`. Since `modname` is `flask.app`, the "app file" is the path to the library's `[app.py](http://app.py)`.  
\- **MAC Address**: `112644713822515` (Decimal of `66:73:24:27:39:33` from `/sys/class/net/eth0/address`).  
\- **Machine ID**: `c8f5e9d2a1b3c4d5e6f7a8b9c0d1e2f3`.

3\. **PIN Calculation**: Using these inputs, we calculated the correct PIN: `447-653-294`.  
4\. **Header Injection**: The application uses `pycurl` to fetch the user-provided URL. Since `pycurl` does not forward cookies, the PIN check failed. We used the `gopher://` protocol to craft a raw HTTP request to the internal debugger console, injecting the `Cookie` header with the calculated trust value.

**Solution**:  
1\. **Forge Trust Cookie**: Generated `__wzd...=timestamp|hash` locally using the calculated PIN.  
2\. **Inject via Gopher**: Sent a Gopher payload to `127.0.0.1:5000` executing code via the Werkzeug debugger console.  
```  
gopher://127.0.0.1:5000/_GET /console?__debugger__=yes&cmd=__import__('os').popen('/readflag').read()&frm=0&s=SECRET HTTP/1.1%0d%0aCookie: ...  
```  
3\. **Retrieve Flag**: The command execution returned the flag.

**Flag**: `ENO{w3rkz3ug_p1n_byp4ss_v1a_c00k13_f0rg3ry_l3ads_2_RCE!}`
