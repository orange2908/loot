---
title: "Lahav433 writeups"
category: "crypto"
subcategory: "image"
type: "writeup"
tags: ["crypto", "qr-code", "base64", "image", "cryptography", "lahav433"]
summary: "The challenge begins with the following text pasted to a pastebin:"
source:
  name: "Dvd848/CTFs"
  url: "https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/README.md"
ctf:
  name: "Lahav433"
  year: 2019
---

## Source

- **CTF:** Lahav433 2019
- **Repository:** [Dvd848/CTFs](https://github.com/Dvd848/CTFs)
- **File:** <https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/README.md>

---
# Lahav 433 CTF - אתגר להב 433 - 2019

The challenge begins with the following text pasted to a pastebin:
```
MA==LA==MA==IA==NA==LA==NA==IA==NQ==LA==NA==IA==Ng==LA==NA==IA==Nw==LA==NA==IA==OA==LA==NA==IA==OQ==LA==NA==IA==MTA=LA==NA==IA==MTM=LA==NA==IA==MjA=LA==NA==IA==MjI=LA==NA==IA==MjM=LA==NA==IA==MjQ=LA==NA==IA==MjU=LA==NA==IA==MjY=LA==NA==IA==Mjc=LA==NA==IA==Mjg=LA==NA==IA==NA==LA==NQ==IA==MTA=LA==NQ==IA==MTI=LA==NQ==IA==MTM=LA==NQ==IA==MTU=LA==NQ==IA==MTY=LA==NQ==IA==MTc=LA==NQ==IA==MTk=LA==NQ==IA==MjI=LA==NQ==IA==Mjg=LA==NQ==IA==NA==LA==Ng==IA==Ng==LA==Ng==IA==Nw==LA==Ng==IA==OA==LA==Ng==IA==MTA=LA==Ng==IA==MTM=LA==Ng==IA==MTQ=LA==Ng==IA==MTU=LA==Ng==IA==MjI=LA==Ng==IA==MjQ=LA==Ng==IA==MjU=LA==Ng==IA==MjY=LA==Ng==IA==Mjg=LA==Ng==IA==NA==LA==Nw==IA==Ng==LA==Nw==IA==Nw==LA==Nw==IA==OA==LA==Nw==IA==MTA=LA==Nw==IA==MTI=LA==Nw==IA==MTM=LA==Nw==IA==MTU=LA==Nw==IA==MTc=LA==Nw==IA==MTk=LA==Nw==IA==MjI=LA==Nw==IA==MjQ=LA==Nw==IA==MjU=LA==Nw==IA==MjY=LA==Nw==IA==Mjg=LA==Nw==IA==NA==LA==OA==IA==Ng==LA==OA==IA==Nw==LA==OA==IA==OA==LA==OA==IA==MTA=LA==OA==IA==MTQ=LA==OA==IA==MTY=LA==OA==IA==MTg=LA==OA==IA==MjA=LA==OA==IA==MjI=LA==OA==IA==MjQ=LA==OA==IA==MjU=LA==OA==IA==MjY=LA==OA==IA==Mjg=LA==OA==IA==NA==LA==OQ==IA==MTA=LA==OQ==IA==MTI=LA==OQ==IA==MTQ=LA==OQ==IA==MTc=LA==OQ==IA==MTk=LA==OQ==IA==MjA=LA==OQ==IA==MjI=LA==OQ==IA==Mjg=LA==OQ==IA==NA==LA==MTA=IA==NQ==LA==MTA=IA==Ng==LA==MTA=IA==Nw==LA==MTA=IA==OA==LA==MTA=IA==OQ==LA==MTA=IA==MTA=LA==MTA=IA==MTI=LA==MTA=IA==MTQ=LA==MTA=IA==MTY=LA==MTA=IA==MTg=LA==MTA=IA==MjA=LA==MTA=IA==MjI=LA==MTA=IA==MjM=LA==MTA=IA==MjQ=LA==MTA=IA==MjU=LA==MTA=IA==MjY=LA==MTA=IA==Mjc=LA==MTA=IA==Mjg=LA==MTA=IA==MTY=LA==MTE=IA==MTg=LA==MTE=IA==MjA=LA==MTE=IA==NA==LA==MTI=IA==NQ==LA==MTI=IA==Ng==LA==MTI=IA==Nw==LA==MTI=IA==OA==LA==MTI=IA==MTA=LA==MTI=IA==MTE=LA==MTI=IA==MTI=LA==MTI=IA==MTM=LA==MTI=IA==MTQ=LA==MTI=IA==MTY=LA==MTI=IA==MTc=LA==MTI=IA==MjE=LA==MTI=IA==MjM=LA==MTI=IA==MjU=LA==MTI=IA==Mjc=LA==MTI=IA==NQ==LA==MTM=IA==Ng==LA==MTM=IA==Nw==LA==MTM=IA==OA==LA==MTM=IA==OQ==LA==MTM=IA==MTI=LA==MTM=IA==MTM=LA==MTM=IA==MTg=LA==MTM=IA==MjM=LA==MTM=IA==Mjc=LA==MTM=IA==NA==LA==MTQ=IA==Nw==LA==MTQ=IA==MTA=LA==MTQ=IA==MTE=LA==MTQ=IA==MTI=LA==MTQ=IA==MTM=LA==MTQ=IA==MTU=LA==MTQ=IA==MTY=LA==MTQ=IA==MTc=LA==MTQ=IA==MTk=LA==MTQ=IA==MjA=LA==MTQ=IA==MjE=LA==MTQ=IA==MjI=LA==MTQ=IA==MjQ=LA==MTQ=IA==MjU=LA==MTQ=IA==Mjc=LA==MTQ=IA==Mjg=LA==MTQ=IA==NQ==LA==MTU=IA==Ng==LA==MTU=IA==OQ==LA==MTU=IA==MTI=LA==MTU=IA==MTM=LA==MTU=IA==MTQ=LA==MTU=IA==MTU=LA==MTU=IA==MTg=LA==MTU=IA==MTk=LA==MTU=IA==MjA=LA==MTU=IA==MjE=LA==MTU=IA==MjI=LA==MTU=IA==MjM=LA==MTU=IA==MjQ=LA==MTU=IA==Mjg=LA==MTU=IA==NA==LA==MTY=IA==NQ==LA==MTY=IA==Ng==LA==MTY=IA==MTA=LA==MTY=IA==MTE=LA==MTY=IA==MTI=LA==MTY=IA==MTM=LA==MTY=IA==MTU=LA==MTY=IA==MTc=LA==MTY=IA==MTk=LA==MTY=IA==MjE=LA==MTY=IA==MjI=LA==MTY=IA==MjQ=LA==MTY=IA==MjY=LA==MTY=IA==Mjc=LA==MTY=IA==Mjg=LA==MTY=IA==NA==LA==MTc=IA==Ng==LA==MTc=IA==Nw==LA==MTc=IA==OQ==LA==MTc=IA==MTM=LA==MTc=IA==MTQ=LA==MTc=IA==MTY=LA==MTc=IA==MTc=LA==MTc=IA==MTg=LA==MTc=IA==MjA=LA==MTc=IA==MjU=LA==MTc=IA==Mjc=LA==MTc=IA==NA==LA==MTg=IA==Ng==LA==MTg=IA==Nw==LA==MTg=IA==OQ==LA==MTg=IA==MTA=LA==MTg=IA==MTI=LA==MTg=IA==MTQ=LA==MTg=IA==MTk=LA==MTg=IA==MjA=LA==MTg=IA==MjI=LA==MTg=IA==MjU=LA==MTg=IA==Mjc=LA==MTg=IA==Mjg=LA==MTg=IA==NA==LA==MTk=IA==Ng==LA==MTk=IA==OA==LA==MTk=IA==OQ==LA==MTk=IA==MTM=LA==MTk=IA==MTQ=LA==MTk=IA==MTY=LA==MTk=IA==MTk=LA==MTk=IA==MjA=LA==MTk=IA==MjE=LA==MTk=IA==MjI=LA==MTk=IA==MjM=LA==MTk=IA==MjQ=LA==MTk=IA==MjU=LA==MTk=IA==Mjg=LA==MTk=IA==NA==LA==MjA=IA==Ng==LA==MjA=IA==Nw==LA==MjA=IA==OQ==LA==MjA=IA==MTA=LA==MjA=IA==MTE=LA==MjA=IA==MTQ=LA==MjA=IA==MTY=LA==MjA=IA==MTg=LA==MjA=IA==MjA=LA==MjA=IA==MjE=LA==MjA=IA==MjI=LA==MjA=IA==MjM=LA==MjA=IA==MjQ=LA==MjA=IA==MjY=LA==MjA=IA==MTI=LA==MjE=IA==MTM=LA==MjE=IA==MTQ=LA==MjE=IA==MTc=LA==MjE=IA==MTk=LA==MjE=IA==MjA=LA==MjE=IA==MjQ=LA==MjE=IA==MjU=LA==MjE=IA==MjY=LA==MjE=IA==NA==LA==MjI=IA==NQ==LA==MjI=IA==Ng==LA==MjI=IA==Nw==LA==MjI=IA==OA==LA==MjI=IA==OQ==LA==MjI=IA==MTA=LA==MjI=IA==MTI=LA==MjI=IA==MTQ=LA==MjI=IA==MTU=LA==MjI=IA==MTY=LA==MjI=IA==MTc=LA==MjI=IA==MTg=LA==MjI=IA==MjA=LA==MjI=IA==MjI=LA==MjI=IA==MjQ=LA==MjI=IA==MjU=LA==MjI=IA==MjY=LA==MjI=IA==Mjc=LA==MjI=IA==Mjg=LA==MjI=IA==NA==LA==MjM=IA==MTA=LA==MjM=IA==MTM=LA==MjM=IA==MTU=LA==MjM=IA==MTg=LA==MjM=IA==MjA=LA==MjM=IA==MjQ=LA==MjM=IA==MjU=LA==MjM=IA==NA==LA==MjQ=IA==Ng==LA==MjQ=IA==Nw==LA==MjQ=IA==OA==LA==MjQ=IA==MTA=LA==MjQ=IA==MTI=LA==MjQ=IA==MTU=LA==MjQ=IA==MTk=LA==MjQ=IA==MjA=LA==MjQ=IA==MjE=LA==MjQ=IA==MjI=LA==MjQ=IA==MjM=LA==MjQ=IA==MjQ=LA==MjQ=IA==MjU=LA==MjQ=IA==MjY=LA==MjQ=IA==Mjc=LA==MjQ=IA==Mjg=LA==MjQ=IA==NA==LA==MjU=IA==Ng==LA==MjU=IA==Nw==LA==MjU=IA==OA==LA==MjU=IA==MTA=LA==MjU=IA==MTI=LA==MjU=IA==MTM=LA==MjU=IA==MTQ=LA==MjU=IA==MTY=LA==MjU=IA==MTc=LA==MjU=IA==MTk=LA==MjU=IA==MjA=LA==MjU=IA==MjE=LA==MjU=IA==MjI=LA==MjU=IA==MjQ=LA==MjU=IA==MjY=LA==MjU=IA==Mjc=LA==MjU=IA==Mjg=LA==MjU=IA==NA==LA==MjY=IA==Ng==LA==MjY=IA==Nw==LA==MjY=IA==OA==LA==MjY=IA==MTA=LA==MjY=IA==MTI=LA==MjY=IA==MTc=LA==MjY=IA==MTg=LA==MjY=IA==MjA=LA==MjY=IA==MjM=LA==MjY=IA==MjY=LA==MjY=IA==Mjg=LA==MjY=IA==NA==LA==Mjc=IA==MTA=LA==Mjc=IA==MTI=LA==Mjc=IA==MTQ=LA==Mjc=IA==MTY=LA==Mjc=IA==MTc=LA==Mjc=IA==MTk=LA==Mjc=IA==MjA=LA==Mjc=IA==MjE=LA==Mjc=IA==MjI=LA==Mjc=IA==MjM=LA==Mjc=IA==MjQ=LA==Mjc=IA==MjU=LA==Mjc=IA==Mjg=LA==Mjc=IA==NA==LA==Mjg=IA==NQ==LA==Mjg=IA==Ng==LA==Mjg=IA==Nw==LA==Mjg=IA==OA==LA==Mjg=IA==OQ==LA==Mjg=IA==MTA=LA==Mjg=IA==MTI=LA==Mjg=IA==MTY=LA==Mjg=IA==MTg=LA==Mjg=IA==MTk=LA==Mjg=IA==MjI=LA==Mjg=IA==MjM=LA==Mjg=IA==MjQ=LA==Mjg=IA==MjU=LA==Mjg=IA==MjY=LA==Mjg=IA==Mjc=LA==Mjg=IA==Mjg=LA==Mjg=IA== .svg
```

The `==` signs look like Base64 padding.
If we try to decode the first snippet, we get:
```console
# echo MA== | base64 -d
0
```

Let's write a Python script to decode the complete text:
```python
import re
import base64

msg = ""
with open("ctf_start.txt") as f:
    for b in re.findall(r"\w+==?", f.read()):
        msg += base64.b64decode(b).decode("ascii")

print(msg)
```

The output:
```
0,0 4,4 5,4 6,4 7,4 8,4 9,4 10,4 13,4 20,4 22,4 23,4 24,4 25,4 26,4 27,4 28,4 4,5 10,5 12,5 13,5 15,5 16,5 17,5 19,5 22,5 28,5 4,6 6,6 7,6 8,6 10,6 13,6 14,6 15,6 22,6 24,6 25,6 26,6 28,6 4,7 6,7 7,7 8,7 10,7 12,7 13,7 15,7 17,7 19,7 22,7 24,7 25,7 26,7 28,7 4,8 6,8 7,8 8,8 10,8 14,8 16,8 18,8 20,8 22,8 24,8 25,8 26,8 28,8 4,9 10,9 12,9 14,9 17,9 19,9 20,9 22,9 28,9 4,10 5,10 6,10 7,10 8,10 9,10 10,10 12,10 14,10 16,10 18,10 20,10 22,10 23,10 24,10 25,10 26,10 27,10 28,10 16,11 18,11 20,11 4,12 5,12 6,12 7,12 8,12 10,12 11,12 12,12 13,12 14,12 16,12 17,12 21,12 23,12 25,12 27,12 5,13 6,13 7,13 8,13 9,13 12,13 13,13 18,13 23,13 27,13 4,14 7,14 10,14 11,14 12,14 13,14 15,14 16,14 17,14 19,14 20,14 21,14 22,14 24,14 25,14 27,14 28,14 5,15 6,15 9,15 12,15 13,15 14,15 15,15 18,15 19,15 20,15 21,15 22,15 23,15 24,15 28,15 4,16 5,16 6,16 10,16 11,16 12,16 13,16 15,16 17,16 19,16 21,16 22,16 24,16 26,16 27,16 28,16 4,17 6,17 7,17 9,17 13,17 14,17 16,17 17,17 18,17 20,17 25,17 27,17 4,18 6,18 7,18 9,18 10,18 12,18 14,18 19,18 20,18 22,18 25,18 27,18 28,18 4,19 6,19 8,19 9,19 13,19 14,19 16,19 19,19 20,19 21,19 22,19 23,19 24,19 25,19 28,19 4,20 6,20 7,20 9,20 10,20 11,20 14,20 16,20 18,20 20,20 21,20 22,20 23,20 24,20 26,20 12,21 13,21 14,21 17,21 19,21 20,21 24,21 25,21 26,21 4,22 5,22 6,22 7,22 8,22 9,22 10,22 12,22 14,22 15,22 16,22 17,22 18,22 20,22 22,22 24,22 25,22 26,22 27,22 28,22 4,23 10,23 13,23 15,23 18,23 20,23 24,23 25,23 4,24 6,24 7,24 8,24 10,24 12,24 15,24 19,24 20,24 21,24 22,24 23,24 24,24 25,24 26,24 27,24 28,24 4,25 6,25 7,25 8,25 10,25 12,25 13,25 14,25 16,25 17,25 19,25 20,25 21,25 22,25 24,25 26,25 27,25 28,25 4,26 6,26 7,26 8,26 10,26 12,26 17,26 18,26 20,26 23,26 26,26 28,26 4,27 10,27 12,27 14,27 16,27 17,27 19,27 20,27 21,27 22,27 23,27 24,27 25,27 28,27 4,28 5,28 6,28 7,28 8,28 9,28 10,28 12,28 16,28 18,28 19,28 22,28 23,28 24,28 25,28 26,28 27,28 28,28 
```

Notice also that the original text ends with ` .svg`. We need to interpret the output in the context of an SVG.

At first, this looked exactly like the format of a `points` attribute of a [polygon](https://www.w3schools.com/graphics/svg_polygon.asp):
```xml
 <svg height="210" width="500">
  <polygon points="200,10 250,190 160,210" style="fill:lime;stroke:purple;stroke-width:1" />
</svg> 
```

However, if we use our output as the points, we get:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/poly.png)

The next attempt was to treat the pairs of numbers as coordinates, and print a dot at each coordinate. That produced:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/qr_circle.png)

That looks like a QR code! Switch the circles to squares and we get:
```python
import re
import base64

msg = ""
with open("ctf_start.txt") as f:
    for b in re.findall(r"\w+==?", f.read()):
        msg += base64.b64decode(b).decode("ascii")

print ('<?xml version="1.0" encoding="UTF-8" ?>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">')
for pair in msg.split():
    x, y = pair.split(",")
    print('<rect x="{}" y="{}" width="1" height="1"/>'.format(x, y))

print ("\n</svg>")
```

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/qr_square.png)

Translate it with `zbar-tools`:
```console
root@kali:/media/sf_CTFs/433/entry# zbarimg qr_square.png
QR-Code:http://l.ead.me/bb338O
scanned 1 barcode symbols from 1 images in 0.06 seconds
```

Visiting the link above, we are greeted with the following message:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/qr_site.png)

This actually looks like the next level of the CTF (basic design, login link etc.), but long story short - this is actually a real website with a very real error message. Looks like the amount of participants is larger than expected. Anyway, someone advertised the real link to the challenge (http://cyberlahavctf2019.com/), allowing us to continue.

Visiting the real site, all we get is a login page:


![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/login.png)

Inspecting the source, we see:
```html
	<form class="login-form" action="/main_page" method="post">
		<script src="1.js"></script>
		<script src="serverSideJS.js"></script>
		<p class="login-text"> </p>
		<input type="hidden" id="time" name="time" value=""/>
		<script>
			document.getElementById("time").value = get_current_time();
		</script>
		<input type="submit" value="Login" class="login-submit" />	
	</form>
```

We see that the page links to `1.js`:
```javascript
function get_current_time()
{
	var date = new Date();
	var time = date.getHours() + ':' + date.getMinutes();
	return time;
}

/*
                  ,--.    ,--.
                 ((O ))--((O ))
               ,'_`--'____`--'_`.
              _:  ____________  :_
             | | ||::::::::::|| | |
             | | ||::::::::::|| | |
             | | ||::::::::::|| | |
             |_| |/__________\| |_|
               |________________|
            __..-'            `-..__
         .-| : .--- ------- ----. : |-.
       ,\ || | |\______________/| | || /.
      /`.\:| | ||  __  __  __  || | |;/,'\
     :`-._\;.| || '--''--''--' || |,:/_.-':
     |    :  | || .-- -- - --. || |  :    |
     |    |  | || '---- -- --' || |  |    |
     |    |  | ||              || |  |    |
     :,--.;  | ||  ( ) ( ) ( ) || |  :,--.;
     (`-'|)  | ||______________|| |  (|`-')
      `--'   | |/______________\| |   `--'
             |____________________|
              `.________________,'
               (_______)(_______)
               (_______)(_______)
               (_______)(_______)
               (_______)(_______)
              |        ||        |
              '--------''--------'
*/
```

And to `serverSideJS.js`:
```javascript
module.exports = {
	get_nonce:function (time, user_agent)
	{
		return user_agent.replace(/ .*/,'') + time;
	}
}
```

The ASCII art in `1.js` is a pretty thick hint for checking out `robots.txt`:
```
User-agent: *
Disallow: /log.log
```

Obviously someone doesn't want us to see what `log.log` contains, let's check it out anyway:
```
Atomz/1.0 : 23:59 response = e2b24a6d4c12eb701e9e42d7862d196d
```

Last thing we need to mention: When clicking the login button, we are greeted with a Digest Authentication window:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/http_login.png)

A short reminder about digest authentication:
> Digest access authentication is one of the agreed-upon methods a web server can use to negotiate credentials, such as username or password, with a user's web browser. This can be used to confirm the identity of a user before sending sensitive information, such as online banking transaction history. It applies a hash function to the username and password before sending them over the network.
> Technically, digest authentication is an application of MD5 cryptographic hashing with usage of nonce values to prevent replay attacks. It uses the HTTP protocol. 
> [...] RFC 2069 specifies roughly a traditional digest authentication scheme with  security maintained by a server-generated nonce value. The authentication response is formed as follows (where HA1 and HA2 are names of string variables): 
> 
> ```
> HA1 = MD5(username:realm:password)
> HA2 = MD5(method:digestURI)
> response = MD5(HA1:nonce:HA2)
> ```
> Source: [Wikipedia](https://en.wikipedia.org/wiki/Digest_access_authentication)


Basically, when a client tries to request a resource which is protected by Digest Authentication, the following sequence happens:
1. Client requests resource
2. Server responds with error code 401 ("Unauthorized") and a `WWW-Authenticate` HTTP header, which contains a nonce (among other things)
3. Client calculates `response` (as explained above) and returns it in `Authorization` HTTP header (among other things)
4. Server checks response and decides whether to allow access to resource


A nonce is supposed to be "an arbitrary number that can be used **just once** in a cryptographic communication". However, we know how the nonce is calculated from inspecting `serverSideJS.js`. It takes the user agent string up to the first space, and appends the `time` parameter to it. This means that by modifying the `time` input value from the HTML form, and sending a custom User Agent via the HTTP headers, we can control the nonce. 

Which values should we use? The ones from the log we found!

We start by making a simple request for `/main_page`:
```console
root@kali:/media/sf_CTFs/433/login# curl -v -d "time=23:59" -A "Atomz/1.0" POST http://cyberlahavctf2019.com/main_page
* Rebuilt URL to: POST/
* Could not resolve host: POST
* Closing connection 0
curl: (6) Could not resolve host: POST
*   Trying 207.154.239.211...
* TCP_NODELAY set
* Connected to cyberlahavctf2019.com (207.154.239.211) port 80 (#1)
> POST /main_page HTTP/1.1
> Host: cyberlahavctf2019.com
> User-Agent: Atomz/1.0
> Accept: */*
> Content-Length: 10
> Content-Type: application/x-www-form-urlencoded
>
* upload completely sent off: 10 out of 10 bytes
< HTTP/1.1 401 Unauthorized
< X-Powered-By: Express
< WWW-Authenticate: Digest realm=National_Cyber_Unit ,nonce="5af65be00c55a2181ce76eb95b43fc3be98d54a1",opaque=""
< Date: Tue, 29 Jan 2019 19:36:46 GMT
< Connection: keep-alive
< Transfer-Encoding: chunked
<
<!DOCTYPE html>
<html lang="en" >

<head>
  <meta charset="UTF-8">
  <title>The Forbidden Site</title>

      <link rel="stylesheet" href="css/style.css">

</head>

<body>

        <form class="login-form" action="/main_page" method="post">
                <script src="1.js"></script>
                <script src="serverSideJS.js"></script>
                <p class="login-text"> </p>
                <input type="hidden" id="time" name="time" value=""/>
                <script>
                        document.getElementById("time").value = get_current_time();
                </script>
                <input type="submit" value="Login" class="login-submit" />
        </form>

        <div class="underlay-photo"></div>
        <div class="underlay-black"></div>

</body>

</html>
```

The important part in the response is:
```
WWW-Authenticate: Digest realm=National_Cyber_Unit ,nonce="5af65be00c55a2181ce76eb95b43fc3be98d54a1",opaque=""
```

We use the realm and nonce in the next request, providing also the response from the log. We need to supply a username as well, let's guess "admin" and cross our fingers.
```console
root@kali:/media/sf_CTFs/433/login# curl -v -d "time=23:59" -A "Atomz/1.0" POST http://cyberlahavctf2019.com/main_page -H 'Authorization: Digest username="admin", realm="National_Cyber
_Unit", nonce="5af65be00c55a2181ce76eb95b43fc3be98d54a1", opaque="", uri="/main_page", response="e2b24a6d4c12eb701e9e42d7862d196d"'
* Rebuilt URL to: POST/
* Could not resolve host: POST
* Closing connection 0
curl: (6) Could not resolve host: POST
*   Trying 207.154.239.211...
* TCP_NODELAY set
* Connected to cyberlahavctf2019.com (207.154.239.211) port 80 (#1)
> POST /main_page HTTP/1.1
> Host: cyberlahavctf2019.com
> User-Agent: Atomz/1.0
> Accept: */*
> Authorization: Digest username="admin", realm="National_Cyber_Unit", nonce="5af65be00c55a2181ce76eb95b43fc3be98d54a1", opaque="", uri="/main_page", response="e2b24a6d4c12eb701e9e42d7862d196d"
> Content-Length: 10
> Content-Type: application/x-www-form-urlencoded
>
* upload completely sent off: 10 out of 10 bytes
< HTTP/1.1 200 OK
< X-Powered-By: Express
< Set-Cookie: AccountType=B6FE1C672256EB8D509CD619691F866CA5D02A929ABD37643AC43C58ADD490C5; Max-Age=900; Path=/; Expires=Tue, 29 Jan 2019 19:52:23 GMT; HttpOnly
< Accept-Ranges: bytes
< Cache-Control: public, max-age=0
< Last-Modified: Sun, 27 Jan 2019 06:35:17 GMT
< ETag: W/"7fa-1688e04fa7f"
< Content-Type: text/html; charset=UTF-8
< Content-Length: 2042
< Date: Tue, 29 Jan 2019 19:37:23 GMT
< Connection: keep-alive
<
<!DOCTYPE html>
<html lang="en" >

<head>
  <meta charset="UTF-8">
  <title>The Forbidden Site</title>
  <link rel="stylesheet" href="main.css">
  <link href='https://fonts.googleapis.com/css?family=Cinzel Decorative' rel='stylesheet'>
  <link href='https://fonts.googleapis.com/css?family=Fredericka the Great' rel='stylesheet'>

</head>

<body>
        <script src="2.js"></script>
        <script src="https://npmcdn.com/js-alert/dist/jsalert.min.js"></script>
        <div class="menu">
                <p>
                        <script>
                                function my_alert(){
                                        alert("You Dont Contact Us We Contact You!!!");
                                }
                        </script>
                        <script>var _0x1d20=["\x6F\x6E\x72\x65\x61\x64\x79\x73\x74\x61\x74\x65\x63\x68\x61\x6E\x67\x65","\x72\x65\x61\x64\x79\x53\x74\x61\x74\x65","\x73\x74\x61\x74\x75\x73","\x47\x45\x54","\x2F\x6C\x6F\x61\x64\x5F\x66\x69\x6C\x65","\x6F\x70\x65\x6E","\x73\x65\x6E\x64","\x72\x65\x73\x70\x6F\x6E\x73\x65\x54\x65\x78\x74","\x54\x72\x75\x65","\x2F\x73\x65\x63\x72\x65\x74\x5F\x66\x69\x6C\x65","\x72\x65\x70\x6C\x61\x63\x65","\x6C\x6F\x63\x61\x74\x69\x6F\x6E","\x59\x6F\x75\x20\x64\x6F\x6E\x74\x20\x68\x61\x76\x65\x20\x70\x65\x72\x6D\x69\x73\x73\x69\x6F\x6E\x73\x20\x66\x6F\x72\x20\x74\x68\x61\x74"];function load_file(){var _0x5d43x2= new XMLHttpRequest();_0x5d43x2[_0x1d20[0]]= function(){if(this[_0x1d20[1]]== 4&& this[_0x1d20[2]]== 200){myFunction(this)}};_0x5d43x2[_0x1d20[5]](_0x1d20[3],_0x1d20[4],true);_0x5d43x2[_0x1d20[6]]()}function myFunction(_0x5d43x4){if(_0x5d43x4[_0x1d20[7]]== _0x1d20[8]){window[_0x1d20[11]][_0x1d20[10]](_0x1d20[9])}else {alert(_0x1d20[12])}}</script>
                        <div onclick="my_alert()" style="text-decoration: none;color:white" title >&emsp;Contact Us &emsp;</div>
                        <div class = 'thing' onclick="load_file()" title>Our Secret File</div>
                </p>
        </div>

        <div class="underlay-photo"></div>
        <p class="text_box">Welcome<br/>
        To The<br/>
        Hacker Hub<br/>
        </p>

        <div class="container1"
                <p> This is the hacker hub.
                <br>The site who knows all, sees all, hacks all...</p>
        </div>

        <div class="links"
        </div>


</body>

</html>
```

We were able to bypass the Digest authentication! 

Let's take a look at what we got here. First, there's an obfuscated script:
```javascript
var _0x1d20=["\x6F\x6E\x72\x65\x61\x64\x79\x73\x74\x61\x74\x65\x63\x68\x61\x6E\x67\x65","\x72\x65\x61\x64\x79\x53\x74\x61\x74\x65","\x73\x74\x61\x74\x75\x73","\x47\x45\x54","\x2F\x6C\x6F\x61\x64\x5F\x66\x69\x6C\x65","\x6F\x70\x65\x6E","\x73\x65\x6E\x64","\x72\x65\x73\x70\x6F\x6E\x73\x65\x54\x65\x78\x74","\x54\x72\x75\x65","\x2F\x73\x65\x63\x72\x65\x74\x5F\x66\x69\x6C\x65","\x72\x65\x70\x6C\x61\x63\x65","\x6C\x6F\x63\x61\x74\x69\x6F\x6E","\x59\x6F\x75\x20\x64\x6F\x6E\x74\x20\x68\x61\x76\x65\x20\x70\x65\x72\x6D\x69\x73\x73\x69\x6F\x6E\x73\x20\x66\x6F\x72\x20\x74\x68\x61\x74"];
function load_file(){var _0x5d43x2= new XMLHttpRequest();_0x5d43x2[_0x1d20[0]]= function(){if(this[_0x1d20[1]]== 4&& this[_0x1d20[2]]== 200){myFunction(this)}};_0x5d43x2[_0x1d20[5]](_0x1d20[3],_0x1d20[4],true);_0x5d43x2[_0x1d20[6]]()}
function myFunction(_0x5d43x4){if(_0x5d43x4[_0x1d20[7]]== _0x1d20[8]){window[_0x1d20[11]][_0x1d20[10]](_0x1d20[9])}else {alert(_0x1d20[12])}}
```

After manually de-obfuscating it, we get:
```javascript
var _0x1d20=[
    "onreadystatechange", // 0
    "readyState",// 1
    "status",// 2
    "GET",// 3
    "/load_file",// 4
    "open",// 5
    "send",// 6
    "responseText",// 7
    "True",// 8
    "/secret_file",// 9
    "replace",// 10
    "location",// 11
    "You dont have permissions for that"// 12
    ];
    
function load_file(){
    var ajax_req = new XMLHttpRequest();
    ajax_req["onreadystatechange"]= function(){
        if(this["readyState"]== 4 && this["status"]== 200){
            myFunction(this)
        }
    };
    
    ajax_req["open"](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/%22GET%22,%22/load_file%22,true);
    ajax_req["send"]()
}

function myFunction(that){
    if(that["responseText"]== "True"){
        window["location"]["replace"](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/%22/secret_file%22)
    }
    else {
        alert("You dont have permissions for that")
    }
}
```

In addition, the page includes `2.js`:
```javascript
var _0x2be5=['length','log','YW45fc9vwUcuLzCWUmUeTC913yt9hunkqKNmYoU2rFGr8e99Pf3UjnZH5EXAULX2dcTbfZrxScREgDFJcLUGSGVhG75Dbo8NVWo956dpENycavPFtbQYMAyhiq8eZJzxdXLpHHHuEKSB4qu3wqfNz5krqWvkXR5qs12F55p5aV9'];
(function(_0x328653,_0x20e5c0){var _0x32f82e=function(_0x4eea02){while(--_0x4eea02){_0x328653['push'](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/_0x328653['shift']());}};_0x32f82e(++_0x20e5c0);}(_0x2be5,0x1c1));
var _0x3a52=function(_0x2d8f05,_0x4b81bb){_0x2d8f05=_0x2d8f05-0x0;var _0x4d74cb=_0x2be5[_0x2d8f05];return _0x4d74cb;};
function get_admin_cookie(){var _0x48471f=_0x3a52('0x0');var _0x3d069a='';for(i=_0x48471f[_0x3a52('0x1')]-0x1;i>=0x0;i--){_0x3d069a+=_0x48471f[i];}console[_0x3a52('0x2')](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/_0x3d069a);console['log'](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/'encoding:%5Cx20bitcoin');}
```

This one is a bit harder to de-obfuscate, but we can at least indent it:
```javascript
var _0x2be5=[
    'length',
    'log','YW45fc9vwUcuLzCWUmUeTC913yt9hunkqKNmYoU2rFGr8e99Pf3UjnZH5EXAULX2dcTbfZrxScREgDFJcLUGSGVhG75Dbo8NVWo956dpENycavPFtbQYMAyhiq8eZJzxdXLpHHHuEKSB4qu3wqfNz5krqWvkXR5qs12F55p5aV9'];
    
(function(_0x328653,_0x20e5c0){
    var _0x32f82e=function(_0x4eea02){
        while(--_0x4eea02){
            _0x328653['push'](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/_0x328653['shift']());
        }
    };
    _0x32f82e(++_0x20e5c0);
}(_0x2be5,0x1c1));

var _0x3a52=function(_0x2d8f05,_0x4b81bb){
    _0x2d8f05=_0x2d8f05-0x0;
    var _0x4d74cb=_0x2be5[_0x2d8f05];
    return _0x4d74cb;
};

function get_admin_cookie(){
    var _0x48471f=_0x3a52('0x0');
    var _0x3d069a='';
    for(i=_0x48471f[_0x3a52('0x1')]-0x1;i>=0x0;i--){
        _0x3d069a+=_0x48471f[i];
    }
    console[_0x3a52('0x2')](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/_0x3d069a);
    console['log'](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/'encoding:%5Cx20bitcoin');
}
```

So what do we have? Clicking on the link `Our Secret File` will call the javascript function `load_file`, which will make an AJAX request to `/load_file`. If the request is successful and the response text is `True`, we get redirected to `/secret_file`. 

What happens if we try to access `/secret_file` directly? We get:

```
TypeError: Cannot read property '0' of undefined
    at /root/apps/CTF/app.js:135:22
    at Layer.handle [as handle_request] (/root/apps/CTF/node_modules/express/lib/router/layer.js:95:5)
    at next (/root/apps/CTF/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/root/apps/CTF/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/root/apps/CTF/node_modules/express/lib/router/layer.js:95:5)
    at /root/apps/CTF/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/root/apps/CTF/node_modules/express/lib/router/index.js:335:12)
    at next (/root/apps/CTF/node_modules/express/lib/router/index.js:275:10)
    at SendStream.error (/root/apps/CTF/node_modules/serve-static/index.js:121:7)
    at emitOne (events.js:116:13)
```

This is different than the regular 404 response for the site, which usually outputs something similar to:
```
Cannot GET /asdf
```

Perhaps we need to use the logic in `2.js`. By running it locally and using the browser developer console to call `get_admin_cookie()`, we get:
```
>>> get_admin_cookie()
9Va5p55F21sq5RXkvWqrk5zNfqw3uq4BSKEuHHHpLXdxzJZe8qihyAMYQbtFPvacyNEpd659oWVN8obD57GhVGSGULcJFDgERcSxrZfbTcd2XLUAXE5HZnjU3fP99e8rGFr2UoYmNKqknuh9ty319CTeUmUWCzLucUwv9cf54WY 2.js:31:28
encoding: bitcoin 2.js:32:5
undefined
```

A quick search reveals that "bitcoin encoding" is also known as "base58 encoding", and we can easily find an online decoder:

```console
# curl "http://lenschulwitz.com/base58er" --data "address=9Va5p55F21sq5RXkvWqrk5zNfqw3uq4BSKEuHHHpLXdxzJZe8qihyAMYQbtFPvacyNEpd659oWVN8obD57GhVGSGULcJFDgERcSxrZfbTcd2XLUAXE5HZnjU3fP99e8rGFr2UoYmNKqknuh9ty319CTeUmUWCzLucUwv9cf54WY&b58action=decode"
7B0A09686173683A207368613235360A09636F6F6B6965206E616D653A204163636F756E74547970650A096C656E6774683A20340A0956616C3A65313563663632356466396365353661313233663762326434383138646439323738616331643835353363333130616566386661393939306639643662333661200A7D
```

Let's decode that as ASCII:
```console
# curl -s "http://lenschulwitz.com/base58er" --data "address=9Va5p55F21sq5RXkvWqrk5zNfqw3uq4BSKEuHHHpLXdxzJZe8qihyAMYQbtFPvacyNEpd659oWVN8obD57GhVGSGULcJFDgERcSxrZfbTcd2XLUAXE5HZnjU3fP99e8rGFr2UoYmNKqknuh9ty319CTeUmUWCzLucUwv9cf54WY&b58action=decode" | xxd -r -p && echo
{
        hash: sha256
        cookie name: AccountType
        length: 4
        Val:e15cf625df9ce56a123f7b2d4818dd9278ac1d8553c310aef8fa9990f9d6b36a
}
```

We are searching for a string of length 4 with a given SHA256 value, should be easy to brute-force:
```python
import string
import hashlib
from itertools import product

HASH = "e15cf625df9ce56a123f7b2d4818dd9278ac1d8553c310aef8fa9990f9d6b36a"
for word in (''.join(i) for i in product(string.printable, repeat = 4)):
    h = hashlib.sha256(word).hexdigest()
    if h == HASH:
        print word
        break
```

Answer is received in a few seconds: `1haV`.

Now we can try to download the secret file:
```console
root@kali:/media/sf_CTFs/433/login# curl -v -X GET http://cyberlahavctf2019.com/secret_file --cookie "AccountType=1haV" -O
Note: Unnecessary use of -X or --request, GET is already inferred.
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:--  0:00:04 --:--:--     0*   Trying 207.154.239.211...
* TCP_NODELAY set
* Connected to cyberlahavctf2019.com (207.154.239.211) port 80 (#0)
> GET /secret_file HTTP/1.1
> Host: cyberlahavctf2019.com
> User-Agent: curl/7.61.0
> Accept: */*
> Cookie: AccountType=1haV
>
< HTTP/1.1 200 OK
< X-Powered-By: Express
< Content-disposition: attachment; filename=success.rar
< Content-type: application/x-rar-compressed
< Date: Tue, 29 Jan 2019 20:52:48 GMT
< Connection: keep-alive
< Transfer-Encoding: chunked
<
{ [3850 bytes data]
100  501k    0  501k    0     0  87666      0 --:--:--  0:00:05 --:--:--  109k

root@kali:/media/sf_CTFs/433/login# file secret_file
secret_file: RAR archive data, v4, os: Win32

root@kali:/media/sf_CTFs/433/login# rar v success.rar

RAR 5.50   Copyright (c) 1993-2017 Alexander Roshal   11 Aug 2017
Trial version             Type 'rar -?' for help

Archive: success.rar
Details: RAR 4

 Attributes      Size    Packed Ratio    Date    Time   Checksum  Name
----------- ---------  -------- ----- ---------- -----  --------  ----
    ..A....      1375      1221  88%  2019-01-24 17:18  E18C5927  sucess/A1w4ysG0_l3ft2RIGHT.png
    ..A....   1146720    512134  44%  2019-01-24 17:51  7D4A1833  sucess/Huffman Queue.wav
    ...D...         0         0   0%  2019-01-24 19:07  00000000  sucess
----------- ---------  -------- ----- ---------- -----  --------  ----
              1148095    513355  44%                              3
```

We get two files. First, an image:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/A1w4ysG0_l3ft2RIGHT.png)

This image contains the following string:
```
000101101000111110111000111010011100011101
```

In addition, we get an audio file. Playing the file provides no meaningful output, so the meaning must be hiding elsewhere. The file name is "Huffman Queue" which is our first hint.

When running `exiftool` on the file, we get our second hint:
```console
# exiftool Huffman_Queue.wav
ExifTool Version Number         : 11.10
File Name                       : Huffman_Queue.wav
Directory                       : .
File Size                       : 1120 kB
File Modification Date/Time     : 2019:01:24 17:51:14+02:00
File Access Date/Time           : 2019:01:29 22:53:49+02:00
File Inode Change Date/Time     : 2019:02:03 22:12:55+02:00
File Permissions                : rwxrwx---
File Type                       : WAV
File Type Extension             : wav
MIME Type                       : audio/x-wav
Encoding                        : Microsoft PCM
Num Channels                    : 1
Sample Rate                     : 44100
Avg Bytes Per Sec               : 88200
Bits Per Sample                 : 16
Artist                          : Guassian 3.5
Duration                        : 13.00 s
```

The artist name is "Guassian 3.5" - a reference to a type of FFT window in signal analysis. 

The standard tool for viewing and analyzing audio files is usually Audacity:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/wavform.png)

Here we can see that the amplitude of the signal does not vary, while frequency does. Zooming in to the wavform, we can see a change of frequency at the ninth second:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/wavform2.png)

By displaying the spectrogram (clicking the black arrow next to the file name) and modifying the parameters a bit, we can see a nice visualization of the different frequencies:

* Scale: Logarithmic
* Algorithm: Frequencies
* Window size: 8192
* Window type: **Gaussian(a=3.5)**

The result:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/spectrogram.png)

We can see that the frequency changes once at the 3rd second, then again at the 5th second, and then every second until the end (13 seconds total).

The next step would be to identify the frequency of each segment. We can do that by selecting a segment and clicking on "Analyze -> Plot Spectrum".

For example, this is the Frequency for 0.0-1.0, after the sample rate to 32768 (the maximum for a 1 second range) and the function to **Gaussian(a=3.5)** (like the hint):

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/plot0.png)

We can see in the "Peak" field the value of "111 Hz".

If we repeat this for every 1 second range in the file, we get:

```
111, 111, 111, 103, 103, 89, 85, 108, 105, 57, 56, 48, 47
```

Notice how all the values are in the ASCII printable range, which is usually a good sign. Translated to ASCII, we get:

```
o, o, o, g, g, Y, U, l, i, 9, 8, 0, /
```

We even got a slash, which is great since it can be used to represent a URI path.

However, this is where I got stuck, I wasn't able to turn this into anything meaningful. Consulted a friend which has worked with me on some CTFs in the past (Yaakov Cohen), but we were both stumped until we got the following two hints:
1. The sample rate needs to be 1024 and not 32768 (not cool!)
2. The output needs to be used to build a Huffman tree in order to decode the bit stream above (we considered that already and overruled it since there are many ways to build a Huffman tree when several characters have the same frequency - so also not cool!)

The first hint brought us to the following frequency peaks:
```
111, 111, 111, 103, 103, 89, 85, 108, 105, 57, 56, 47, 46
o,   o,   o,   g,   g,   Y,  U,  l,   i,   9,  8,  /,  .
```

We kept our "/", and also gained a ".". Yaakov immediately saw that this looks like the Google URL Shortener `goo.gl/`. Formally, the Huffman tree can be built using the following script:

```python
import heapq
from collections import namedtuple, Counter

text = "oooggYUli98/."
msg = list("000101101000111110111000111010011100011101")

QueueEntry = namedtuple('QueueEntry', 'node insertion_order')

class Node(object):
    def __init__(self, data, freq, small, big):
        self.data = data
        self.freq = freq
        self.left = small
        self.right = big

    def __eq__(self, other):
        return other.freq == self.freq

    def __lt__(self, other):
         return self.freq < other.freq

    def __str__(self):
        return "('{}', {})".format(self.data, self.freq)

    def __repr__(self):
        return str(self)

queue = []
counter = 0
for item in Counter(text).items():
    letter, frequency = item
    heapq.heappush(queue, QueueEntry(  Node(data = letter,
                                            freq = frequency,
                                            small = None,
                                            big = None),
                                       -1 * counter))
    counter += 1



while (len(queue) > 1):
    small = heapq.heappop(queue).node
    big = heapq.heappop(queue).node
    new = Node(data = None, freq = small.freq + big.freq, small=small, big=big)
    heapq.heappush(queue, QueueEntry(new, -1 * counter))
    counter += 1

root = heapq.heappop(queue).node

tree = {}
def build_tree(node, s):
    if node.data != None:
        tree[s] = node.data
        return
    build_tree(node.left, s + '0')
    build_tree(node.right, s + '1')

build_tree(root, "")
print(tree)

c = ""
while (len(msg) != 0):
    c += msg.pop(0)
    if c in tree:
        print(tree[c], end='')
        c = ""
```

In this implementation, we maintain the order of insertion to the priority queue, so that an item which is being inserted to the queue and has the same priority as an item which was inserted before, will be placed after the old item. We do this by using tuples of two elements as entries of the queue: `node` and `insertion_order`. The `node` contains a `Node` class instance, which compares itself to other `Nodes` by comparing the frequency, so when two nodes have different frequencies, their order in the queue is determined by that value alone. When the frequencies are equal, the comparison moves on to the next entry in the tuple, which is a negative running counter, so that newly inserted items always have a lower priority compared to existing items.

Running the script gives the following result:
```
{'00': 'g', '01': 'o', '1000': '8', '1001': '9', '1010': '.', '1011': '/', '1100': 'U', '1101': 'Y', '1110': 'i', '1111': 'l'}
goo.gl/8i9UoY
```

As a tree, it looks like this:
```
        _____________#_______________                              
      0/                             \1                            
    __#__                   __________#___________                 
  0/     \1               0/                      \1               
  g       o          _____#____                ____#_____          
                   0/          \1            0/          \1        
                ___#___      ___#___      ___#___      ___#___     
              0/       \1  0/       \1  0/       \1  0/       \1   
              8         9  .         /  U         Y  i         l   
```

The left hand branch of each node is encoded as 0, and the right hand branch is encoded as 1. So to get from the root to "g", we go twice left, meaning that the encoding is "00". To get to "U", we go right, right, left, left, so the encoding is "1100".

Off to goo.gl/8i9UoY, we continue, which brings us to a Telegram channel called "R U ready?", owned by "Lahav 433 cyber unit".

The channel offered RAR file for download:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/telegram.png)

```console
root@kali:/media/sf_CTFs/433/1N7ERCEP7U5# ls
Instructions.json Server.ova Client.ova
root@kali:/media/sf_CTFs/433/1N7ERCEP7U5# cat Instructions.json
{
  "Password": "laeyobmsamlrdmyh",
  "Commands": [
    "whoami",
    "ls",
    "time",
        "get flag",
        "get key",
    "downloadfile [filename]",
    "help",
    "quit"
  ]
}
```

We have two [*.ova](https://en.wikipedia.org/wiki/Open_Virtualization_Format) files, which is a format used to distribute software to be run in virtual machines.

Therefore, the next step is to import Client.ova and Server.ova into VirtualBox using "File -> Import Appliance".

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/vbox1.png)

We start the machines and observe.

The server boots to the following screen:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/server.png)

The client boots to the following screen:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/client.png)

Trying to connect to either of the machines with the password supplied in the JSON file is unsuccessful.

So we have a server listening on 192.168.54.150:11111 and a client trying to connect to this address. Time to launch Wireshark and try to analyze the traffic. 

In order to reduce noise and gain better control over the network, it made sense to me to create a new host network interface using VirtualBox and assign it the subnet of 192.168.54.x:

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/vbox_adapter.png)

I then assigned this new adapter as a Host-only adapter of the two virtual machines we got, in addition to a third machine which acts as a controller of sorts.

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/client_network_settings.png)


Once the machines were booted again, Wireshark captured the following network traffic:

```console
root@kali:/media/sf_CTFs/433/1N7ERCEP7U5/pcap# tshark -r traffic.pcapng
    1 0.000000000 PcsCompu_f4:51:fa → Broadcast    ARP 60 Who has 192.168.54.150? Tell 192.168.54.151
    2 0.000009993 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 192.168.54.150 is at 08:00:27:14:69:d5
    3 0.000137690 192.168.54.151 → 192.168.54.150 TCP 74 36716 → 11111 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=3318941419 TSecr=0 WS=128 36716 11111
    4 0.000233057 192.168.54.150 → 192.168.54.151 TCP 74 11111 → 36716 [SYN, ACK] Seq=0 Ack=1 Win=28960 Len=0 MSS=1460 SACK_PERM=1 TSval=1043065940 TSecr=3318941419 WS=128 11111 36716
    5 0.000388519 192.168.54.151 → 192.168.54.150 TCP 66 36716 → 11111 [ACK] Seq=1 Ack=1 Win=29312 Len=0 TSval=3318941420 TSecr=1043065940 36716 11111
    6 0.039759345 192.168.54.150 → 192.168.54.151 TCP 82 11111 → 36716 [PSH, ACK] Seq=1 Ack=1 Win=29056 Len=16 TSval=1043065980 TSecr=3318941420 11111 36716
    7 0.039875575 192.168.54.150 → 192.168.54.151 TCP 66 11111 → 36716 [FIN, ACK] Seq=17 Ack=1 Win=29056 Len=0 TSval=1043065980 TSecr=3318941420 11111 36716
    8 0.039878363 192.168.54.151 → 192.168.54.150 TCP 66 36716 → 11111 [ACK] Seq=1 Ack=17 Win=29312 Len=0 TSval=3318941459 TSecr=1043065980 36716 11111
    9 0.040145647 192.168.54.151 → 192.168.54.150 TCP 66 36716 → 11111 [FIN, ACK] Seq=1 Ack=18 Win=29312 Len=0 TSval=3318941459 TSecr=1043065980 36716 11111
   10 0.040235053 192.168.54.150 → 192.168.54.151 TCP 66 11111 → 36716 [ACK] Seq=18 Ack=2 Win=29056 Len=0 TSval=1043065980 TSecr=3318941459 11111 36716
   11 1.045147271 192.168.54.151 → 192.168.54.150 TCP 74 35700 → 15850 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=3318942463 TSecr=0 WS=128 35700 15850
   12 1.045439731 192.168.54.150 → 192.168.54.151 TCP 74 15850 → 35700 [SYN, ACK] Seq=0 Ack=1 Win=28960 Len=0 MSS=1460 SACK_PERM=1 TSval=1043066985 TSecr=3318942463 WS=128 15850 35700
   13 1.045933465 192.168.54.151 → 192.168.54.150 TCP 66 35700 → 15850 [ACK] Seq=1 Ack=1 Win=29312 Len=0 TSval=3318942465 TSecr=1043066985 35700 15850
   14 5.063573683 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 Who has 192.168.54.151? Tell 192.168.54.150
   15 5.063997581 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 192.168.54.151 is at 08:00:27:f4:51:fa
   16 121.177132417 192.168.54.151 → 192.168.54.150 TCP 72 35700 → 15850 [PSH, ACK] Seq=1 Ack=1 Win=29312 Len=6 TSval=3319062535 TSecr=1043066985 35700 15850
   17 121.177587403 192.168.54.150 → 192.168.54.151 TCP 66 15850 → 35700 [ACK] Seq=1 Ack=7 Win=29056 Len=0 TSval=1043187056 TSecr=3319062535 15850 35700
   18 121.178018522 192.168.54.150 → 192.168.54.151 TCP 91 15850 → 35700 [PSH, ACK] Seq=1 Ack=7 Win=29056 Len=25 TSval=1043187057 TSecr=3319062535 15850 35700
   19 121.178396954 192.168.54.151 → 192.168.54.150 TCP 66 35700 → 15850 [ACK] Seq=7 Ack=26 Win=29312 Len=0 TSval=3319062537 TSecr=1043187057 35700 15850
   20 126.272890626 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 Who has 192.168.54.150? Tell 192.168.54.151
   21 126.273127272 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 192.168.54.150 is at 08:00:27:14:69:d5
   22 126.297370899 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 Who has 192.168.54.151? Tell 192.168.54.150
   23 126.297467854 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 192.168.54.151 is at 08:00:27:f4:51:fa
   24 241.318067318 192.168.54.151 → 192.168.54.150 TCP 74 35700 → 15850 [PSH, ACK] Seq=7 Ack=26 Win=29312 Len=8 TSval=3319182616 TSecr=1043187057 35700 15850
   25 241.318842868 192.168.54.150 → 192.168.54.151 TCP 91 15850 → 35700 [PSH, ACK] Seq=26 Ack=15 Win=29056 Len=25 TSval=1043307138 TSecr=3319182616 15850 35700
   26 241.320511830 192.168.54.151 → 192.168.54.150 TCP 66 35700 → 15850 [ACK] Seq=15 Ack=51 Win=29312 Len=0 TSval=3319182619 TSecr=1043307138 35700 15850
   27 246.439909724 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 Who has 192.168.54.150? Tell 192.168.54.151
   28 246.440595748 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 192.168.54.150 is at 08:00:27:14:69:d5
   29 246.465037762 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 Who has 192.168.54.151? Tell 192.168.54.150
   30 246.465719604 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 192.168.54.151 is at 08:00:27:f4:51:fa
   31 361.482437470 192.168.54.151 → 192.168.54.150 TCP 74 35700 → 15850 [PSH, ACK] Seq=15 Ack=51 Win=29312 Len=8 TSval=3319302721 TSecr=1043307138 35700 15850
   32 361.483256608 192.168.54.150 → 192.168.54.151 TCP 91 15850 → 35700 [PSH, ACK] Seq=51 Ack=23 Win=29056 Len=25 TSval=1043427242 TSecr=3319302721 15850 35700
   33 361.484115437 192.168.54.151 → 192.168.54.150 TCP 66 35700 → 15850 [ACK] Seq=23 Ack=76 Win=29312 Len=0 TSval=3319302723 TSecr=1043427242 35700 15850
   34 366.607010922 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 Who has 192.168.54.150? Tell 192.168.54.151
   35 366.607023914 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 192.168.54.150 is at 08:00:27:14:69:d5
   36 366.630833279 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 Who has 192.168.54.151? Tell 192.168.54.150
   37 366.631135125 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 192.168.54.151 is at 08:00:27:f4:51:fa
   38 481.646232022 192.168.54.151 → 192.168.54.150 TCP 72 35700 → 15850 [PSH, ACK] Seq=23 Ack=76 Win=29312 Len=6 TSval=3319422824 TSecr=1043427242 35700 15850
   39 481.646731995 192.168.54.150 → 192.168.54.151 TCP 91 15850 → 35700 [PSH, ACK] Seq=76 Ack=29 Win=29056 Len=25 TSval=1043547346 TSecr=3319422824 15850 35700
   40 481.647153247 192.168.54.151 → 192.168.54.150 TCP 66 35700 → 15850 [ACK] Seq=29 Ack=101 Win=29312 Len=0 TSval=3319422826 TSecr=1043547346 35700 15850
   41 486.772498057 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 Who has 192.168.54.150? Tell 192.168.54.151
   42 486.774421458 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 192.168.54.150 is at 08:00:27:14:69:d5
   43 486.798472755 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 Who has 192.168.54.151? Tell 192.168.54.150
   44 486.798911741 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 192.168.54.151 is at 08:00:27:f4:51:fa
```


What do we have here? The client (192.168.54.151) initiates a connection with the server (192.168.54.150) on port 11111 (packet #3-5).

The server sends some data to the client (packet #6):

```console
root@kali:/media/sf_CTFs/433/1N7ERCEP7U5/pcap# tshark -r traffic.pcapng -Y frame.number==6 -T json  -e data.data
[
  {
    "_index": "packets-2019-02-18",
    "_type": "pcap_file",
    "_score": null,
    "_source": {
      "layers": {
        "data.data": ["c1:88:51:ba:99:ab:41:41:7e:05:56:a9:9b:6d:38:fb"]
      }
    }
  }

]
```

The server closes the connection (packets #7-9). Immediately after that, the client connects to a different port - 15850 (packets #11-13). This port is nowhere to be seen in the data received from the server.

Then, every two minutes, the client sends data to the server and receives a response (#16-19, #24-26, etc.):

```
root@kali:/media/sf_CTFs/433/1N7ERCEP7U5/pcap# tshark -r traffic.pcapng -qz follow,tcp,ascii,1

===================================================================
Follow: tcp,ascii
Filter: tcp.stream eq 1
Node 0: 192.168.54.151:35700
Node 1: 192.168.54.150:15850
6
123456
        25
wrong password, try again
8
password
        25
wrong password, try again
8
12345678
        25
wrong password, try again
6
qwerty
        25
wrong password, try again
===================================================================
```

We see that the client is trying to log in with different passwords, and the server is rejecting the passwords. Perhaps this is where the password from the JSON file fits in?

So we just have to connect to the same port and send our password, no?

Here's a Python script that will try to do that:
```python
import socket

TCP_IP = '192.168.54.150'
TCP_PORT = 15850
BUFFER_SIZE = 1024
MESSAGE = "laeyobmsamlrdmyh"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
s.send(MESSAGE)
data = s.recv(BUFFER_SIZE)
s.close()

print "received data:", data
```

However, the server just ACKs the message, as seen in the following capture:

```
    1 0.000000000 192.168.54.151 → 192.168.54.150 TCP 73 35700 → 15850 [PSH, ACK] Seq=1 Ack=1 Win=229 Len=7 TSval=3320863856 TSecr=1044868275 35700 15850
    2 0.000429219 192.168.54.150 → 192.168.54.151 TCP 91 15850 → 35700 [PSH, ACK] Seq=1 Ack=8 Win=227 Len=25 TSval=1044988377 TSecr=3320863856 15850 35700
    3 0.001079105 192.168.54.151 → 192.168.54.150 TCP 66 35700 → 15850 [ACK] Seq=8 Ack=26 Win=229 Len=0 TSval=3320863857 TSecr=1044988377 35700 15850
    4 5.161008116 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 Who has 192.168.54.150? Tell 192.168.54.151
    5 5.161636569 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 192.168.54.150 is at 08:00:27:14:69:d5
    6 5.187090877 PcsCompu_14:69:d5 → PcsCompu_f4:51:fa ARP 60 Who has 192.168.54.151? Tell 192.168.54.150
    7 5.187526058 PcsCompu_f4:51:fa → PcsCompu_14:69:d5 ARP 60 192.168.54.151 is at 08:00:27:f4:51:fa
    8 7.568105122 192.168.54.1 → 192.168.54.150 TCP 60 65218 → 15850 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0 65218 15850
    9 7.682326812 192.168.54.1 → 192.168.54.150 TCP 66 65221 → 15850 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM=1 65221 15850
   10 7.682508917 192.168.54.150 → 192.168.54.1 TCP 66 15850 → 65221 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=128 15850 65221
   11 7.682648282 192.168.54.1 → 192.168.54.150 TCP 60 65221 → 15850 [ACK] Seq=1 Ack=1 Win=525568 Len=0 65221 15850
   12 7.683109519 192.168.54.1 → 192.168.54.150 TCP 60 65221 → 15850 [PSH, ACK] Seq=1 Ack=1 Win=525568 Len=4 65221 15850
   13 7.683112379 192.168.54.150 → 192.168.54.1 TCP 60 15850 → 65221 [ACK] Seq=1 Ack=5 Win=29312 Len=0 15850 65221
   14 12.870963103 PcsCompu_14:69:d5 → 0a:00:27:00:00:0c ARP 60 Who has 192.168.54.1? Tell 192.168.54.150
   15 12.870976254 0a:00:27:00:00:0c → PcsCompu_14:69:d5 ARP 60 192.168.54.1 is at 0a:00:27:00:00:0c
```

Packets 1-3 show the real client sending an incorrect password to the server (packet #2) and receiving a response that the password is invalid (packet #3).

Packets 9-13 show the controller (IP: 192.168.54.1) establishing a TCP connection with the server, and sending the password (packet #12). The server just responds with an ACK (packet #13). One possible explanation would be that the server acts differently for incorrect and correct passwords, however repeating the experiment with an incorrect password still can't get the server to send any response.

Another observation from running the flow multiple times is that each time, after connecting to port 11111 and receiving a 16-byte message from the server, the client connects to a different port. 

In the example, the client received a response of `c18851ba99ab41417e0556a99b6d38fb` and connected to port 15850. Other experiments showed the following results:
```
7b74622e35280296ffc437b6fc5a2625 -> port 24321
c836c672c2a168780447189a2d949b9d -> port 21247
3074dd34f4ef97b1b8f73dcf4afabe13 -> port 20655
```

The port was never part of the plaintext message, meaning that the client and server are agreeing on a port using some different kind of protocol. This means that we can't simply write a client that connects to 11111, receives the 16-byte buffer and then connects to the new port and sends the password, since we don't know what the new port will be. And since we can't connect to the new port after the real client has connected to it, we need a different way to attack this problem.

I had two ideas as to how to proceed from this point: An easy way and a harder way. I started with the easy way...

The easy way:
We have two virtual machines, with two virtual hard drives. If we use each drive as a boot device, we boot to the operating systems like we saw before. What happens though if we just mount these HDs as secondary storage devices to an existing virtual machine?

![](https://raw.githubusercontent.com/Dvd848/CTFs/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/images/vbox-hd.png)

The answer is that we get direct access to the contents and can read any file we want!

Notice how the client and the server print the following line when booting:

```
Restoring backup files from /mnt/sda1/tce/mydata.tgz
```

After booting to the controller, we start by listing the storage devices we have:
```console
root@kali:/# fdisk -l | grep Disk
Disk /dev/sda: 16 GiB, 17179869184 bytes, 33554432 sectors
Disklabel type: dos
Disk identifier: 0x034c7279
Disk /dev/sdb: 16 GiB, 17179869184 bytes, 33554432 sectors
Disklabel type: dos
Disk identifier: 0xc773fc5f
Disk /dev/sdc: 5 GiB, 5368709120 bytes, 10485760 sectors
Disklabel type: dos
Disk identifier: 0x00000000
Disk /dev/sdd: 5 GiB, 5368709120 bytes, 10485760 sectors
Disklabel type: dos
Disk identifier: 0x00000000
```

There are four disks. The first two are part of my regular setup, leaving `/dev/sdc` and `/dev/sdd` which are the two new devices. Let's mount them:

```console
root@kali:/# mount /dev/sdc1 /mnt/m/ --read-only
root@kali:/# cd /mnt/m
root@kali:/mnt/m# ls
lost+found  tce
root@kali:/mnt/m# ls tce
boot  firstrun  mydata.tgz  onboot.lst  ondemand  optional  xwbar.lst
root@kali:/mnt/m# tar -tvf tce/mydata.tgz
drwxrwsr-x root/staff        0 2019-01-31 13:39 opt/
-rw-rw-r-- tc/staff        153 2019-01-31 13:39 opt/.filetool.lst
-rwxr-xr-x root/staff      186 2019-01-24 16:02 opt/eth0.sh
-rw-r--r-- tc/staff         23 2019-01-24 15:56 opt/.appbrowser
-rw-rw-r-- root/staff       31 2019-01-24 15:55 opt/tcemirror
-rw-rw-r-- root/staff      145 2018-03-19 13:06 opt/.xfiletool.lst
-rwxr-xr-x root/staff      272 2018-03-19 13:06 opt/bootsync.sh
-rwxr-xr-x root/staff      613 2018-03-19 13:06 opt/shutdown.sh
-rwxr-xr-x root/staff       97 2019-01-24 20:07 opt/bootlocal.sh
drwxrwsr-x root/staff        0 2019-01-24 15:52 opt/backgrounds/
drwxrwxr-x root/staff        0 2019-01-24 15:52 home/
drwxr-s--- tc/staff          0 2019-01-31 13:38 home/tc/
drwx--S--- tc/staff          0 2019-01-31 13:37 home/tc/.fltk/
drwx--S--- tc/staff          0 2019-01-31 13:37 home/tc/.fltk/fltk.org/
-rw-r--r-- tc/staff         94 2019-01-31 13:39 home/tc/.fltk/fltk.org/fltk.prefs
-rw-r--r-- tc/staff         97 2019-01-24 16:06 home/tc/.fltk/fltk.org/filechooser.prefs
lrwxrwxrwx root/staff        0 2019-01-31 13:37 home/tc/.wbar -> /usr/local/tce.icons
-rwxr-xr-x tc/staff        275 2019-01-24 15:52 home/tc/.Xdefaults
-rwxr-xr-x tc/staff        103 2019-01-24 15:52 home/tc/.setbackground
-rwxr-xr-x tc/staff        450 2019-01-24 15:52 home/tc/.xsession
-rw-r--r-- tc/staff        920 2018-03-19 13:06 home/tc/.profile
-rw-rw-r-- tc/staff       1815 2019-01-31 13:39 home/tc/.ash_history
-rw-r--r-- tc/staff        446 2018-03-19 13:06 home/tc/.ashrc
-rwxrwxrwx tc/staff      95492 2019-01-24 18:30 home/tc/number.py
-rwxrwxrwx tc/staff     420240 2019-01-27 20:20 home/tc/canudoit.zip
-rwxrwxrwx tc/staff       4555 2019-01-31 13:38 home/tc/server.py
-rwxrwxrwx tc/staff          0 2019-01-31 12:00 home/tc/flag.txt
drwxr-s--- tc/staff          0 2019-01-24 15:52 home/tc/.local/
drwxr-s--- tc/staff          0 2019-01-24 15:52 home/tc/.local/bin/
drwxr-s--- tc/staff          0 2019-01-24 15:52 home/tc/.X.d/
-rw-rw---- root/staff      168 2019-01-24 15:53 etc/shadow
-rwxr-xr-x root/staff      186 2019-01-24 16:02 opt/eth0.sh
-rwxr-xr-x root/root      2432 2019-01-24 16:05 usr/local/lib/python2.7/site-packages/Crypto/pct_warnings.py
-rw-r--r-- root/root     95492 2019-01-24 18:31 usr/local/lib/python2.7/site-packages/Crypto/Util/number.py
```

We can copy `mydata.tgz` to our local filesystem, extract it and inspect the interesting files. Then we should unmount the filesystem using `umount /mnt/m`.

For the server, the interesting files are `canudoit.zip` (we'll get to that much later) and `server.py`:
```python
import socket
import sys
import random
import os
import time
import hashlib
from time import sleep
from Crypto.Cipher import AES


def commands(comm):

    comm_decoded = comm.decode('UTF-8')
    if comm.isdigit():
        return str(comm_decoded)
    elif comm_decoded == 'whoami':
        return 'LUKE, I am your father!'
    elif comm_decoded == 'ls':
        ls = "420240    canudoit.zip\n"
        ls += "4096      Downloads\n"
        ls += "4096      Home\n"
        ls += "4096      Public"

        return ls
    elif comm_decoded == 'time':
        return 'It\'s time to say GOODBYE!'
    elif comm_decoded == 'downloadfile canudoit.zip':
        return 'send zip'
    elif comm_decoded == 'get key':
        key = "AES\n"
        key += "key=4dJhvjFRn2oXraty\n"
        key += "iv=1234567890123456\n"
        key += "MODE_CBC\n"
        return key
    elif comm_decoded == 'get flag':
        g = open('/home/tc/flag.txt', 'r+')
        k = g.read(1024)
        if k == '':
            md5f = hashlib.md5("bazinga").hexdigest()
            nflag = random.randint(10000, 99999)

            flag = ''
            n = 0
            for i in str(nflag):
                flag += md5f[int(i)]
                flag += str(nflag)[n]
                n += 1
            g.write(flag)
        else:
            flag = k
        g.close()
        return "your flag is: " + flag
    elif comm_decoded == 'help':
        return 'I really want to help you, but I hate get COMMANDS!'
    elif comm_decoded == 'quit':
        return 'ok, bye'
    else:
        return 'I can\'t understand you!'


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]

server_ip = "192.168.54.150"
# Create a TCP/IP socket
sockfirst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = (server_ip, 11111)
print >>sys.stderr, 'starting up on %s port %s' % server_address
sockfirst.bind(server_address)

# Listen for incoming connections
sockfirst.listen(1)

# Wait for a connection
#print >>sys.stderr, 'waiting for a connection'
connection_f, client_address_f = sockfirst.accept()
try:
    #print >> sys.stderr, 'connection from', client_address_f
    main_port = random.randint(1024, 65535)
    mport = str(main_port).encode('utf-8')
    encryption_suite = AES.new('4dJhvjFRn2oXraty', AES.MODE_CBC, '1234567890123456')
    raw = pad(mport)
    encrypted = encryption_suite.encrypt(raw)
    #print(str(encrypted))
    connection_f.sendall(encrypted)
finally:
    connection_f.close()

sock_main = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address_m = (server_ip, main_port)
#print >> sys.stderr, 'starting up on %s port %s' % server_address_m
sock_main.bind(server_address_m)

# Listen for incoming connections
sock_main.listen(1)

# Wait for a connection
#print >>sys.stderr, 'waiting for a connection'
timeout = time.time() + 3
connection_m, client_address_m = sock_main.accept()

# check if the time pass
if time.time() > timeout:
    connection_m.close()
    print ('connection timeout')

try:
    #print >> sys.stderr, 'connection from', client_address_m
    data = connection_m.recv(4098)
    #print >> sys.stderr, 'received "%s"' % data
    password = 'laeyobmsamlrdmyh'

    # Get in loop
    while data != password:
        connection_m.sendall('wrong password, try again')
        data = connection_m.recv(4098)
        #print >> sys.stderr, 'received "%s"' % data
    while data:
        connection_m.sendall('ok')
        #print('welcome')

        # get first command
        data = connection_m.recv(4098)

        res = 0
        while data != 'quit':
            # get commands
            #print >> sys.stderr, 'received "%s"' % data
            cmd = data.rstrip('\n')
            res = commands(cmd)
            connection_m.send(res)

            if res == 'send zip':
                f = open('/home/tc/canudoit.zip', 'rb')
                f.seek(0)

                l = f.read(1024)
                while (l):
                    connection_m.send(l)
                    l = f.read(1024)
                f.close()

                #print >> sys.stderr, 'Done sending'

            #print('wait to client')
            # wait for next command
            data = connection_m.recv(4098)

        #print >> sys.stderr, 'bye'
        break

    #print >> sys.stderr, 'no more data from', client_address_m
finally:
    # Clean up the connection
    #print >> sys.stderr, 'closing socket'
    connection_m.close()
```

For the client, we have a file called `passwords.txt` with 8MB worth of passwords, and `client.py`:

```python
import socket
import sys
import time
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]

# read all the passwords
lines = [line.rstrip() for line in open('home/tc/passwords.txt')]

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_ip = "192.168.54.150"
# Connect the socket to the port where the server is listening
server_address = (server_ip, 11111)
res = sock.connect_ex(server_address)
while res != 0:
    res = sock.connect_ex(server_address)

print >>sys.stderr, 'connecting to %s port %s' % server_address
```

---

*Truncated at 1200 lines. Full text: <https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2019_Lahav433/README.md>*
