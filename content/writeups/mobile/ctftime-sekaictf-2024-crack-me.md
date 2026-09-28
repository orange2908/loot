---
title: "Crack Me - SekaiCTF 2024"
category: "mobile"
subcategory: "aes"
type: "writeup"
tags: ["mobile", "android", "firebase", "aes", "cbc", "cyberchef", "sekaictf", "sekaictf-2024", "2024", "ctf-writeup"]
summary: "Sekai CTF Rev Challenge: Crack Me"
source:
  name: "CTFtime writeup #39537"
  url: "https://ctftime.org/writeup/39537"
original_source: "https://www.powershell.zip/blog/ctf-writeups/crack-me-writeup.html"
ctf:
  name: "SekaiCTF 2024"
  year: 2024
  challenge: "Crack Me"
---

## Metadata

- **CTF:** SekaiCTF 2024
- **Task:** Crack Me
- **Author team:** seasonal allergies
- **CTFtime tags:** android, firebase
- **CTFtime:** <https://ctftime.org/writeup/39537>
- **Original writeup:** <https://www.powershell.zip/blog/ctf-writeups/crack-me-writeup.html>

---
Sekai CTF Rev Challenge: Crack Me

[APK](https://static.sekai.team/5917c8e34a216396df3535c9381ecea4/CrackMe.apk)

Decompiling the app and running `rg "sekai"` I found  
`[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)`

Confirmed that `[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)` is a real user, just need to find the password.  
I found `03afaa672ff078c63d5bdb0ea08be12b09ea53ea822cd2acef36da5b279b9524` in the same code/configuration block as the admin user, and this seems to be a an AES encrypted string.

At the end of the same code block from `resources` I found the key, IV, and the AES encrypted password:  
`key = "react_native_expo_version_47.0.0"`  
`iv = "__sekaictf2023__"`  
`encrypt_pswd = "03afaa672ff078c63d5bdb0ea08be12b09ea53ea822cd2acef36da5b279b9524"`  
`length: 17`

Using the magic of [[[https://cyberchef.org/#recipe=AES_Decrypt(%7B'option':'UTF8','string':'react_native_expo_version_47.0.0'%7D,%7B'option':'UTF8','string':'__sekaictf2023__'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=MDNhZmFhNjcyZmYwNzhjNjNkNWJkYjBlYTA4YmUxMmIwOWVhNTNlYTgyMmNkMmFjZWYzNmRhNWIyNzliOTUyNA](https://cyberchef.org/#recipe=AES_Decrypt\(%7B'option':'UTF8','string':'react_native_expo_version_47.0.0'%7D,%7B'option':'UTF8','string':'__sekaictf2023__'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D\)&input=MDNhZmFhNjcyZmYwNzhjNjNkNWJkYjBlYTA4YmUxMmIwOWVhNTNlYTgyMmNkMmFjZWYzNmRhNWIyNzliOTUyNA) | cyberchef]] we get the admin password `s3cr3t_SEKAI_P@ss`

If we try and use that to log into the app, it gives us this:  
![[Pasted image 20240824093820.png]]

Which is not super helpful, but we do know this is a Firebase application, so we can begin grepping the resources folder for the API key of the project, to see if we can get any additional information.

Firebase API keys all start with `AIz`, so I tried `rg "AIz"`, and would you look at that, we got the API key `AIzaSy[REDACTED]`

Next we need to get some additional information about the project, if you look at the output from the grep to find the API key, directly after it is the rest of the configurations that we need:

```  
# Firebase project configuration  
config = {  
"apiKey": "AIzaSy[REDACTED]",  
"authDomain": "[crackme-1b52a.firebaseapp.com](http://crackme-1b52a.firebaseapp.com)",  
"databaseURL": "<https://crackme-1b52a-default-rtdb.firebaseio.com>",  
"projectId": "crackme-1b52a",  
"storageBucket": "[crackme-1b52a.appspot.com](https://crackme-1b52a.appspot.com)",  
"messagingSenderId": "544041293350",  
"appId": "1:544041293350:web:2abc55a6bb408e4ff838e7",  
"measurementId": "<https://crackme-1b52a-default-rtdb.firebaseio.com>"  
}  
```

Final code to get the flag  
```  
import requests  
api_key = "AIzaSy[REDACTED]"  
email = "[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)"  
password = "s3cr3t_SEKAI_P@ss"  
auth_url = f"<https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=>{api_key}"  
payload = {  
"email": email,  
"password": password,  
"returnSecureToken": True  
}  
auth_response = [requests.post](http://requests.post)(auth_url, data=payload)  
if auth_response.status_code == 200:  
auth_data = auth_response.json()  
id_token = auth_data['idToken'] # This is your authentication token  
uid = auth_data['localId'] # This is the user's UID  
db_url = f"<https://crackme-1b52a-default-rtdb.firebaseio.com/users/>{uid}/flag.json?auth={id_token}"  
db_response = requests.get(db_url)  
if db_response.status_code == 200:  
flag = db_response.json()  
if flag:  
print("Flag:", flag)  
else:  
print("No flag found.")  
else:  
print("Failed to retrieve data from the database:", db_response.json())  
else:  
print("Failed to authenticate:", auth_response.json())  
```

All that's left to do is run it, and would you look at that, flag acquired:`Flag: SEKAI{15_React_N@71v3_R3v3rs3_H@RD???}`
