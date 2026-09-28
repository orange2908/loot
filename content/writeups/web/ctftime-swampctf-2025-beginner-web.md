---
title: "Beginner Web - SwampCTF 2025"
category: "web"
subcategory: "aes"
type: "writeup"
tags: ["web", "aes", "ecb", "base64", "samesite", "swampctf", "swampctf-2025", "2025", "ctf-writeup"]
summary: "If there are 3 flags, then it is safe to assume that:"
source:
  name: "CTFtime writeup #40139"
  url: "https://ctftime.org/writeup/40139"
ctf:
  name: "SwampCTF 2025"
  year: 2025
  challenge: "Beginner Web"
---

## Metadata

- **CTF:** SwampCTF 2025
- **Task:** Beginner Web
- **Author team:** Raccoon Byte
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40139>

---
# Approach  
If there are 3 flags, then it is safe to assume that:  
\- the first flag will be in the easy place to be spotted.  
\- the rest will be hidden.

For the first part of the flag turned out to be a HTML comment, just under the `html` tag:  
```html

```

Now, we need to find the rest.

If the rest of the parts are hiding, most likely it will hide in the JavaScript. Turns out, by analyzing the downloaded JavaScript from the browser's network tag, we get this:  
```javascript  
var gs = class e {  
constructor(t) {  
this.cookieService = t;  
let n = "flagPart2_3"  
, r = "U2FsdGVkX1/oCOrv2BF34XQbx7f34cYJ8aA71tr8cl8="  
, o = "U2FsdGVkX197aFEtB5VUIBcswkWs4GiFPal6425rsTU=";  
this.cookieService.set("flagPart2", $n.AES.decrypt(r, n).toString($n.enc.Utf8), {  
expires: 7,  
path: "/",  
secure: !0,  
sameSite: "Strict"  
});  
let i = new Headers;  
i.set("flagPart3", $n.AES.decrypt(o, n).toString($n.enc.Utf8)),  
fetch("/favicon.ico", {  
headers: i  
})  
}  
...  
}  
```  
Based on the code snippet, we know that:  
\- both parts are encrypted; and  
\- it's encrypted using AES

But we need to know what library is used to encrypt the flag, so that we can deduce the parameters, mainly the payload and the secret key.

We found this:  
```javascript  
var $n = Yp(Sp());  
```

Now, my hunch suggested that we check `Sp` first:  
```javascript  
var Sp = Q( (ps, _p) => {  
"use strict";  
(function(e, t, n) {  
typeof ps == "object" ? _p.exports = ps = t(K(), jr(), w0(), I0(), Mt(), A0(), Tt(), fu(), Vi(), F0(), hu(), P0(), L0(), V0(), Gi(), U0(), gt(), me(), G0(), Y0(), K0(), J0(), tp(), rp(), ip(), ap(), up(), dp(), hp(), gp(), vp(), yp(), Cp(), wp(), Ip()) : typeof define == "function" && define.amd ? define(["./core", "./x64-core", "./lib-typedarrays", "./enc-utf16", "./enc-base64", "./enc-base64url", "./md5", "./sha1", "./sha256", "./sha224", "./sha512", "./sha384", "./sha3", "./ripemd160", "./hmac", "./pbkdf2", "./evpkdf", "./cipher-core", "./mode-cfb", "./mode-ctr", "./mode-ctr-gladman", "./mode-ofb", "./mode-ecb", "./pad-ansix923", "./pad-iso10126", "./pad-iso97971", "./pad-zeropadding", "./pad-nopadding", "./format-hex", "./aes", "./tripledes", "./rc4", "./rabbit", "./rabbit-legacy", "./blowfish"], t) : e.CryptoJS = t(e.CryptoJS)  
}  
)(ps, function(e) {  
return e  
})  
}  
);  
```

After asking 2nd opinion from ChatGPT regarding the original code snippet, I'm sure that flag is indeed encrypted with `CryptoJS` library. Now, we only need to decrypt those flags.

There are lots of tools online, but I used [IT Tools Tech](https://it-tools.tech/encryption). Just type in the secret key and the encrypted payload, then choose the encryption algorithm.  
# Answer  
\- Flag 1: `w3b_`  
\- Flag 2: `br0w53r5_4r3_`  
\- Flag 3: `c0mpl1c473d`  
\- Flag: `swampCTF{w3b_br0w53r5_4r3_c0mpl1c473d}`
