---
title: "Stealer - BlackHat MEA CTF Qualification 2024"
category: "rev"
subcategory: "packers"
type: "writeup"
tags: ["rev", "bhmea24", "packer", "dotnet", "cyberchef", "base64", "packers", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "Method 1: Calculate the hash of the exe using Hash calculator and then upload the hash or the exe to VirusTotal (online threat intel)."
source:
  name: "CTFtime writeup #39445"
  url: "https://ctftime.org/writeup/39445"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Stealer"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Stealer
- **Author team:** Malware Minions
- **CTFtime tags:** bhmea24
- **CTFtime:** <https://ctftime.org/writeup/39445>

---
Method 1: Calculate the hash of the exe using Hash calculator and then upload the hash or the exe to VirusTotal (online threat intel). You will get its analysis within seconds. After that, go to the behavior tab of VirusTotal and analyze it. Then you will find the Cryptographic Plain Text in the Behaviour Section "54812370027267561120:QkhGbGFnWXt0M2xlZ3I0bV9nMGVzX3chbGR9" . This is token. Copy this part: "QkhGbGFnWXt0M2xlZ3I0bV9nMGVzX3chbGR". After that used the cyber chef at this URL “<https://gchq.github.io/CyberChef/>". Copy the text in input section of cyber chef. As many of the time, text i encoded with base64. So, recipe used in cyberchef this time is 'From Base64'. Now click on Bake and you will receive the Flag for stealer i.e., "BHFlagY{t3legr4m_g0es_w!ld}".  
Method 2: You can use the other tools like dnspy and dot4net for code reviewing and unpacking of the executable in which you find the obfuscated token i.e., “QkhGbGFnWXt0M2xlZ3I0bV9nMGVzX3chbGR”. The text then deobfuscated using cyberchef using “frombase64” function.
