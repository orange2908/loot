---
title: "Rotten - CTF@CIT 2025"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "cryptography", "rot13", "caesar", "cyberchef", "rotten", "classical", "ctf-cit", "ctf-cit-2025", "2025", "ctf-writeup"]
summary: "I'm here to write about a cryptography challenge called \"Rotten\""
source:
  name: "CTFtime writeup #40209"
  url: "https://ctftime.org/writeup/40209"
ctf:
  name: "CTF@CIT 2025"
  year: 2025
  challenge: "Rotten"
---

## Metadata

- **CTF:** CTF@CIT 2025
- **Task:** Rotten
- **Author team:** Infinity Code Asia
- **CTFtime tags:** cryptography, rot13
- **CTFtime:** <https://ctftime.org/writeup/40209>

---
Hey, Zul from Singapore!   
I'm here to write about a cryptography challenge called "Rotten"

\-----

# Rotten  
This is a cryptography challenge. Yet the easiest one to tackle.

Aight firstly, we have this skibidi ohio format: PVG{LxxdJwAXJGcsDoncKfRctddA}.

Seems annoying isn't it? Welp, you don't need any fancy skills or anything to solve this.

All you need is to understand how cipher works!

## Eh Zul, WAT CIPHER SIAA?  
ok ok chill, Cipher is basically a technique on making a simple message very hard to read. Or in another word, secret message passing around without people understanding the standard language (I mean common human language).

## Eh talk too much how to solve this sia?  
Okai, let's stop yapping and teach you exactly how to solve this.

\-----  
### Step 1) Go to a cryptography decrypter sites  
There's many cryptography decrypter sites out There  
to translate this guy over here: PVG{LxxdJwAXJGcsDoncKfRctddA}

in this example we'll be using [CyberChef](<https://gchq.github.io/CyberChef/>)  
### Step 2) Analyze the cipher  
Here's a funny theory. Most common cipher always ROT13 which basically a orginal alphabetical order but shifted idle left or right with certain number differences. Let me show you an example:

| Alphabetical | A | B | C | D | E | F | G | H | I | J | K | L | M | N | O | P | Q | R | S | T | U | V | W | X | Y | Z |  
|---------------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|  
| Ciphered | C | D | E | F | G | H | I | J | K | L | M | N | O | P | Q | R | S | T | U | V | W | X | Y | Z | A | B |

As you can see from this example, it is shifted by 3 (count the original shift too!)

ok ok now what if you don't know what kind of ciphered it is??

in this case in CyberChef we have a feature called "**magic**"   
What this does is analyzing you the text it's been ciphered.

And you may get like  
|Result snippet | Properties |  
|-------------- |------------|  
|PVG{LxxdJwAXJGcsDoncKfRctddA}| Matching ops: From Base85 Valid UTF8 Entropy: 4.25|

Isn't useful isn't it? So, in this case we try **ROT13** since we have officially learn that it basically shift left or right.

**NOTE: IT MAY PRODUCE FALSE CIPHERED. IT'S GOOD TO KNOW YOUR FOUNDATION CRYPTOGRAPHY.**

### step 3) How many rotation?  
Aight, now on the search bar on the app search for **"ROT13"** and you'll see the option of ROT13.  
Now what you need to do now is drag that guy from his dearest life into the white container beside you/ aka you workspace.

How default it give you a shift of 13.. But this isn't shifted by 13 time. But you're lucky it's shifted 13 times.

Or else you had to manually range the number from 2 to 20 (to check first time work or not. If not increase to 40) :3

\-----  
# FLAG FOUND  
**CIT{YkkqWjNKWTpfQbapXsEpgqqN}**
