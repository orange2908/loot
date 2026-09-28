---
title: "fixpoint - BuckeyeCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "cryptography", "cyberchef", "base64", "fixpoint", "buckeyectf", "buckeyectf-2024", "2024", "ctf-writeup"]
summary: "In this chal, we're given a \"fixed point\" which is reached when you repeatedly apply a Base64 encoding function with a custom alphabet to any string, and told to figure out what that custom alphabet w"
source:
  name: "CTFtime writeup #39583"
  url: "https://ctftime.org/writeup/39583"
ctf:
  name: "BuckeyeCTF 2024"
  year: 2024
  challenge: "fixpoint"
---

## Metadata

- **CTF:** BuckeyeCTF 2024
- **Task:** fixpoint
- **Author team:** Batman's Kitchen
- **CTFtime tags:** cryptography
- **CTFtime:** <https://ctftime.org/writeup/39583>

---
# BuckeyeCTF 2024 Fixpoint Writeup  
In this chal, we're given a "fixed point" which is reached when you repeatedly apply a Base64 encoding function with a custom alphabet to any string, and told to figure out what that custom alphabet was. To do this, we must first quickly revisit how Base64 works with a normal alphabet.

# Back to Base64-ics   
Base64 is an encoding function which converts arbitrary binary data into printable characters. The standard alphabet is A-Z, a-z, 0-9, and + / for a total of 64 characters. The best way to see how this works is to just look at it happen in practice. Suppose that the binary data we're encoding is "test12" in the UTF-8 format. This means that each of these characters is represented by 8 bits, which is to say an 8-digit binary number. We need to convert this into Base64, where each character is 6 bits (2^6 = 64). To get everything to line up neatly, we will have to group the 8-bit characters into groups of 3, giving us a chunk of 24 bits which we can then neatly encode with four 6-bit characters in Base64.

In the case of our test string, this means that we will first encode `tes` - we first convert it to binary using a tool like [CyberChef]([https://gchq.github.io/CyberChef/#recipe=To_Binary('Space',8)&input=dGVz)](https://gchq.github.io/CyberChef/#recipe=To_Binary\('Space',8\)&input=dGVz\)), giving us 01110100 01100101 01110011. We then take that and group it up into chunks of 6 bits, giving 011101 000110 010101 110011. Finally, we look at what character each of these chunks corresponds to in the [standard alphabet](<https://en.wikipedia.org/wiki/Base64#Base64_table_from_RFC_4648>), giving us `dGVz`. We can then repeat the process with the final 3 characters of the test string.  
### Observation: In Base64, groups of 3 characters are converted into groups of 4.

# Fixed Points  
Now that we've established how Base64 works normally, let's take a quick look at the concept of a fixed point. A "fixed point" refers to something which maps to itself when a function is applied to it. For example, 1 is a fixed point of f(x)=x^2, because f(1)=1. The challenge helpfully provides us a fixed point for ordinary base64.[^1] The first 12 characters of it are `Vm0wd2QyUXlV`. Let's look at what happens when we base64-encode the start here, once again in chunks of 3:  
`Vm0` -> `Vm0w`  
`wd2` -> `d2Qy`  
`QyU` -> `UXlV`

### Observation: The first 3 characters of the fixed point encode into its first 4 characters, the second group of 3 characters encode into the second group of 4, etc.

# Custom Alphabet  
This finally brings us to the actual challenge itself. We're given the fixed point and need to figure out the alphabet that corresponds to it. Let's look at the start of this fixed point as well: `NslSBwm6YNHH`

The fact that this is a fixed point implies the following mappings:  
`Nsl` -> `NslS`  
`SBw` -> `Bwm6`  
`m6y` -> `YNHH`

To get a sense for exactly what this means, we can walk through the whole encoding process for the first chunk. `Nsl` in UTF-8 corresponds to `01001110 01110011 01101100` in binary (we can use CyberChef for this as before). Splitting this into chunks of 6 bits gives `010011 100111 001101 101100`. This means that in our Base64 alphabet, `010011` (in decimal, 19) corresponds to `N`, `100111` (in decimal, 39) to `s`, etc.

We now have everything we need to solve this challenge. We just need to iterate through the characters of the fixed point provided by the author, run this calculation for each chunk of 3 characters, and every time we discover a correspondence (e.g. 19 corresponds to `N`), we save that into our alphabet string at the relevant index (in this case, this means that we set the character at index 19 to `N`). After we have discovered every correspondence, we will have the flag.

Here's a Python script which does exactly this:  
```python  
# Given in chal description  
alphabet = "bctf{?????????????????????????FiXed???????????????????????p01nT}"  
fixed = "NslSBwm6YNHHNreCNsmojw8zY9nGVzep9NoJ5LHpH3b8NKnQlB2Ca{XzIxeUyR85Y{COjRD09P4mFEAAFACZlAo0jwnGBrj7UAbwYBHDjBDEjBlMY{DWkE46YrVtaKh6ABDdVLoty{5Gjr5DMrmSNAo05DVu5NjR93m9VEDqMfHcjr5rAr2WVPo0lBVGaxA{N3mvBw8cYzbL5DHLlB8GBxrzYNo95B52N9HCIR4Ol3mcaxm3AocWkE2tArVeF{D0NxlvVrm6UElHFKmklB5CNE2tU{VtFPmp9B8WUNAtlNmUUBefyACwNR7zY9leFEwzj9nxARvDks5caoHo5sv{k{8ZYPH9aKwRABASy{HqY9vSjxAfNrBOVDA0As5EBEL7UBCZALAUj35SNKLAABmoHsocj6VUBxVp9NoSHBHDV64GU98ZjAmR5Evzl9leYweWl3lRFRv0UD4HB{X8IBv6BrDtjAl8Fwe29NoRBR4Zj9HUarmgAr5ck{DzlBAt5B76ABmf9rDkjAAGkzANNrvkjBDtY9nCaRnxMxH9ABmZAsb8NKnNy{mC5DIRl{VAUNeMMrDvBxADVs4SU92o93VoAR7zYDmEBsI7ABjwy{m09femjsIRjsm{VE4cYfeEVRBOUB8WBrmylD4GUBeAI3mvHwDOl9luFw5pY{mcVfAtlzHcjKLKU3m{MR4cjBVuFrDUNsmRMR4t5P5HU98fIAmJF{LZyfocjKLMj3ldU{8qYr88FRLflB5mBK20ArDANKAlN3m{VrmZjB59az5NANrOYzrzAKncBxVp9B5v5BmzyNVcjK46F3vvkfoKH9LGawoyMslvFLHDlElHHKADAomtNLAtUDVtaKL8Y{jw5LAtHBDmkRLRyPV{NR78YPAEVzA793vvILHKj35SFrexMrvkyLBzY3vlBx5xMrm9VBHO5DAUaRLyNACwVfAjlBeAUNeKyBDvyrH0ND48HKnxMrvkN9hzYE5AFze293CZU{Hy"

# Iterate through fixed point chars in groups of 3. We do len(fixed)//4 instead of 3 because otherwise we get an out of bounds error later.  
for i in range(len(fixed)//4):  
# Grab the 3 characters which will be converted into 4 by the b64 process (3*8 bits = 24 bits = 4*6 bits)  
# Basically, Nsl gets converted to NslS, then SBw -> BWm6, etc.  
triplet = fixed[3*i:3*i+3]

# Convert each char to 0-extended binary and join them  
binary = ''.join(format(ord(x), 'b').zfill(8) for x in triplet)

# Convert each group of 6 bits to an int and update alphabet at that index  
alphabet = alphabet[0:int(binary[0:6],2)] + fixed[4*i] + alphabet[int(binary[0:6],2)+1:]

alphabet = alphabet[0:int(binary[6:12],2)] + fixed[4*i + 1] + alphabet[int(binary[6:12],2)+1:]

alphabet = alphabet[0:int(binary[12:18],2)] + fixed[4*i + 2] + alphabet[int(binary[12:18],2)+1:]  
  
alphabet = alphabet[0:int(binary[18:],2)] + fixed[4*i + 3] + alphabet[int(binary[18:],2)+1:]  
# We did fixed[4*i] rather than 3*i because we're converting into groups of 4 chars at a time. That's why SBw -> BWm6, not SBwm

print(alphabet)  
```  
This outputs `bctf{DEPCmQqklUgj5yNBA93IHMYaVFiXedxroKsh4GuSvJW72OzwLR6Z8p01nT}`, which is the flag :)

[^1]: Eagle-eyed readers might notice that this technically isn't a fixed point. Base64-encoding any text will always produce text which is slightly longer, because each group of 3 characters is converted into 4. If we keep applying the base64 function infinitely many times, the string will grow infinitely long. What the challenge author means is that at every step in this process, `base64(string)` will begin with that same string. Mathematically keen readers are challenged to prove that any starting string will always converge in the limit to the same string upon repeated applications of `base64()` (note that, despite what the challenge implies, two starting strings might not necessarily converge to the exact same result in a finite number of steps because base64 is bijective, and the string length increases each time it's applied).
