---
title: "just TV - justCTF 2024 teaser"
category: "rev"
type: "writeup"
tags: ["rev", "reverse", "mheg", "xor", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "Description : My favorite TV channel has recently become more interactive…"
source:
  name: "CTFtime writeup #39224"
  url: "https://ctftime.org/writeup/39224"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "just TV"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** just TV
- **Author team:** ECSC Team France
- **CTFtime tags:** reverse, mheg
- **CTFtime:** <https://ctftime.org/writeup/39224>

---
# Intro

Title : `Just TV`

Description : `My favorite TV channel has recently become more interactive…`

Attachment : `just_tv.tar.gz`

# Exploration

```  
justtv.tar.gz  
├── a  
├── clock.asn  
├── extras.asn  
├── img  
│ ├── cat.png  
│ ├── clouds.png  
│ ├── small_cat.png  
│ ├── snow.png  
│ └── sunny.png  
├── main_menu.asn  
├── splash_screen.asn  
├── tv_overlay.asn  
└── weather.asn  
```

There are some images and some unknown files (`*.asn` & `a`).

The extension `.asn` refers to the format `ASN.1`.   
This can be validated by using a [generic DER decoder](<https://lapo.it/asn1js>)

By googling `ASN.1` and `interactive television`, we get some results about `MHEG-5`.

The ASN.1 specification of `MHEG-5` can be found [here](<https://www.itu.int/ITU-T/formal-language/itu-t/t/t172/1998/ISO13522-MHEG-5.html>)

Later a hint was added to the challenge : `Hey if someone was wondering app was written in MHEG+`

The software `MHEG+` is a Java application that can interpret this instruction set.

The technical specification can be found [here](<https://www.etsi.org/deliver/etsi_es/202100_202199/202184/02.04.01_50/es_202184v020401m.pdf>)

# Reverse

The file `a` is the startup file and each `.asn` file is a different menu page.

The page `extras.asn` contains a virtual keyboard and asks for the flag. The flag checking logic is encoded with this special instruction set.

The checking logic is heavily based on `events` which trigger `links`. 

When entering a bad password, the screen turns red. The link 2583 sets the background color to red and the link 2584 sets it to green. This is the target.

The flag length must be between 1 and 70, the correct length must be guessed somehow.

The instruction `TestVariable` compares a variable content with an expression, this triggers a `TestEvent`. The `TestEvent` triggers links based on the variable tested and the test output.

A brief summary of the algorithm  
\- shuffle the key based on the input length  
\- translate each input byte with a custom charset  
\- map each byte with a 7 bit string  
\- xor this concatened bit string with the shuffled key  
\- check the result against a hardcoded value

# Solve script

```py  
# Credit to Juju 

for flag_length in range(1, 70):  
input = "a" * flag_length  
v49 = "1234567890qwertyuiopasdfghjkl{zxcvbnm_!@#$%^&*+=QWERTYUIOPASDFGHJKL}ZXCVBNM-"  
v50 = "0000000000000100000100000011000010000001010000110000011100010000001001000101000010110001100000110100011100001111001000000100010010010001001100101000010101001011000101110011000001100100110100011011001110000111010011110001111101000000100001010001001000110100100010010101001100100111010100001010010101010010101101011000101101010111001011110110000011000101100100110011011010001101010110110011011101110000111001011101001110110111100011110101111100111111100000010000011000010100001110001001000101100011010001111001000100100110010101001011"  
v51 = "00011001101110001010100100010001100100011001000011010001110101001111011011000100100111100100001011000010111001110101101110101100100101111010001100011110010111000010010100111100111101111011110100111010010110011010111110110111010111100100011110011100000010010100110100000110101011110101001010000010101000101001001010010111101110111110011001010100010000000110100001110100101111110100110011011100100000011011010101011110010010111111011101001111000100001101101001011000000001111110"  
v52 = "11010011010000101111101110101001011001101100101000111101101110101101010000010111101110000110100001000111101100000001110010010000000001011111001101111110011110111100111000111111101000110110010111100111110001111010110100110111000001001111010001100110111000101010010001000110010001100100001101000111010100111101101100010010011110010000101100001011100111010110111010110010010111101000110001111001011100001001010011110011110111101111010011101001011001101011111011011101011110010001"

v53 = input  
v61 = len(v53) * 7

v63 = v51[:v61]  
v64 = v51[v61:]  
v65 = v64 + v63

v69 = ""

def xor(a, b):  
res = ''  
for i in range(len(a)):  
res += '1' if a[i] != b[i] else '0'

return res

x = xor(v65, v52)

blocks = [x[i*7:i*7+7] for i in range(len(x) // 7)]  
v50_blocks = [v50[i*7:i*7+7] for i in range(len(v50) // 7)]

flag = ''  
is_ok = True  
for block in blocks:  
try:  
i = v50_blocks.index(block)  
flag += v49[i]  
except:  
is_ok = False  
break  
if is_ok:  
print(flag)  
```
