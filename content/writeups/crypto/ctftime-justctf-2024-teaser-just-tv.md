---
title: "just TV - justCTF 2024 teaser"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "\\- The files are MHEG5 (red button) ASN1."
source:
  name: "CTFtime writeup #39195"
  url: "https://ctftime.org/writeup/39195"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "just TV"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** just TV
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39195>

---
\- The files are MHEG5 (red button) ASN1.  
\- [This](<https://code.google.com/archive/p/mhegenc/>) can be used to convert the to a human readable format.  
\- Use [these](<https://github.com/johnbeech/mheg-training-01-menu>) instructions to play the files (after replacing your `a` file with theirs).  
\- The extras menu seems to allow us to input a flag. It displays red for incorrect.  
\- Searching for green RGB (`=00=FF=00=00`) brings us to link `2584`.  
\- Link `2584` is called from link `117` which seems to be the flag checking logic.  
\- In short, the logic is:  
\- Shift `var_51` based on the length of the inputted flag to make `var_65`.  
\- Convert the inputted flag to binary (7 bits per char, using the `var_49` charset).  
\- XOR `var_65` with the binary flag (result stored in `var_70`).  
\- Compare `var_70` to `var_62`.  
\- Things that helped in reversing:  
\- The player variable view.  
\- Take the first argument of `:Cal`l (e.g. `27`), look at the top of the file for the corresponding string (e.g. `GSL`), and then search that in the [spec](<https://www.etsi.org/deliver/etsi_es/202100_202199/202184/02.04.01_50/es_202184v020401m.pdf>). I think second argument is maybe a Boolean of if the call is made, after that it is the spec arguments.  
\- Link blocks often have an `:EventData` boolean at the start. This seems to determine if they are executed (based on a proceeding `:TestVariable`).  
\- Solve script:

```python  
def xor(a, b):  
return "".join(str(int(a_ != b_)) for a_, b_ in zip(a, b))

var_51 = "00011001101110001010100100010001100100011001000011010001110101001111011011000100100111100100001011000010111001110101101110101100100101111010001100011110010111000010010100111100111101111011110100111010010110011010111110110111010111100100011110011100000010010100110100000110101011110101001010000010101000101001001010010111101110111110011001010100010000000110100001110100101111110100110011011100100000011011010101011110010010111111011101001111000100001101101001011000000001111110"  
var_52 = "11010011010000101111101110101001011001101100101000111101101110101101010000010111101110000110100001000111101100000001110010010000000001011111001101111110011110111100111000111111101000110110010111100111110001111010110100110111000001001111010001100110111000101010010001000110010001100100001101000111010100111101101100010010011110010000101100001011100111010110111010110010010111101000110001111001011100001001010011110011110111101111010011101001011001101011111011011101011110010001"  
charset = "1234567890qwertyuiopasdfghjkl{zxcvbnm_!@#$%^&*+=QWERTYUIOPASDFGHJKL}ZXCVBNM-" # =3D is = escaped

for flag_length in range(9, 49):  
var_65 = var_51[7 * flag_length :] + var_51[: 7 * flag_length]  
flag_bin = xor(var_52, var_65)

flag = ""

try:  
for i in range(0, flag_length * 7, 7):  
flag_char = int(flag_bin[i : i + 7], 2)  
flag += charset[flag_char]  
except IndexError:  
pass

print(flag)  
```
