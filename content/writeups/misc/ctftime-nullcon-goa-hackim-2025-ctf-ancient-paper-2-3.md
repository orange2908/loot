---
title: "Ancient paper - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "ancient", "paper", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Its a IBM punchcard. The decode information can be found [here]("
source:
  name: "CTFtime writeup #39935"
  url: "https://ctftime.org/writeup/39935"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Ancient paper"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Ancient paper
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39935>

---
Its a IBM punchcard. The decode information can be found [here](  
<https://gen5.info/$/LU0NS2XPG8MDVCVZS/>)

```python=  
"""  
Most code from this repo  
# <https://github.com/MusIF-MIAI/punchcard-decoder/blob/main/card.py>

"""  
def master_card_to_map(master_card_string):  
# Turn the ASCII art sideways and build a hash lookup  
rows = master_card_string[1:].split('\n')  
rotated = [[r[i] for r in rows[0:13]] for i in range(5, len(rows[0]) - 1)]  
translate = {}  
for v in rotated:  
translate[tuple(v[1:])] = v[0]  
return translate

# IBM punch card character map  
IBM_MODEL_029_KEYPUNCH = """  
/&-0123456789ABCDEFGHIJKLMNOPQR/STUVWXYZ:#@'="`.<(+|!$*);^~,%_>? |  
12 / O OOOOOOOOO OOOOOO |  
11| O OOOOOOOOO OOOOOO |  
0| O OOOOOOOOO OOOOOO |  
1| O O O O |  
2| O O O O O O O O |  
3| O O O O O O O O |  
4| O O O O O O O O |  
5| O O O O O O O O |  
6| O O O O O O O O |  
7| O O O O O O O O |  
8| O O O O OOOOOOOOOOOOOOOOOOOOOOOO |  
9| O O O O |   
|__________________________________________________________________|"""

# Create translation map  
translate = master_card_to_map(IBM_MODEL_029_KEYPUNCH)

def decode_punch_card(data_rows):  
# Convert string data to list of columns  
columns = []  
width = len(data_rows[0])  
  
# Create columns from rows  
for i in range(width):  
column = []  
for row in data_rows:  
column.append(row[i] == '1')  
columns.append(column)  
  
# Decode each column to a character  
result = ''  
for column in columns:  
code_key = []  
for bit in column:  
code_key.append('O' if bit else ' ')  
code_key = tuple(code_key)  
result += translate.get(code_key, '•')  
  
return result

# manual work  
punch_card_data = [  
"00000010001010100110000000100010101010000000000000100000000000000000000000000000",  
"00000001110000011000110100000100000000101011011011010000000000000000000000000000",  
"00000000000100000101000001010001000101010001000000001000000000000000000000000000",  
"10000000001000000000000010000000000000000000000000000010000000000000000000000000",  
"00000000000000000000000000000000000000000000000000000000000000000000000000000000",  
"01100000000100000000111001001010010000010000000000001001100000000000000000000000",  
"00000000010000000000000000000000101000000100000000000000000000000000000000000000",  
"00000000000011110000000000010100000100000010110000010000000000000000000000000000",  
"00000011000000001000000000000000000010000000001000000000000000000000000000000000",  
"00010000000000000000000000000000000000000000000010000000010000000000000000000000",  
"00000000000011000010000000110000000100000000111000000000000000000000000000000000",  
"00000000100000000000000100000000000000101000000001100000000000000000000000000000"  
]

decoded_text = decode_punch_card(punch_card_data)  
print("Decoded text:", decoded_text)  
```
