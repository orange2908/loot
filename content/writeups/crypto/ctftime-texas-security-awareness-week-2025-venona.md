---
title: "Venona - Texas Security Awareness Week 2025"
category: "crypto"
type: "writeup"
tags: ["crypto", "venona", "texas-security-awareness-week", "texas-security-awareness-week-2025", "2025", "ctf-writeup"]
summary: "writeup made by: romerquelle"
source:
  name: "CTFtime writeup #40160"
  url: "https://ctftime.org/writeup/40160"
ctf:
  name: "Texas Security Awareness Week 2025"
  year: 2025
  challenge: "Venona"
---

## Metadata

- **CTF:** Texas Security Awareness Week 2025
- **Task:** Venona
- **Author team:** kiberpsihoza.exe
- **CTFtime:** <https://ctftime.org/writeup/40160>

---
# Venona; Texas Security Awareness Week CTF 2025  
\---  
writeup made by: [romerquelle](<https://github.com/Romketha>)

category: crypto

## Task description:

```  
You've been deployed on a classified reconnaissance mission deep in the jungles of Vietnam. After days of trekking through dense foliage, your team discovers an abandoned intelligence outpost that appears to have been hastily evacuated. As the team's cryptanalyst, you're tasked with investigating a small underground room containing what looks like a communication center. Among scattered papers and broken equipment, you find:

A peculiar reference table (see attached image) with alphabetic grid patterns Scattered papers with two plaintext messages and three encrypted messages.

Intelligence believes one of the three messages contains critical information about enemy operations.

flag format: texsaw{FLAG}  
```

txt file we got:  
```  
===== PLAINTEXT MESSAGES =====  
-OPERATION BLUE EAGLE MOVING TO SECTOR FOUR STOP REQUEST EXTRACTION AT BLUE EAGLE  
-AGENT SUNFLOWER COMPROMISED NEAR HANOI STOP ABORT MISSION COMPROMISED

===== ENCRYPTED MESSAGES =====  
-RCPZURNPAQELEPJUJZEGAMVMXWVWCTBMHKNYEEAZVXQWVKGMRVWXDLCANHLGY  
-FLPDBSBQIGBJECHMIOZGJMQONXJANFPQYQPWIIONYKNERKHIABLJTPTAOZMDGZUTAESK  
-KDPRMZZKNBECTGTKMKQOWXKCHMVNDOPQXUWJJLECUCLBQKKVDXJNUEYFIDAGVIUG  
```

and DIANA.tiff file we got:

![Diana](<https://upload.wikimedia.org/wikipedia/commons/thumb/1/19/NSA_DIANA_one_time_pad.tiff/lossless-page1-677px-NSA_DIANA_one_time_pad.tiff.png>)

## Solving the task

From the name of the tiff file, we can conclude that this is a DIANA cipher.  
Searching the web about the DIANA cipher and analyzing the given table, we found this page:  
```<http://www.crittologia.eu/en/critto/cifraDIANA.html>```  
This web page explains in detail how the DIANA cipher works and this made it even easier for us to write the code.  
The page says:  
```According to Shannon's theorem, a figure like this is 100% indecipherable under two conditions: 1) that the sequence is truly random; 2) that an OTP is never reused. The second depends on the organization of the service, the first condition is very difficult to respect; ```  
Given that decryption is only possible in the case of the same OTP, we assumed that both messages were encrypted with the same OTP key. Now we have all the information to write the code:

```py  
def create_diana_table():  
"""Create the DIANA cipher table from the provided information"""  
diana_table = {}  
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  
  
for i, letter in enumerate(alphabet):  
# For each row, create the bottom alphabet (shifted)  
offset = 26 - i  
bottom_row = alphabet[-offset:] + alphabet[:-offset]  
diana_table[letter] = bottom_row  
  
return diana_table

def decrypt_diana(ciphertext, key, diana_table):  
"""  
Decodes a message encrypted with the DIANA cipher  
  
Args:  
ciphertext (str): The encrypted message  
key (str): The encryption key  
diana_table (dict): Dictionary mapping rows to their bottom row values  
  
Returns:  
str: The decrypted message  
"""  
plaintext = ""  
key = key.upper() # Ensure key is uppercase  
key_length = len(key)  
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  
  
for i, char in enumerate(ciphertext):  
if not char.isalpha():  
plaintext += char # Preserve non-alphabetic characters  
continue  
  
# Get the row to use from the key (repeating as needed)  
key_char = key[i % key_length]  
  
# Find the position of the ciphertext character in the bottom row of the key's row  
bottom_row = diana_table[key_char]  
  
if char in bottom_row:  
# Find position in bottom row  
pos = bottom_row.index(char)  
# Get corresponding character from top row (standard alphabet)  
plaintext += alphabet[pos]  
else:  
plaintext += char # Character not found in table, keep as is  
  
return plaintext

def find_key_from_known_text(ciphertext, known_plaintext, diana_table):  
"""  
Attempt to find the key by using known plaintext and ciphertext pairs  
  
Args:  
ciphertext (str): The encrypted message  
known_plaintext (str): The known plaintext that corresponds to the ciphertext  
diana_table (dict): The DIANA cipher table  
  
Returns:  
str: The potential key  
"""  
# Clean up the texts - remove spaces and make uppercase  
ciphertext = ''.join(c for c in ciphertext if c.isalpha()).upper()  
known_plaintext = ''.join(c for c in known_plaintext if c.isalpha()).upper()  
  
# Ensure we only use the length of the shorter text  
length = min(len(ciphertext), len(known_plaintext))  
ciphertext = ciphertext[:length]  
known_plaintext = known_plaintext[:length]  
  
# For each pair of plaintext/ciphertext characters, determine what key letter would map one to the other  
potential_key = ""  
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  
  
for i in range(length):  
p_char = known_plaintext[i]  
c_char = ciphertext[i]  
  
# Try each possible key row  
key_found = False  
for key_char in alphabet:  
bottom_row = diana_table[key_char]  
if bottom_row[alphabet.index(p_char)] == c_char:  
potential_key += key_char  
key_found = True  
break  
  
if not key_found:  
potential_key += "?" # Couldn't find a mapping  
  
# Look for repeating patterns in the key  
for key_length in range(2, 16): # Try keys of length 2 to 15  
if len(potential_key) >= key_length * 2:  
repeat = True  
base_key = potential_key[:key_length]  
  
# Check if this segment repeats  
for i in range(key_length, len(potential_key), key_length):  
segment = potential_key[i:i+key_length]  
if segment and segment != base_key[:len(segment)]:  
repeat = False  
break  
  
if repeat:  
return base_key  
  
return potential_key

def main():  
# Create the DIANA cipher table  
diana_table = create_diana_table()  
  
# Load the encrypted messages  
encrypted_messages = [  
"RCPZURNPAQELEPJUJZEGAMVMXWVWCTBMHKNYEEAZVXQWVKGMRVWXDLCANHLGY",  
"FLPDBSBQIGBJECHMIOZGJMQONXJANFPQYQPWIIONYKNERKHIABLJTPTAOZMDGZUTAESK",  
"KDPRMZZKNBECTGTKMKQOWXKCHMVNDOPQXUWJJLECUCLBQKKVDXJNUEYFIDAGVIUG"  
]  
  
# Known plaintext messages  
plaintext_messages = [  
"OPERATION BLUE EAGLE MOVING TO SECTOR FOUR STOP REQUEST EXTRACTION AT BLUE EAGLE",  
"AGENT SUNFLOWER COMPROMISED NEAR HANOI STOP ABORT MISSION COMPROMISED"  
]  
  
# Try to find the key from the known plaintext/ciphertext pairs  
print("=== ATTEMPTING TO FIND THE KEY ===")  
for i, plaintext in enumerate(plaintext_messages):  
for j, ciphertext in enumerate(encrypted_messages):  
potential_key = find_key_from_known_text(ciphertext, plaintext, diana_table)  
print(f"Plaintext {i+1} with Ciphertext {j+1} suggests key: {potential_key}")  
  
# Try the key to see if it produces something readable  
decrypted = decrypt_diana(ciphertext, potential_key, diana_table)  
print(f"Decryption with this key: {decrypted[:50]}...\n")  
  
# Interactive mode to try different keys  
while True:  
key = input("\nEnter a key to try (or 'q' to quit): ").strip().upper()  
if key == 'Q':  
break  
  
for i, message in enumerate(encrypted_messages, 1):  
decrypted = decrypt_diana(message, key, diana_table)  
print(f"Message {i} decrypted with key '{key}':")  
print(decrypted)  
print()

if __name__ == "__main__":  
main()

```

### Detailed description of the code:

#### Creating a DIANA table:

`create_diana_table` function creates the provided DIANA cipher table.

It generates a cipher table called `diana_table` which maps each letter of the alphabet (A to Z) to a unique shifted version of the alphabet.  
The top row of the table is the standard alphabet (A-Z), and the bottom row for each key letter is a shifted version of the alphabet.  
For example:

```  
Key A: ABCDEFGHIJKLMNOPQRSTUVWXYZ → ABCDEFGHIJKLMNOPQRSTUVWXYZ  
Key B: ABCDEFGHIJKLMNOPQRSTUVWXYZ → BCDEFGHIJKLMNOPQRSTUVWXYZA  
Key C: ABCDEFGHIJKLMNOPQRSTUVWXYZ → CDEFGHIJKLMNOPQRSTUVWXYZAB   
```

The result is a dictionary where each key is a letter (A to Z), and the value is the corresponding shifted alphabet.

#### Decryption: 

`decrypt_diana` function decrypts ciphertext encoded using the DIANA cipher and a specific encryption key.

We have 3 inputs here: `ciphertext`, `key` and `diana_table` (which we got from the previously mentioned function).

##### Process:

1\. Converts the key to uppercase to ensure case insensitivity.  
2\. Iterates over each character in the ciphertext:  
\- for Non-Alphabetic Characters: Added to the plaintext as-is (e.g., spaces, punctuation).  
\- for Alphabetic Characters:   
\- Determines the row in the cipher table using the current key character.  
\- Finds the position of the ciphertext letter in the row.  
\- Maps the ciphertext letter back to the standard alphabet (A-Z) using the found position.  
3\. Returns the decrypted plaintext message.

#### Finding a key using a known plaintext:

`find_key_from_known_text` attempts to derive the encryption key used to encode a ciphertext when part of the plaintext is already known.

We also have 3 inputs here: `ciphertext`, `known_plaintext` and `diana_table`.

##### Process:

1\. Cleans up both the ciphertext and known plaintext:  
\- Removes non-alphabetic characters.  
\- Converts them to uppercase.  
2\. Iterates over each pair of plaintext and ciphertext characters:  
\- For each key character (A-Z), checks if the plaintext character maps to the ciphertext character using the cipher table.  
\- If a match is found, the corresponding key character is added to the potential key.  
\- If no match is found, a placeholder (?) is added.  
3\. Attempts to identify repeating patterns in the derived key (since encryption keys are often cyclic, e.g., `ABABAB`).  
4\. Returns the most likely key or the derived key with placeholders.

### Summarised explanation of the code:

1\. Creates cipher table: Generates the DIANA cipher table using `create_diana_table`.  
2\. Loads encrypted messages:  
\- A predefined set of encrypted messages (`encrypted_messages`) is loaded.  
\- Known plaintext messages (`plaintext_messages`) are provided for testing.  
3\. Known plaintext attack:  
\- Pairs each plaintext with each ciphertext to guess the encryption key using `find_key_from_known_text`.  
\- Decrypts messages using the derived keys to check readability.

P.S.  
Initially, the script was not interactive and required users to modify the code directly to test different encryption keys. However, I later enhanced it by integrating an interactive mode, which allows users to manually input custom encryption keys. This feature enables users to decrypt the provided encrypted messages, analyze the results, and experiment with different keys in a more user-friendly way.

### Finding the flag:

When we execute the code we get this output:

```  
=== ATTEMPTING TO FIND THE KEY ===  
Plaintext 1 with Ciphertext 1 suggests key: DNLIUYFBNPTRALJOYVSSFEIGEIDSAANVCWTHMLMKETACRSNIUCFXBSUMAHSFN   
Decryption with this key: OPERATIONBLUEEAGLEMOVINGTOSECTORFOURSTOPREQUESTEXT...

Plaintext 1 with Ciphertext 2 suggests key: RWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHG  
Decryption with this key: OPERATIONBLUEEAGLEMOVINGTOSECTORFOURSTOPREQUESTEXT...

Plaintext 1 with Ciphertext 3 suggests key: WOLAMGRWAATIPCTEBGEABPXWOYDJBVBZSGCSRSQNDYVHMSRRGESNSLQRVDHFKOQC   
Decryption with this key: OPERATIONBLUEEAGLEMOVINGTOSECTORFOURSTOPREQUESTEXT...

Plaintext 2 with Ciphertext 1 suggests key: RWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCV   
Decryption with this key: AGENTSUNFLOWERCOMPROMISEDNEARHANOISTOPABORTMISSION...

Plaintext 2 with Ciphertext 2 suggests key: FFLQIAHDDVNNALFYWZISXEYKKKFAWYPDKIXDUTOMKTUSJSPAMOJVHACMCRUZD   
Decryption with this key: AGENTSUNFLOWERCOMPROMISEDNEARHANOISTOPABORTMISSION...

Plaintext 2 with Ciphertext 3 suggests key: KXLETHFXIQQGPPRWAVZAKPSYEZRNMHPDJMEQVWEBGLSPISSNPKHZIPHRWVICS   
Decryption with this key: AGENTSUNFLOWERCOMPROMISEDNEARHANOISTOPABORTMISSION...  
```

We can notice that one of the keys appears in both cases (`RWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHG`).   
With the same code, we try decryption using that key:

```  
Enter a key to try (or 'q' to quit): RWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHG

Message 1 decrypted with key 'RWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHG':  
AGENTSUNFLOWERCOMPROMISEDNEARHANOISTOPABORTMISSIONCOMPROMISED

Message 2 decrypted with key 'RWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHG':  
OPERATIONBLUEEAGLEMOVINGTOSECTORFOURSTOPREQUESTEXTRACTIONATBLUEEAGLE

Message 3 decrypted with key 'RWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHGXKNSOEDIUJRWLMBZTCVFQPAYHG':  
THEFLAGISWONTIMEPADWITHUNDERSCORESBETWEENWORDSWRAPPEDINTHEHEADER  
```

Decrypted message: `THEFLAGISWONTIMEPADWITHUNDERSCORESBETWEENWORDSWRAPPEDINTHEHEADER`

So the flag is: `texsaw{won_time_pad}`
