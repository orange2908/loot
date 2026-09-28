---
title: "Shopping Time - TUCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "shopping", "time", "tuctf", "tuctf-2024", "2024", "ctf-writeup"]
summary: "The challenge provided a simple web shop page & it's source in Python."
source:
  name: "CTFtime writeup #39832"
  url: "https://ctftime.org/writeup/39832"
original_source: "https://github.com/rux-one/tuctf-2025-writeups/tree/main/shopping-time"
ctf:
  name: "TUCTF 2024"
  year: 2024
  challenge: "Shopping Time"
---

## Metadata

- **CTF:** TUCTF 2024
- **Task:** Shopping Time
- **Author team:** Hakierspejs
- **CTFtime:** <https://ctftime.org/writeup/39832>
- **Original writeup:** <https://github.com/rux-one/tuctf-2025-writeups/tree/main/shopping-time>

---
## TUCTF - Shopping time

The challenge provided a simple web shop page & it's source in Python. Looking through the code we could see that item details can be viewed via page by their's slugs and one slug in particular returns a blocked page (slug was `Flag`).

![](<https://github.com/rux-one/tuctf-2025-writeups/raw/main/uploads/fffc2625-68ed-44ed-8809-8625d955033a.png>)

It quickly became apparent that items are checked & fetched from the DB by ID made of the first 6 characters of a md5 hash of the slug. Hashing collision!

I asked Claude Sonnet to generate a python script to methodically check all strings (lowercased & digits only for simplicity) and return the first which md5 hash has the same beginning as requested string. 

![](<https://github.com/rux-one/tuctf-2025-writeups/raw/main/uploads/df042c51-8f63-408c-a73c-baa14d541bfa.png>)

And the generated `[md5_collision_finder.py](http://md5_collision_finder.py)` script goes as follows:

```python=  
#!/usr/bin/env python3  
import hashlib  
import string  
import sys  
import time

def generate_next_string(current_string=None, length=10):  
characters = string.ascii_lowercase + string.digits  
  
if current_string is None:  
return characters[0] * length  
  
char_list = list(current_string)  
pos = length - 1  
  
while pos >= 0:  
current_char_index = characters.index(char_list[pos])  
  
if current_char_index < len(characters) - 1:  
char_list[pos] = characters[current_char_index + 1]  
return ''.join(char_list)  
else:  
char_list[pos] = characters[0]  
pos -= 1  
  
return None

def find_hash_collision(prefix):  
if not all(c in string.hexdigits for c in prefix):  
raise ValueError("Prefix must contain only hexadecimal characters")

start_time = time.time()  
attempts = 1  
test_string = None  
  
while True:  
attempts += 1  
test_string = generate_next_string(test_string)  
  
if test_string is None:  
print("\nExhausted all possibilities without finding a match.")  
return None  
  
hash_result = hashlib.md5(test_string.encode()).hexdigest()  
  
if hash_result.startswith(prefix.lower()):  
end_time = time.time()  
print(f"\nFound match after {attempts:,} attempts!")  
print(f"Time taken: {end_time - start_time:.2f} seconds")  
print(f"String: {test_string}")  
print(f"MD5 Hash: {hash_result}")  
return test_string  
  
if attempts % 100000 == 0:  
print(f"Tried {attempts:,} combinations...", end='\r')

def main():  
if len(sys.argv) != 2:  
print("Usage: python [collision_finder.py](http://collision_finder.py) <prefix>")  
print("Example: python [collision_finder.py](http://collision_finder.py) a0b1")  
sys.exit(1)  
  
prefix = sys.argv[1]  
try:  
find_hash_collision(prefix)  
except ValueError as e:  
print(f"Error: {e}")  
sys.exit(1)

if __name__ == "__main__":  
main()  
```

...and it can be used like this:

![](<https://github.com/rux-one/tuctf-2025-writeups/raw/main/uploads/0824f701-be10-415f-a477-c1cbd7ee7fcb.png>)

...and it simply worked on the target website. While this particular challenge was rather `Easy` (even for me), it still makes a great reminder to be aware of hashing collisions being a real vulnerability.

![](<https://github.com/rux-one/tuctf-2025-writeups/raw/main/uploads/ce634af0-8003-4439-b3c0-245b6d94ff52.jpg>)
