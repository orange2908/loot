---
title: "Powerplay - Nullcon Goa HackIM 2025 CTF"
category: "misc"
subcategory: "integer"
type: "writeup"
tags: ["misc", "integer-overflow", "powerplay", "integer", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "An interactive challenge where we are given the python code for the challenge and our job is to trick the server to reveal the flag."
source:
  name: "CTFtime writeup #39995"
  url: "https://ctftime.org/writeup/39995"
original_source: "https://w1r3w01f.github.io/2025/02/02/Nullcon-2025/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Powerplay"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Powerplay
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39995>
- **Original writeup:** <https://w1r3w01f.github.io/2025/02/02/Nullcon-2025/>

---
# Powerplay

## Description

An interactive challenge where we are given the python code for the challenge and our job is to trick the server to reveal the flag.

## Solution

\- On initial inspection of the code, we can find the vulnerability in it,

\- `server`  
```  
import numpy as np  
from secret import flag, quotes

prizes = quotes + ['missingno'] * 4 + [flag] * 24

if __name__ == '__main__':  
print('Welcome to our playground for powerful people where you can pump yourself up and get awesome prizes!\n')  
player_count = int(input('How many players participate?\n'))  
power = np.zeros(player_count, dtype = np.int32)  
for i in range(player_count):  
power[i] = int(input(f'Player {i}, how strong are you right now?\n'))  
ready = False

while True:  
print('What do you want to do?\n1) pump up\n2) cash in')  
option = int(input())  
if option == 1:  
power = power**2  
ready = True  
elif option == 2:  
if not ready:  
raise Exception('Nope, too weak')  
for i in range(player_count):  
if power[i] < len(quotes):  
print(f'You got an inspiration: {prizes[power[i]]}')  
exit()  
else:  
raise Exception('What?')  
```

\- The code creates the power as a numpy array of 32 bit signed integer type and then, the pump option lets us square the power array and the check is just if the power value is less than the length of quotes (positive)   
\- So one can cause integer overflow in power value to make it negative on squaring but there is one more catch that as the prizes has [flag]*24 we need to specifically make power in the range (-23 to -1) so that we bypass the check and acces the prizes array at an index where the flag is present which is one out of the last 24 cells, so we write a brute force script to get such a number.

## Solution

\- `[solve.py](http://solve.py)`  
```  
import numpy as np

start = 1000001  
end = 100000000  
max_iter = 10

lower_bound = -24  
upper_bound = -1

for i in range(start, end + 1):  
if i % 100000 == 0:  
print(f'{i = }')  
a = np.int32(i)  
ctr = 0  
while ctr < max_iter:  
a = a ** 2  
ctr += 1  
if int(a) > lower_bound and int(a) <= upper_bound:  
print(f"Found: i = {i}, iterations = {ctr}, value = {a}")  
break  
```  
\- This gives first valid solution as `34716455 1 -15`, and on using this as our input we get our flag.

```  
Welcome to our playground for powerful people where you can pump yourself up and get awesome prizes!

How many players participate?  
1  
Player 0, how strong are you right now?  
34716455  
What do you want to do?  
1) pump up  
2) cash in  
1  
What do you want to do?  
1) pump up  
2) cash in  
2  
You got an inspiration: ENO{d0_n0t_be_s0_neg4t1ve_wh3n_y0u_sh0uld_be_pos1t1ve}  
```

## Flag  
`ENO{d0_n0t_be_s0_neg4t1ve_wh3n_y0u_sh0uld_be_pos1t1ve}`
