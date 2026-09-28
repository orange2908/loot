---
title: "Without a Trace - UIUCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "without", "trace", "uiuctf", "uiuctf-2024", "2024", "ctf-writeup"]
summary: "I removed all the unnecessary code and got left with this."
source:
  name: "CTFtime writeup #39291"
  url: "https://ctftime.org/writeup/39291"
ctf:
  name: "UIUCTF 2024"
  year: 2024
  challenge: "Without a Trace"
---

## Metadata

- **CTF:** UIUCTF 2024
- **Task:** Without a Trace
- **Author team:** 1c3Gh3tt0
- **CTFtime tags:** crypto
- **CTFtime:** <https://ctftime.org/writeup/39291>

---
I removed all the unnecessary code and got left with this. I also removed the input and initialiazed the diagonal all with ones. From the full code, we could see that what the code was doing was that it turns the flag into 5 parts each 5 characters long, and after that saving each part in a list in its long bytes representation. Then it would turn that new list into a matrix. At the end, it would multiply the M matrix with the new F matrix. We would end up with a matrix that in it's diagonal, each element has the long bytes of each part of the flag. The program woud print out the sum of the diagonal: 2000128101369. 

The easiest way to find what each part was, would be instead of 1 in every element, we'd put only one 1. The program doesn't let us add any 0 on the diagonal but it does let us add -1. By adding -1 to one of the elements, we would have removed that element twice. for example, if we give u1 -1, then the sum of he diagonal would be: 991567152401. If we remove that from the sum of all bytes (2000128101369 - 991567152401) we'd be left basically with sum - (2 * u1) = 1008560948968. If we devide this by 2, it will give us the bytes of the first 5 characters of the flag. 1008560948968 / 2 = 504,280,474,484 , long_to_bytes(504280474484) = b'uiuct'. Do that for the rest and we will find the full flag: 

```  
u1 = uiuct  
u2 =f{tr4  
u3 = c1ng_  
u4 = &&_mu  
u5 = lt5!}

flag = uiuctf{tr4c1ng_&&_mult5!}

\----------------------------------------------------------------

import numpy as np  
from Crypto.Util.number import bytes_to_long

def fun(M):  
f = [bytes_to_long(bytes("uiuct f{man what ever} asder"[5*i:5*(i+1)], 'utf-8')) for i in range(5)]  
F = [  
[0, 0, 0, 0, 0],  
[0, 0, 0, 0, 0],  
[0, 0, 0, 0, 0],  
[0, 0, 0, 0, 0],  
[0, 0, 0, 0, 0],  
]  
for i in range(5):  
F[i][i] = f[i]

R = np.matmul(F, M)  
print(f)  
return np.trace(R)

def main():  
print("[WAT] Welcome")  
M = [  
[1, 0, 0, 0, 0],  
[0, 1, 0, 0, 0],  
[0, 0, 1, 0, 0],  
[0, 0, 0, 1, 0],  
[0, 0, 0, 0, 1],  
]

res = fun(M)  
print(f"[WAT] Have fun: {res}")

if __name__ == "__main__":  
main()  
```
