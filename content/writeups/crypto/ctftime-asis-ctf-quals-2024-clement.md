---
title: "Clement - ASIS CTF Quals 2024"
category: "crypto"
subcategory: "number-theory"
type: "writeup"
tags: ["crypto", "chinese-remainder", "clement", "number-theory", "asis-ctf-quals", "asis-ctf-quals-2024", "2024", "ctf-writeup"]
summary: "Clement - ASIS CTF Quals 2024"
source:
  name: "CTFtime writeup #39481"
  url: "https://ctftime.org/writeup/39481"
original_source: "https://sectt.github.io/writeups/ASIS24-quals/Clement/README"
ctf:
  name: "ASIS CTF Quals 2024"
  year: 2024
  challenge: "Clement"
---

## Metadata

- **CTF:** ASIS CTF Quals 2024
- **Task:** Clement
- **Author team:** STT
- **CTFtime:** <https://ctftime.org/writeup/39481>
- **Original writeup:** <https://sectt.github.io/writeups/ASIS24-quals/Clement/README>

---
Clement – ASIS CTF Quals 2024

## Given

```
    Welcome to Clement Crypto Challenge, we have gained access to a very powerful supercomputer with high processing capabilities. Try to connect to the app running on this computer and find the flag.
    
    nc 65.109.192.143 37771
    
    Nopte: For simplicity, we reduced the number of STEPS of this challenge.
```

## Source

[here](https://sectt.github.io/writeups/ASIS24-quals/Clement/source.py)

## TL;DR

  * We are presented with a server that uses the function `factoreal` to check for a condition in the user’s input. If the function returns **True** , we move onto the next level.

  * The condition is satisfied when our input `n` is such that `n+1` and `n+3` are both primes, requiring us to find **Twin Primes** with a certain number of bits.


## Code Analysis

The code initially asked for the user to pass 40 rounds in order to get the flag. However, that number of rounds implied finding twin primes with more than 5000 bits, which seemed unfeasible in the competition time. Therefore, the organizers changed the number of rounds to 19.

```
    def main():
    	global secret, border
    	border = "┃"
    	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    	pr(border, "Welcome to Clement Crypto Challenge, we have gained access to a   ", border)
    	pr(border, "very powerful supercomputer with high processing capabilities. Try", border)
    	pr(border, "to connect to the app running on this computer and find the flag. ", border)
    	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    	b, c, nbit, STEP = False, 0, 64, 40 #STEP = 19 after fix
    	for level in range(STEP):
    		pr(border, f"Your are at level {level + 1} of {STEP}")
    		pr(border, f"Please submit an {nbit}-integer:")
    		_n = sc().decode()
    		try:
    			_n = int(_n)
    			_k = _n**2 + 4*_n + 3
    		except:
    			die(border, 'Your input is not integer! Bye!!')
    		if _n.bit_length() == nbit:
    			try:
    				_b = factoreal(_n, _k, b)
    			except TimeoutError:
    				pass
    		else:
    			die(border, f"Your input integer is NOT {nbit}-bit! Bye!!") 
    		if _b:
    			c += 1
    			nbit = int(1.1 * nbit) + getRandomRange(1, 12)
    			if c >= STEP:
    				die(border, f'Congratulation! You got the flag: {flag}')
    		else:
    			die(border, "Wrong response! Start again. Bye!!") 
    
    if __name__ == '__main__':
    	main()
```

We see that in order to advance to the next round, `_b = factoreal(_n, _k, b)` must be **True**. Here, `_n` is the user’s input, which must be an `nbit`-integer, `b` is set to **False** and `_k = _n**2 + 4*_n + 3`.

Let’s then check out the function `factoreal`.

```
    TIMEOUT = 3
    @exec_limit(TIMEOUT)
    def factoreal(n, k, b):
    	if b: # When YOU have access to supercomputer!
    		i, s = 1, 1
    		while i < n + 1:
    			s = (s * i) % k
    			i += 1
    		if (4 * s + n + 5) % k == 0:
    			return True
    		return False
    	else: # Otherwise
    		return rapid_factoreal_check(n)
```

When “one has access to a supercomputer”, the function checks if `(4 * s + n + 5) % k == 0`, which when **True** is equivalent to \\(4 \cdot n! + n + 5 \equiv 0 \pmod k\\)

Assuming that `rapid_factoreal_check` performs the same check but in a more efficient way, we must find out which input will satisfy the condition above.

## Solution

We first note that `_k = _n**2 + 4*_n + 3`, and therefore the modulus of our equation is factorizable:

\\[k = n^2 + 4n +3 = (n+1)(n+3)\\] 

The name of the challenge, **Clement** , is itself a huge hint for this problem. In fact, there is a known mathematical result known as **Clement’s Theorem** , that states that \\(n + 2\\) and \\(n + 4\\) are both primes if and only if \\(4 \cdot [(n + 1)! + 1] + n + 2 \equiv 0 \pmod{(n + 2)(n + 4)}\\)

This condition seems oddly familiar. Setting \\(n’ = n+1\\), we get:

\\[4 \cdot n'! + n' + 5 \equiv 0 \pmod{(n' + 1)(n' + 3)}\\] 

Which is the exact condition of `factoreal`!

Although looking up the challenge name is becoming a good practice for CTF challenges, we did not immediately discover this result, but arrived to the same conclusion using other results.

Whenever one sees a factorial in a mathematicar equation, **Wilson’s Theorem** comes to mind. Let \\(p\\) be prime. This theorem states the following condition:

\\[(p-1)! \equiv -1 \pmod p\\] 

We also noted that, since we can factor the modulus \\(k\\) into 2 factors that differ by 2 (therefore coprime if \\(n\\) is even), the problem is equivalent to using the Chinese Remainder Theorem and solving the equations:

  * \\[4 \cdot n! + n + 5 \equiv 0 \pmod{(n + 1)}\\] 
  * \\[4 \cdot n! + n + 5 \equiv 0 \pmod{(n + 3)}\\] 


Combining these observations led us to think “What if \\(n+1\\) or \\(n+3\\)” are prime?”

Let’s consider each case:

  * \\(n+1\\) is prime


In this case, let \\(p = n+1\\). Let’s apply **Wilson’s Theorem** :

\\[4(p-1)! + (p-1) + 5 \equiv 4(p-1)! + 4 \equiv -4+4 \equiv 0 \pmod p\\] 

Therefore the condition is satisfied.

  * \\(n+3\\) is prime


Let \\(p = n+3\\). Let’s once again apply **Wilson’s Theorem** :

\\[4(p-3)! + (p-3) + 5 \equiv 4(p-3)! + 2 \pmod p\\] \\[\equiv 4*(p-1)!*(-2)^{-1}*(-1)^{-1}+2 \pmod p\\] \\[\equiv -4*(2)^{-1}+2=0 \pmod p\\] 

Therefore the condition would be true iff:

\\[-4*(2)^{-1} \equiv -2 \pmod p\\] 

and multiplying the equation by 2 on both sides yields the desired result.

Therefore, if \\(n+1\\) and \\(n+3\\) are both primes, the condition is always **True**.

Also note that \\(n+1\\) and \\(n+3\\) indeed had to be prime. If they were composite numbers, their prime factor decomposition would have only primes which are smaller than \\(n\\), and therefore the Chinese Remainder Theorem would render \\(n!\\) out of the equation, since it would lead to a system of equations of the form:

\\[4 \cdot n! + n + 5 \equiv 0 \pmod{p_i}\\] 

with \\(p_i < n\\). Therefore \\(n! \equiv 0 \pmod{p_i}\\) and all equations would become of the form

\\[n + 5 \equiv 0 \pmod{p_i}\\] 

which is only true when \\(p_i = 5\\). However, given the number of bits of our \\(n\\)’s, this condition would never suffice.

The challenge is then equivalent to, given a number of bits `nbits`, find an integer \\(n\\) such that \\(n+1\\) and \\(n+3\\) are **Twin Primes**.

This is a computationally challenging problem, and our solution was finding twin primes for each number of bits from 64 to the maximum number of bits required, storing them in a `json` file and then using them to pass the levels. We went to bed knowing the solution for every `nbit` possibility from 64 up to 1000 bits, which got us to level 25. When we woke up, we found that the number of levels had been decreased to 19 and got the flag.

## Conclusion

The solution script can be found [here](https://sectt.github.io/writeups/ASIS24-quals/Clement/exploit.py).

**Flag:`ASIS{gg_THeOR3M_0n_Tw!N_PrIm35!}`**
