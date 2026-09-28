---
title: "GISSNINGSLEK - Hack.lu CTF 2025"
category: "misc"
subcategory: "prng"
type: "writeup"
tags: ["misc", "prng", "gissningslek", "hack-lu-ctf", "hack-lu-ctf-2025", "2025", "ctf-writeup"]
summary: "A bash script that asks you to guess a random number correctly 1000 times in a row."
source:
  name: "CTFtime writeup #40492"
  url: "https://ctftime.org/writeup/40492"
ctf:
  name: "Hack.lu CTF 2025"
  year: 2025
  challenge: "GISSNINGSLEK"
---

## Metadata

- **CTF:** Hack.lu CTF 2025
- **Task:** GISSNINGSLEK
- **Author team:** Cyclopropenylidene
- **CTFtime tags:** misc
- **CTFtime:** <https://ctftime.org/writeup/40492>

---
# [Hack.lu](http://Hack.lu) CTF 2025 GISSNINGSLEK Writeup (Misc)

writeup: **fridgebuyer**

## Challenge Description  
A bash script that asks you to guess a random number correctly 1000 times in a row.  
You only get to provide ONE guess, which seems mathematically impossible.

## The Vulnerability

### Vulnerable Code  
```bash  
read -r user_guess

function guess() {  
rand=$(( ( RANDOM % 10000 ) + 1337 ))  
if [[ "${1}" -eq "${rand}" ]]; # ← BUG HERE  
then  
echo "Rätta"  
else  
echo "Fel"  
exit 1  
fi  
}

for _ in {1..1000}; do  
guess "${user_guess}"  
done

/readflag  
```

### The Bug  
The comparison uses `-eq` (arithmetic equality operator) instead of `==` (string comparison).

In bash arithmetic context with `-eq`:  
\- Both sides are evaluated as arithmetic expressions  
\- Bare variable names (without $) are treated as variable references  
\- The string "rand" gets evaluated as the variable `rand`

### How It Works

1\. User inputs: `rand`  
2\. Each iteration:  
\- Line 9 sets: `rand=5432` (example random value)  
\- Line 10 compares: `[[ "rand" -eq "5432" ]]`  
\- In arithmetic context: `rand` → references variable `rand` → `5432`  
\- Comparison becomes: `5432 -eq 5432` → TRUE

3\. This works for all 1000 iterations because `rand` always evaluates to the current value of the `rand` variable.

### Why 1000 Iterations?

Protection against brute forcing:  
\- Random range: 1337-11336 (10,000 possibilities)  
\- You only provide ONE guess (read once at the start)  
\- That guess must match 1000 DIFFERENT random numbers  
\- Probability without exploit: (1/10000)^1000 = impossible  
\- With exploit: All iterations pass regardless of count

## Exploitation

### Steps  
1\. Connect to service:  
```bash  
nc gissningslek.solven.jetzt 1024  
```

2\. When prompted for guess, enter:  
```  
rand  
```

3\. All 1000 comparisons succeed, script executes `/readflag`

## Flag

Rätta  
Rätta  
Rätta  
Rätta  
Rätta  
Rätta  
Rätta  
**flag{it5_y0ur_lucky_d4y_h3h3_04217a096}**
