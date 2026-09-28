---
title: "[Very Easy] SealedRune - cyber apocalypse 2025"
category: "rev"
subcategory: "rev"
type: "writeup"
tags: ["rev", "base64", "easy", "sealedrune", "reverse-engineering", "very-easy-sealedrune"]
summary: "rev writeup for \"[Very Easy] SealedRune\" from cyber apocalypse - techniques: base64, easy, sealedrune, reverse-engineering, very-easy-sealedrune."
source:
  name: "hackthebox/cyber-apocalypse-2025"
  url: "https://github.com/hackthebox/cyber-apocalypse-2025/blob/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/reversing/%5BVery%20Easy%5D%20SealedRune/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2025
  challenge: "[Very Easy] SealedRune"
---

## Source

- **CTF:** cyber apocalypse 2025
- **Challenge:** [Very Easy] SealedRune
- **Repository:** [hackthebox/cyber-apocalypse-2025](https://github.com/hackthebox/cyber-apocalypse-2025)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2025/blob/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/reversing/%5BVery%20Easy%5D%20SealedRune/README.md>

---
<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2025/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/assets/banner.png" style="zoom: 80%;" align=center />

<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2025/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/assets/htb.png" style="zoom: 80%;" align='left' /><font size="5">SealedRune</font>

  6<sup>th</sup> 03 25

  Prepared By: clubby789

  Challenge Author: clubby789

  Difficulty: <font color=green>Very Easy</font>

  Classification: Official






# Synopsis

SealedRune is a Very Easy reverse engineering challenge. Players will identify base64 decoding in order to extract a password.

## Skills Required
    - Use of a decompiler
## Skills Learned
    - Knowledge of simple encoding techniques


# Solution

Running the binary gives us a prompt:

```
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⠀⠈⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⠀⠀⠘⠃⠀⢻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢠⡀⠀⢀⣤⣸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣷⣾⡷⠞⠛⠙⣛⣷⣤⣤⣄⡀⠀⠀⠀⠀⠀
       ⠀⠀⠀⠀⠀⢀⣤⣾⣿⣯⡁⠀⠀⠀⠀⠀⠀⠀⠀⣈⣿⣿⣦⣤⡀⠀⠀⠀⠀
       ⠀⠀⠀⢠⣾⡿⠛⠁⠀⠙⢿⡄⠀⠀⠀⠀⠀⠀⣸⡿⠋⠀⠙⠛⢿⣦⡀⠀⠀
       ⠀⠀⣴⡿⠁⠀⠀⠀⠀⠀⠈⣿⣶⣤⣀⣀⣤⣶⣿⠁⠀⠀⠀⠀⠀⠙⢿⣦⠀
       ⠀⣾⡟⠀⠀⠀⠀⠀⠀⠀⢰⡟⠉⠛⠿⠿⠛⠉⢻⡆⠀⠀⠀⠀⠀⠀⠘⣷  
       ⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠈⣧⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⠀⠀⠀⠀⠀⢹  
       ⠘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣇⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⣸⠇  
        ⠹⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⠀⠀⠀⢰⠇⠀⠀⠀⠀⠀⠀⣰⠏    
         ⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣄⠀⠀⣀⡾⠀⠀⠀⠀⠀⣠⠞⠁    
           ⠈⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠙⠓⠚⠋⠀⠀⠀⠀⣠⡾⠁      
              ⠙⠳⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡤⠖⠋        
                 ⠈⠛⠶⣤⣄⡀⠀⠀⢀⣠⡤⠖⠛⠁          
                     ⠉⠛⠛⠉
🔮 The ancient rune shimmers with magical energy... 🔮
Enter the incantation to reveal its secret:
```

## Analysis

We'll open the binary in a decompiler. Our input is checked in this function:

```c
  int64_t check_input(char* flag)

  char* rax_1 = decode_secret()
  
  if (strcmp(flag, rax_1) != 0)
      puts(str: "\x1b[1;31mThe rune rejects your words... Try again.\x1b[0m")
   else {
      puts(str: "\x1b[1;32mThe rune glows with power... The path to The Drago…")
      printf(format: "\x1b[1;33m%s\x1b[0m\n", &decode_flag()[1])
  }
  
  return free(mem: rax_1)
```

```c
  char* decode_secret()

  char* result = base64_decode("emFyZmZ1bkdsZWFW")
  reverse_str(result)
  return result
```

If we check `base64_decode`, we can see it's a basic base64 decoding implementation. `reverse_str` also simply reverses the bytes of a string in-place.

We'll extract the secret by performing these operations in Python.

```
>>> base64.b64decode("emFyZmZ1bkdsZWFW")[::-1]
```

This gives us the password `VaelGnuffraz`. If we run the binary and provide this input, we'll receive the flag.
