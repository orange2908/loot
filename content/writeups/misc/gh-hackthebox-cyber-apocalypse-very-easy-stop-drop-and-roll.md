---
title: "[Very Easy] Stop Drop and Roll - cyber apocalypse 2024"
category: "misc"
subcategory: "rop"
type: "writeup"
tags: ["misc", "rop", "pwntools", "easy", "stop", "drop", "roll"]
summary: "misc writeup for \"[Very Easy] Stop Drop and Roll\" from cyber apocalypse - techniques: rop, pwntools, easy, stop, drop, roll."
source:
  name: "hackthebox/cyber-apocalypse-2024"
  url: "https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/misc/%5BVery%20Easy%5D%20Stop%20Drop%20and%20Roll/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2024
  challenge: "[Very Easy] Stop Drop and Roll"
---

## Source

- **CTF:** cyber apocalypse 2024
- **Challenge:** [Very Easy] Stop Drop and Roll
- **Repository:** [hackthebox/cyber-apocalypse-2024](https://github.com/hackthebox/cyber-apocalypse-2024)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/misc/%5BVery%20Easy%5D%20Stop%20Drop%20and%20Roll/README.md>

---
![](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/banner.png)

<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/htb.png" style="margin-left: 20px; zoom: 60%;" align=left />        <font size="10">Stop Drop and Roll</font>

​	8<sup>th</sup> March 2024

​	Challenge Author: ir0nstone





# Synopsis

Stop Drop and Roll is a Very Easy misc coding challenge where the remote server sends you scenarios and you must script a response to them.

## Description

The Fray: The Video Game is one of the greatest hits of the last... well, we don't remember quite how long. Our "computers" these days can't run much more than that, and it has a tendency to get repetitive...

## Skills Required
 - Basic programming skills

## Skills Learned
 - Scripting remote connections

# Enumeration

Connecting to the server gives us this prompt:

```
$ nc localhost 1337
===== THE FRAY: THE VIDEO GAME =====
Welcome!
This video game is very simple
You are a competitor in The Fray, running the GAUNTLET
I will give you one of three scenarios: GORGE, PHREAK or FIRE
You have to tell me if I need to STOP, DROP or ROLL
If I tell you there's a GORGE, you send back STOP
If I tell you there's a PHREAK, you send back DROP
If I tell you there's a FIRE, you send back ROLL
Sometimes, I will send back more than one! Like this: 
GORGE, FIRE, PHREAK
In this case, you need to send back STOP-ROLL-DROP!
Are you ready? (y/n) 
```

The instructions are pretty clear - we have to take in a list of `GORGE`, `PHREAK` and `FIRE` prompts and return the instructions `STOP`, `DROP` or `ROLL` depending on the prompt.

# Solution

We will script this challenge using pwntools. First start a connection:

```python
from pwn import *

p = remote('<IP>', <PORT>)
```

Then we want to send `y` to start the game and receive the response.

```python
p.sendlineafter(b'(y/n) ', b'y')
p.recvline()
```

Now we'll start an infinite loop, taking in a line of input. We then want to replace every `, ` with `-`, every `GORGE` with `STOP`, every `PHREAK` with `DROP` and every `FIRE` with `ROLL`. After this, we send it back.

If the line we receive has no `GORGE`, `PHREAK` or `FIRE`, it's probably returned the flag to us, so we just print out the line and quit the loop.

```python
while True:
    recv = p.recvlineS().strip()

    if 'GORGE' not in recv and 'PHREAK' not in recv and 'FIRE' not in recv:
        print(recv)
        break

    result = recv.replace(", ", "-")
    result = result.replace("GORGE", "STOP")
    result = result.replace("PHREAK", "DROP")
    result = result.replace("FIRE", "ROLL")

    p.sendlineafter(b'do? ', result.encode())
```

Running this against the server, we get the flag!
