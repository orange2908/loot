---
title: "Stone Game - The Cyber Jawara International 2024"
category: "crypto"
subcategory: "jwt"
type: "writeup"
tags: ["crypto", "xor", "jwt", "stone", "game", "the-cyber-jawara-international", "the-cyber-jawara-international-202", "2024", "ctf-writeup"]
summary: "Welcome to the Stone Game."
source:
  name: "CTFtime writeup #39610"
  url: "https://ctftime.org/writeup/39610"
original_source: "https://gist.github.com/jedifathan/8289b3e4798c0bf1c7f5c8cbff97829c"
ctf:
  name: "The Cyber Jawara International 2024"
  year: 2024
  challenge: "Stone Game"
---

## Metadata

- **CTF:** The Cyber Jawara International 2024
- **Task:** Stone Game
- **Author team:** dimas fans club
- **CTFtime:** <https://ctftime.org/writeup/39610>
- **Original writeup:** <https://gist.github.com/jedifathan/8289b3e4798c0bf1c7f5c8cbff97829c>

---
## Description

Welcome to the Stone Game. Take turns with the computer to pick stones from any set. Remove as many as you want, but the one who takes the last stone wins. Plan your moves carefully and try to outsmart the computer.

`nc 68.183.177.211 10001`

## Solution

Given a netcat service. When we try to open the service, we find the following challenge:

```
    jedi@aqua: /mnt/d/CTF/cj
    $ nc 68.183.177.211 10001                                                                                    
    Welcome to the Stone Game! Try to beat the computer.
    
    Rules:
    1. There are 7 sets of stones. Each set has a certain number of stones.
    2. On your turn, pick any set and remove 1 or more stones from it.
    3. You must take at least one stone, and you cannot take more than what is available.
    4. The player who takes the last stone wins!
    
    
    Stones:
    +---+---+---+---+---+---+---+
    | 3 | 4 | 5 | 2 | 6 | 3 | 5 |
    +---+---+---+---+---+---+---+
      1   2   3   4   5   6   7
    
    Your turn! Choose a set of stones (1-7):
```

As you can see, this challenge falls into a type of game called a nim game. Each person will take a stone from a set, and the last person to take a stone will be the winner. The solution to solving the nim game is to do the xor calculation on each set. If the xor result is 0, then we are in a losing position. And if the xor result is not 0, then we are in a winning position. We must put the opponent in a losing position by subtracting one of the sets with the xor calculation result, so that the xor result of all sets is 0 when it is the opponent's turn

However, when we look at the present condition, we find that 3 ⊕ 4 ⊕ 5 ⊕ 2 ⊕ 6 ⊕ 3 ⊕ 5 = 0

One solution to this problem is to not take a stone in the first round and let the computer take a stone. With this, we can be in a winning position.

```
    Stones:
    +---+---+---+---+---+---+---+
    | 3 | 4 | 5 | 2 | 6 | 3 | 5 |
    +---+---+---+---+---+---+---+
      1   2   3   4   5   6   7
    
    Your turn! Choose a set of stones (1-7): 1
    1
    How many stones to take from set 1? 0
    0
    
    Stones:
    +---+---+---+---+---+---+---+
    | 3 | 4 | 5 | 2 | 6 | 3 | 5 |
    +---+---+---+---+---+---+---+
      1   2   3   4   5   6   7
    Computer takes 1 stone(s) from set 1
    
    Stones:
    +---+---+---+---+---+---+---+
    | 2 | 4 | 5 | 2 | 6 | 3 | 5 |
    +---+---+---+---+---+---+---+
      1   2   3   4   5   6   7
    
    Your turn! Choose a set of stones (1-7):
```

We find that we can indeed not take any stones in the first round, so we can play in a winning position. The solver that I made is as follows :

```
    from pwn import *
    
    host = "68.183.177.211"
    port = 10001
    p = remote(host, port, level='debug')
    
    def parse_stone_sets(solve):
        lines = solve.splitlines()
        stone_line = next(line for line in lines if "|" in line)
        stones = [int(num.strip()) for num in stone_line.split("|")[1:-1]]
        return stones
    
    def calculate_nim_sum(stones):
        nim_sum = 0
        for stone in stones:
            nim_sum ^= stone
        return nim_sum
    
    def make_optimal_move(stones):
        nim_sum = calculate_nim_sum(stones)
        for i, stone in enumerate(stones):
            target = stone ^ nim_sum
            if target < stone:
                return i + 1, stone - target
        return 1, 1
    
    solve = p.recvuntil(b"Your turn! Choose a set of stones")
    
    p.sendline(b"1") 
    p.sendline(b"0")
    p.recvuntil(b"Computer takes")
    
    while True:
        solve = p.recvuntil(b"Your turn! Choose a set of stones", timeout=5)
        if b"CJ{" in solve:
            print(solve.decode())
            break
    
        stones = parse_stone_sets(solve.decode())
        set_index, stones_to_take = make_optimal_move(stones)
        
        p.sendline(str(set_index).encode())  
        p.recvuntil(b"How many stones to take from set")
        p.sendline(str(stones_to_take).encode()) 
    
        solve = p.recvuntil(b"Computer takes", timeout=5)
        if b"CJ{" in solve:
            print(solve.decode())
            break
    
    # Sorry for the broken solver, skill issue detected :(
```

With this code, we can get the flag

```
    [DEBUG] Received 0xc3 bytes:
        b'1\r\n'
        b'\r\n'
        b'Stones:\r\n'
        b'+---+---+---+---+---+---+---+\r\n'
        b'| 0 | 0 | 0 | 0 | 0 | 0 | 0 |\r\n'
        b'+---+---+---+---+---+---+---+\r\n'
        b'  1   2   3   4   5   6   7 \r\n'
        b'\r\n'
        b'Congratulations! You win.\r\n'
        b'CJ{why_I_allowed_zero_:(}\r\n'
        b'\r\n'
```

`Flag : CJ{why_I_allowed_zero_:(}`

NB : This question is similar to a challenge from ImaginaryCTF with title `nim trials 1`

[![image](https://private-user-images.githubusercontent.com/73788466/380577757-3b37b77a-70b4-4ab7-a72f-3f94186c6b9c.png?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3OTAzNDEyNzQsIm5iZiI6MTc5MDM0MDk3NCwicGF0aCI6Ii83Mzc4ODQ2Ni8zODA1Nzc3NTctM2IzN2I3N2EtNzBiNC00YWI3LWE3MmYtM2Y5NDE4NmM2YjljLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNjA5MjUlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjYwOTI1VDEyNTYxNFomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTQzYzY4OTY5YjRjYjYxNmViYmYwMTVmMWUwNTkxOTNjYmRhOGJjYjIzMmU5NmFjM2FkYzBhM2VmOTFhODg1NmQmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JnJlc3BvbnNlLWNvbnRlbnQtdHlwZT1pbWFnZSUyRnBuZyJ9.ADjnFK7n7luJWt-MhybnWMtTxJVtUq13qchyDJsMOBg)](https://private-user-images.githubusercontent.com/73788466/380577757-3b37b77a-70b4-4ab7-a72f-3f94186c6b9c.png?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3OTAzNDEyNzQsIm5iZiI6MTc5MDM0MDk3NCwicGF0aCI6Ii83Mzc4ODQ2Ni8zODA1Nzc3NTctM2IzN2I3N2EtNzBiNC00YWI3LWE3MmYtM2Y5NDE4NmM2YjljLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNjA5MjUlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjYwOTI1VDEyNTYxNFomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTQzYzY4OTY5YjRjYjYxNmViYmYwMTVmMWUwNTkxOTNjYmRhOGJjYjIzMmU5NmFjM2FkYzBhM2VmOTFhODg1NmQmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JnJlc3BvbnNlLWNvbnRlbnQtdHlwZT1pbWFnZSUyRnBuZyJ9.ADjnFK7n7luJWt-MhybnWMtTxJVtUq13qchyDJsMOBg)
