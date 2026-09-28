---
title: "Sudoku - Codefest CTF 2025"
category: "pwn"
type: "writeup"
tags: ["pwn", "sudoku", "codefest-ctf", "codefest-ctf-2025", "2025", "ctf-writeup"]
summary: "Just run this code and wait a little bit :)"
source:
  name: "CTFtime writeup #39838"
  url: "https://ctftime.org/writeup/39838"
ctf:
  name: "Codefest CTF 2025"
  year: 2025
  challenge: "Sudoku"
---

## Metadata

- **CTF:** Codefest CTF 2025
- **Task:** Sudoku
- **Author team:** DIONLABS
- **CTFtime:** <https://ctftime.org/writeup/39838>

---
### Solution  
Just run this code and wait a little bit :)

```python  
from pwn import *  
from sudoku import Sudoku  
import re

def remake(lines):  
newGrid = []  
for line in lines:  
newLine = []  
for symb in line:  
if symb != "_":  
newLine.append(int(symb))  
else:  
newLine.append(0)  
newGrid.append(newLine)  
return newGrid

def interact_with_server(host, port, num_puzzles=300):  
r = remote(host, port)

try:  
for puzzle_num in range(num_puzzles):  
print(f"doing sudoku #{puzzle_num + 1}/{num_puzzles}")  
if puzzle_num == 300:  
r.interactive()

# waiting for ">>"  
r.recvuntil(b">>")

# receive 9 lines of sudoku  
lines = []  
for _ in range(10):  
line = r.recvline().decode().strip()  
if "Codefest" in line:  
print(line)  
lines.append(re.split(r'\s+', line))  
  
del lines[0] # delete an empty line  
  
print("received sudoku:")  
for line in lines:  
print(" ".join(line))

grid = remake(lines)  
puzzle = Sudoku(3, 3, board=grid)

solved = puzzle.solve()  
solved_board = solved.board

if solved_board:  
print("\nsolution:")  
for row in solved_board:  
print(" ".join(map(str, row)))

solution_lines = [" ".join(map(str, row)).encode() for row in solved_board]  
r.sendline(b"\n".join(solution_lines))  
  
# if we solved all sudokus we need to switch to interactive mode to catch the flag from console  
if puzzle_num == num_puzzles:  
r.interactive()  
  
r.recvuntil(">> Input Answer:\n")  
response = r.recvline().decode().strip()  
print(response)  
else:  
print("failed to solve sudoku.")

except EOFError:  
print("an error occured.")

finally:  
r.close()

if __name__ == "__main__":  
host = "codefest-ctf.iitbhu.tech"   
port = 15397   
interact_with_server(host, port, num_puzzles=300)  
```
