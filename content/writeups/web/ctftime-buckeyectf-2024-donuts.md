---
title: "donuts - BuckeyeCTF 2024"
category: "web"
type: "writeup"
tags: ["web", "donuts", "buckeyectf", "buckeyectf-2024", "2024", "ctf-writeup"]
summary: "I don't like Jessica and she has donuts on her two pegs (1 and 2)."
source:
  name: "CTFtime writeup #39488"
  url: "https://ctftime.org/writeup/39488"
original_source: "https://github.com/Execut3/CTF/tree/master/Writeups/2024/BuckeyeCTF/donut"
ctf:
  name: "BuckeyeCTF 2024"
  year: 2024
  challenge: "donuts"
---

## Metadata

- **CTF:** BuckeyeCTF 2024
- **Task:** donuts
- **Author team:** Execut3
- **CTFtime:** <https://ctftime.org/writeup/39488>
- **Original writeup:** <https://github.com/Execut3/CTF/tree/master/Writeups/2024/BuckeyeCTF/donut>

---
## donut [100 pts]

**Category:** Web  
**Solves:** 109

## Description  
I don't like Jessica and she has donuts on her two pegs (1 and 2). Can you move all those donuts onto my third peg please??

I don't like Jessica and she has donuts on her two pegs (1 and 2). Can you move all those donuts onto my third peg please??

### Solution

Checking the connection we'll see:  
```bash  
$ nc [challs.pwnoh.io](http://challs.pwnoh.io) 13434  
|  
-|-  
|  
\----|----  
|

|  
|  
\---|---  
|  
\-----|-----  
|  
\------|------  
|  
\-------|-------  
|  
\---------|---------  
|

|  
|  
\--|--  
|  
\--------|--------  
|  
\----------|----------  
|

Enter the stack number you would like to move a donut from (1, 2 or 3):  
1  
Enter the stack number you would like to move this donut to (1, 2 or 3):  
2

```

It seem there are three stacks each containing some donuts. that we can move any upper donut from one stack to anothers.

It's hanoi towers problem with N items.  
I used quite a time to solve it. most of the current implementation of it is for 3 items, but found this repo working find for 10 items:

<https://github.com/daturkel/pynoi>

And did some twists one it.

The final payload is in `[source.py](http://source.py)` file.  
It tries to get the data received from server, convert it to format of   
`[[1,2], [3, 4, 5], [6, 9, 10, 7, 8]]`  
and feed in the function to calculate steps to solve the hanoi in this format  
`[source, destinaion]` for example `[1, 2]` means move topest item from stack1 to stack2.

and running it after almost 1000 iterations got me the flag:  
```bash  
$ python [solve.py](http://solve.py)

Connected to server [challs.pwnoh.io](http://challs.pwnoh.io) on port 13434  
|  
\--|--  
|  
\---|---  
|  
\-------|-------  
|  
\---------|---------  
|  
\----------|----------  
|

|  
|  
-|-  
|  
\----|----  
|  
\------|------  
|  
\--------|--------  
|

|  
|  
\-----|-----  
|

Enter the stack number you would like to move a donut from (1, 2 or 3):

972\. (1,2): [[6, 3, 2], [5, 4, 1], [10, 9, 8, 7]]  
973\. (1,3): [[6, 3], [5, 4, 1], [10, 9, 8, 7, 2]]  
974\. (2,3): [[6, 3], [5, 4], [10, 9, 8, 7, 2, 1]]  
975\. (1,2): [[6], [5, 4, 3], [10, 9, 8, 7, 2, 1]]  
976\. (3,1): [[6, 1], [5, 4, 3], [10, 9, 8, 7, 2]]  
977\. (3,2): [[6, 1], [5, 4, 3, 2], [10, 9, 8, 7]]  
978\. (1,2): [[6], [5, 4, 3, 2, 1], [10, 9, 8, 7]]  
979\. (1,3): [[], [5, 4, 3, 2, 1], [10, 9, 8, 7, 6]]  
980\. (2,3): [[], [5, 4, 3, 2], [10, 9, 8, 7, 6, 1]]  
981\. (2,1): [[2], [5, 4, 3], [10, 9, 8, 7, 6, 1]]  
982\. (3,1): [[2, 1], [5, 4, 3], [10, 9, 8, 7, 6]]  
983\. (2,3): [[2, 1], [5, 4], [10, 9, 8, 7, 6, 3]]  
984\. (1,2): [[2], [5, 4, 1], [10, 9, 8, 7, 6, 3]]  
985\. (1,3): [[], [5, 4, 1], [10, 9, 8, 7, 6, 3, 2]]  
986\. (2,3): [[], [5, 4], [10, 9, 8, 7, 6, 3, 2, 1]]  
987\. (2,1): [[4], [5], [10, 9, 8, 7, 6, 3, 2, 1]]  
988\. (3,1): [[4, 1], [5], [10, 9, 8, 7, 6, 3, 2]]  
989\. (3,2): [[4, 1], [5, 2], [10, 9, 8, 7, 6, 3]]  
990\. (1,2): [[4], [5, 2, 1], [10, 9, 8, 7, 6, 3]]  
991\. (3,1): [[4, 3], [5, 2, 1], [10, 9, 8, 7, 6]]  
992\. (2,3): [[4, 3], [5, 2], [10, 9, 8, 7, 6, 1]]  
993\. (2,1): [[4, 3, 2], [5], [10, 9, 8, 7, 6, 1]]  
994\. (3,1): [[4, 3, 2, 1], [5], [10, 9, 8, 7, 6]]  
995\. (2,3): [[4, 3, 2, 1], [], [10, 9, 8, 7, 6, 5]]  
996\. (1,2): [[4, 3, 2], [1], [10, 9, 8, 7, 6, 5]]  
997\. (1,3): [[4, 3], [1], [10, 9, 8, 7, 6, 5, 2]]  
998\. (2,3): [[4, 3], [], [10, 9, 8, 7, 6, 5, 2, 1]]  
999\. (1,2): [[4], [3], [10, 9, 8, 7, 6, 5, 2, 1]]  
1000\. (3,1): [[4, 1], [3], [10, 9, 8, 7, 6, 5, 2]]  
1001\. (3,2): [[4, 1], [3, 2], [10, 9, 8, 7, 6, 5]]  
1002\. (1,2): [[4], [3, 2, 1], [10, 9, 8, 7, 6, 5]]  
1003\. (1,3): [[], [3, 2, 1], [10, 9, 8, 7, 6, 5, 4]]  
1004\. (2,3): [[], [3, 2], [10, 9, 8, 7, 6, 5, 4, 1]]  
1005\. (2,1): [[2], [3], [10, 9, 8, 7, 6, 5, 4, 1]]  
1006\. (3,1): [[2, 1], [3], [10, 9, 8, 7, 6, 5, 4]]  
1007\. (2,3): [[2, 1], [], [10, 9, 8, 7, 6, 5, 4, 3]]  
1008\. (1,2): [[2], [1], [10, 9, 8, 7, 6, 5, 4, 3]]  
1009\. (1,3): [[], [1], [10, 9, 8, 7, 6, 5, 4, 3, 2]]  
1010\. (2,3): [[], [], [10, 9, 8, 7, 6, 5, 4, 3, 2, 1]]  
solved in 1010 steps

Final state of stacks:  
Stack A: []  
Stack B: []  
Stack C: [10, 9, 8, 7, 6, 5, 4, 3, 2, 1]  
index 1  
[2, 3]  
b'Enter the stack number you would like to move this donut to (1, 2 or 3):\n'  
b' |\n\n |\n |\n --|--\n |\n ---|---\n |\n -------|-------\n |\n\n |\n |\n -|-\n |\n ----|----\n |\n -----|-----\n |\n ------|------\n |\n --------|--------\n |\n ---------|---------\n |\n ----------|----------\n |\n\nEnter the stack number you would like to move a donut from (1, 2 or 3):\n'  
index 2  
[3, 1]  
b'Enter the stack number you would like to move this donut to (1, 2 or 3):\n'  
b' |\n -|-\n |\n\n |\n |\n --|--\n |\n ---|---\n |\n -------|-------\n |\n\n |\n |\n ----|----\n |\n -----|-----\n |\n ------|------\n |\n --------|--------\n |\n ---------|---------\n |\n ----------|----------\n |\n\nEnter the stack number you would like to move a donut from (1, 2 or 3):\n'  
index 3  
[1, 2]  
b'Enter the stack number you would like to move this donut to (1, 2 or 3):\n'  
b' |\n\n |\n |\n -|-\n |\n --|--\n |\n ---|---\n |\n -------|-------\n |\n\n |\n |\n ----|----\n |\n -----|-----\n |\n ------|------\n |\n --------|--------\n |\n ---------|---------\n |\n ----------|----------\n |\n\nEnter the stack number you would like to move a donut from (1, 2 or 3):\n'

```

And finaly the flag will apear.

[solve.py](http://solve.py):  
```python  
import socket

def parse_stacks(representation):  
"""  
Parse the visual representation of stacks and return a list of stacks.  
  
representation: A string representation of the stacks.  
"""  
stacks = []  
lines = representation.strip().split('\n')

# Determine the number of stacks by counting columns  
num_stacks = 3

# Initialize stacks  
for _ in range(num_stacks):  
stacks.append([])

# Iterate through lines from bottom to top  
stack_index = 0  
for line in lines:  
if not '-' in line:  
if not '|' in line:  
stack_index += 1  
continue   
value = int(line.count('-')/2)  
stacks[stack_index].insert(0, value)

return stacks

FINAL_STEPS = []

class TowersOfHanoi:  
initial_posts = []

def __init__(self,n,verbose=True, posts=None):  
self.n = n  
self.verbose = verbose  
self._step_count = None  
self.initial_posts = [[i for i in range(self.n,0,-1)],[],[]] if not posts else posts  
self.reset()  
  
def __str__(self):  
return str(self.posts)  
  
def __repr__(self):  
return f'TowersOfHanoi: {str(self.posts)}'  
  
## Private method; returns a `posts` array in initial state  
def _reset_posts(self):  
return self.initial_posts.copy()  
  
## Public method to reset the puzzle to its initial state  
def reset(self):  
self.posts = self._reset_posts()  
  
## Public method to move the top piece from post a to post b  
## Posts are 1-indexed (1,2,3)  
def move(self,a,b,verbose=None):  
verbose = verbose if verbose is not None else self.verbose  
# check to see if initial post has any discs  
if len(self.posts[a-1]) == 0:  
print(f'Post {a} has no discs to move.')  
return False  
else:  
pass  
# check to see if move would place a larger disc on top of a smaller one  
if len(self.posts[b-1]) > 0 and (self.posts[a-1][-1] > self.posts[b-1][-1]):  
print(f'Disc {self.posts[a-1][-1]} cannot be moved on top of disc {self.posts[b-1][-1]}.')  
return False  
else:  
pass  
# execute the move  
self.posts[b-1].append(self.posts[a-1].pop())  
self._step_count = self._step_count + 1 if self._step_count is not None else None  
if verbose:  
FINAL_STEPS.append([a, b])  
if self._step_count is not None:  
print(f'{self._step_count}. ({a},{b}): {self}')  
else:  
print(f'({a},{b}): {self}')  
return True  
  
## Private method; move a stack of two pieces from post a to post b  
def _two_move(self,a,b,verbose=None):  
verbose = verbose if verbose is not None else self.verbose  
c = 6-a-b  
self.move(a,c,verbose)  
self.move(a,b,verbose)  
self.move(c,b,verbose)  
  
## Private method; recursively move a stack of n pieces from post a to post b  
def _n_move(self,n,a,b,verbose=None):  
verbose = verbose if verbose is not None else self.verbose  
c = 6-a-b  
if n == 1:  
self.move(a,b,verbose)  
elif n == 2:  
self._two_move(a,b,verbose)  
elif n > 2:  
self._n_move(n-1,a,c,verbose)  
self._n_move(1,a,b,verbose)  
self._n_move(n-1,c,b,verbose)

## Public method; (reset and) solve the puzzle, moving all discs from post 1 to post 3  
def solve(self,verbose=None):  
self.reset()  
verbose = verbose if verbose is not None else self.verbose  
self._step_count = 0  
  
self._n_move(self.n,1,3,verbose=verbose)  
if not verbose:  
print(self)  
print(f'solved in {self._step_count} steps')  
  
self._step_count = None

# Create a socket connection   
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
host = "[challs.pwnoh.io](http://challs.pwnoh.io)"  
port = 13434  
s.connect((host, port))  
print(f"Connected to server {host} on port {port}")

data = s.recv(1024).decode('utf-8')

print(data) # Print the received data  
stacks = parse_stacks(data)  
puz = TowersOfHanoi(10, posts=stacks)  
print(puz)  
puz.solve()

# Output the final state of the stacks  
print("\nFinal state of stacks:")  
print("Stack A:", stacks[0])  
print("Stack B:", stacks[1])  
print("Stack C:", stacks[2])

index = 0  
for step in FINAL_STEPS:  
index += 1  
print('index', index)  
print(step)  
s.send(f'{step[0]}\n'.encode())  
print(s.recv(1024))   
s.send(f'{step[1]}\n'.encode())  
print(s.recv(2048))  
# # Check for the prompt asking for stack number  
# if "Enter the stack number you would like to move a donut from (1, 2 or 3):" in data:  
# # Parse the input for the stack number  
# stack_number = input("Enter your choice (1, 2 or 3): ")  
  
# # Send the chosen stack number to the server  
# s.sendall(stack_number.encode('utf-8'))

```
