---
title: "All coding challenges - Cyber Apocalypse CTF 2025: Tales from Eldoria"
category: "crypto"
subcategory: "xss"
type: "writeup"
tags: ["crypto", "coding", "xss", "eval", "challenges", "cyber-apocalypse-ctf-2025-tale", "cyber-apocalypse-ctf-2025-tales-fr", "2025", "ctf-writeup"]
summary: "All the coding challenges (clockworkguardian, dragonflight, dragonfury, enchantedcipher, summonersincantation) in the given URL, I will post here the final code:"
source:
  name: "CTFtime writeup #40117"
  url: "https://ctftime.org/writeup/40117"
original_source: "https://github.com/PwnOfPower/HTB_cyberapocalypse_2025/tree/main/coding"
ctf:
  name: "Cyber Apocalypse CTF 2025: Tales from Eldoria"
  year: 2025
  challenge: "All coding challenges"
---

## Metadata

- **CTF:** Cyber Apocalypse CTF 2025: Tales from Eldoria
- **Task:** All coding challenges
- **Author team:** PwnOfPower
- **CTFtime tags:** coding
- **CTFtime:** <https://ctftime.org/writeup/40117>
- **Original writeup:** <https://github.com/PwnOfPower/HTB_cyberapocalypse_2025/tree/main/coding>

---
All the coding challenges (`clockwork_guardian`, `dragon_flight`, `dragon_fury`, `enchanted_cipher`, `summoners_incantation`) in the given URL, I will post here the final code:

## Clockwork Guardian

```python  
from collections import deque  
import ast

def shortest_safe_path(grid):  
rows, cols = len(grid), len(grid[0])  
directions = [(0,1), (1,0), (0,-1), (-1,0)] # Right, Down, Left, Up

# Find the exit position  
exit_pos = None  
for r in range(rows):  
for c in range(cols):  
if grid[r][c] == 'E':  
exit_pos = (r, c)  
grid[r][c] = 0 # Treat 'E' as a walkable path

if not exit_pos:  
return -1 # No exit found

# BFS Initialization  
queue = deque([(0, 0, 0)]) # (row, col, steps)  
visited = set()  
visited.add((0, 0))

while queue:  
r, c, steps = queue.popleft()

# If we reach the exit, return the shortest path length  
if (r, c) == exit_pos:  
return steps

# Explore neighbors  
for dr, dc in directions:  
nr, nc = r + dr, c + dc

if 0 <= nr < rows and 0 <= nc < cols and (nr, nc) not in visited:  
if grid[nr][nc] == 0: # Only move to open paths  
queue.append((nr, nc, steps + 1))  
visited.add((nr, nc))

return -1 # No path found

# Read input dynamically (input the grid as a list of lists)  
grid_input = input("Enter the grid (as a list of lists): ")

# Convert the input string into a list of lists  
grid = ast.literal_eval(grid_input)

# Run the function and print the shortest path  
print(shortest_safe_path(grid))  
```

## Dragon Flight  
```python  
# Read input lines into variables.  
input1 = input() # e.g., "5 3" (number of segments and operations)  
input2 = input() # e.g., "10 -2 3 -1 5" (initial wind effects)

# Parse inputs  
N, Q = map(int, input1.split()) # Number of segments (N) and operations (Q)  
arr = list(map(int, input2.split())) # Initial wind effects

# Read Q lines of operations dynamically  
queries = [input().strip() for _ in range(Q)]

class SegmentTree:  
class Node:  
def __init__(self, value):  
self.total = value  
self.best_prefix = value  
self.best_suffix = value  
self.best_sum = value

def __init__(self, arr):  
self.n = len(arr)  
self.tree = [None] * (4 * self.n)  
self.build(arr, 0, 0, self.n - 1)

def build(self, arr, node, start, end):  
if start == end:  
self.tree[node] = self.Node(arr[start])  
else:  
mid = (start + end) // 2  
left_child = 2 * node + 1  
right_child = 2 * node + 2  
self.build(arr, left_child, start, mid)  
self.build(arr, right_child, mid + 1, end)  
self.tree[node] = self.merge(self.tree[left_child], self.tree[right_child])

def merge(self, left, right):  
merged = self.Node(0)  
merged.total = left.total + right.total  
merged.best_prefix = max(left.best_prefix, left.total + right.best_prefix)  
merged.best_suffix = max(right.best_suffix, right.total + left.best_suffix)  
merged.best_sum = max(left.best_suffix + right.best_prefix, left.best_sum, right.best_sum)  
return merged

def update(self, index, value, node=0, start=0, end=None):  
if end is None:  
end = self.n - 1

if start == end:  
self.tree[node] = self.Node(value)  
else:  
mid = (start + end) // 2  
left_child = 2 * node + 1  
right_child = 2 * node + 2  
if index <= mid:  
self.update(index, value, left_child, start, mid)  
else:  
self.update(index, value, right_child, mid + 1, end)  
self.tree[node] = self.merge(self.tree[left_child], self.tree[right_child])

def query(self, l, r, node=0, start=0, end=None):  
if end is None:  
end = self.n - 1

if r < start or l > end:  
return self.Node(float('-inf')) # Nodo nulo para combinaciones  
if l <= start and end <= r:  
return self.tree[node]

mid = (start + end) // 2  
left_child = 2 * node + 1  
right_child = 2 * node + 2  
left_result = self.query(l, r, left_child, start, mid)  
right_result = self.query(l, r, right_child, mid + 1, end)  
return self.merge(left_result, right_result)

# Construct segment tree  
seg_tree = SegmentTree(arr)

# Process operations dynamically  
outputs = []  
for query in queries:  
parts = query.split()  
if parts[0] == 'U':  
i, x = int(parts[1]) - 1, int(parts[2])  
seg_tree.update(i, x)  
elif parts[0] == 'Q':  
l, r = int(parts[1]) - 1, int(parts[2]) - 1  
result = seg_tree.query(l, r)  
outputs.append(str(result.best_sum))

# Print all query results  
print("\n".join(outputs))  
```

## Dragon Fury

```python  
from itertools import product  
from typing import List

# Input the text as a single string  
input_list = input() # Example: "shock;979;23"  
input_int = input()

# Write your solution below and make sure to encode the word correctly  
damage_values = eval(input_list)  
damage = int(input_int)

def quest(xss, x):  
for combination in product(*xss): # generate all possible combinations  
if sum(combination) == x:  
return list(combination) # return the first valid combination

print(quest(damage_values, damage))  
```

## Enchanted Cipher

```python  
import math

# Input the text as a single string  
input_text = input()  
input_shift_groups = input()  
input_shift_values = input()

# Write your solution below and make sure to encode the word correctly  
shift_values = eval(input_shift_values)

def quest(text, values):  
spaces = 0  
result = ""  
for i in range(len(input_text)):  
if input_text[i] == ' ': # ignore whitespaces  
spaces += 1  
result += ' '  
continue  
shift_index = math.floor((i-spaces)/5) # calculate shift value index  
newchar = chr((ord(input_text[i]) - shift_values[shift_index] - ord('a')) % 26 + ord('a')) # decode character  
result += newchar  
return result

print(quest(input_text, shift_values))

```

## Summoners Incantation

```python  
# Input the text as a single string  
input_text = input() # Example: "shock;979;23"

# Write your solution below and make sure to encode the word correctly  
def quest(input_text):  
input_list = eval(input_text)

if len(input_list) == 0:  
return 0  
if len(input_list) == 1:  
return nums[0]

include = 0 # max sum including the current element  
exclude = 0 # max sum excluding the current element

for token in input_list:  
new_include = exclude + token  
exclude = max(include, exclude)  
include = new_include

return max(include, exclude)

print(quest(input_text))  
```
