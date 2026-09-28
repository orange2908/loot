---
title: "Back From Brazil - n00bzCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "back", "brazil", "n00bzctf", "n00bzctf-2024", "2024", "ctf-writeup"]
summary: "Given 10 different squares made up of 1000x1000 random numbers you need to input the optimal path from the upper left to the lower right corner consisting only of steps d - down or r - right."
source:
  name: "CTFtime writeup #39377"
  url: "https://ctftime.org/writeup/39377"
original_source: "https://moormaster.github.io/CtfWriteups/backfrombrazil.html"
ctf:
  name: "n00bzCTF 2024"
  year: 2024
  challenge: "Back From Brazil"
---

## Metadata

- **CTF:** n00bzCTF 2024
- **Task:** Back From Brazil
- **Author team:** zwiebel
- **CTFtime:** <https://ctftime.org/writeup/39377>
- **Original writeup:** <https://moormaster.github.io/CtfWriteups/backfrombrazil.html>

---
Given 10 different squares made up of 1000x1000 random numbers you need to input the optimal path from the upper left to the lower right corner consisting only of steps d - down or r - right. The sum of all the visited numbers must be maximal.

An approach using [dynamic programming](https://en.wikipedia.org/wiki/Dynamic_programming) can be used to find the optimal path through the square.

```
    import sys
    
    MAX_RUNS = 10
    DIMENSION = 1000
    
    # make recursion depth large enough so that width and length of the eggs-square fits in
    sys.setrecursionlimit(2*DIMENSION + sys.getrecursionlimit())
    
    def find_max_path(eggs, x, y, cached_result = None):
        if cached_result is None:
            cached_result = dict()
    
        if (x,y) in cached_result:
            return cached_result[(x,y)]
    
        right_result = None
        if x+1 < DIMENSION:
            right_result = find_max_path(eggs, x+1, y, cached_result)
    
        down_result = None
        if y+1 < DIMENSION:
            down_result = find_max_path(eggs, x, y+1, cached_result)
    
        if right_result is None and down_result is None:
            cached_result[(x,y)] = ('', eggs[y][x])
            return ('', eggs[y][x])
    
        if down_result is not None and (right_result is None or down_result[1] > right_result[1]):
            result = ('d' + down_result[0], eggs[y][x] + down_result[1])
            cached_result[(x,y)] = result
            return result
    
        if right_result is not None and (down_result is None or right_result[1] > down_result[1]):
            result = ('r' + right_result[0], eggs[y][x] + right_result[1])
            cached_result[(x,y)] = result
            return result
    
    f = open("backfrombrazil.log", "w")
    
    success = True
    
    # read first input for run
    received_reply = input()
    f.write("< " + received_reply + "\n")
    
    for run in range(MAX_RUNS):
        received_rows = []
        for i in range(DIMENSION):
            received_rows.append(received_reply)
    
            received_reply = input()
            f.write("< " + received_reply + "\n")
    
        eggs = []
        for received_row in received_rows:
            row = list(map(
                lambda s: int(s), 
                received_row.split(" ")[:-1]
            ))
            eggs.append(row)
    
        (path, sum_value) = find_max_path(eggs, 0, 0)
        print(path)
        f.write("> " + path + "\n")
    
        if "still in brazil" in received_reply or "didn't find" in received_reply or "out of time" in received_reply:
            success = False
            break
    
        # read first input for next run
        received_reply = input()
        f.write("< " + received_reply + "\n")
    
    if success:
        received_reply = input()
        print(received_reply, file=sys.stderr)
        f.write("< " + received_reply + "\n")
    
        received_reply = input()
        print(received_reply, file=sys.stderr)
        f.write("< " + received_reply + "\n")
    
    f.close()
```
