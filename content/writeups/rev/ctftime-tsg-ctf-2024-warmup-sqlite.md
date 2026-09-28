---
title: "Warmup SQLite - TSG CTF 2024"
category: "rev"
type: "writeup"
tags: ["rev", "bytecode", "sqlite3", "sqlite", "warmup", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "Firstly, we need to decompile the bytecode of SQLite."
source:
  name: "CTFtime writeup #39707"
  url: "https://ctftime.org/writeup/39707"
original_source: "https://yasarli.com/posts/tsg-ctf-2024-reverse-writeup/"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "Warmup SQLite"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** Warmup SQLite
- **Author team:** blue-lotus
- **CTFtime tags:** bytecode, sqlite3
- **CTFtime:** <https://ctftime.org/writeup/39707>
- **Original writeup:** <https://yasarli.com/posts/tsg-ctf-2024-reverse-writeup/>

---
Firstly, we need to decompile the bytecode of SQLite. According to this [site](<https://www.sqlite.org/opcode.html>), we can get the meaning of each command.

```plaintext  
| id | opcode | p1 | p2 | p3 | p4 | p5 | Comment |  
| --- | ------------- | --- | --- | --- | ----------------------------- | --- | -------------------------- |  
| 0 | Init | 0 | 88 | 0 | | 0 | start = 88 |  
| 1 | InitCoroutine | 1 | 68 | 2 | | 0 | |  
| 2 | OpenPseudo | 1 | 2 | 3 | | 0 | c1 = PseudoLine(v2, 3) |  
| 3 | OpenEphemeral | 4 | 3 | 0 | | 0 | c4 = TempTable(3) |  
| 4 | InitCoroutine | 3 | 34 | 5 | | 0 | |  
| 5 | OpenPseudo | 3 | 4 | 3 | | 0 | c3 = PseudoLine(v4, 3) |  
| 6 | OpenEphemeral | 5 | 3 | 0 | | 0 | c5 = TempTable(3) |  
| 7 | String8 | 0 | 5 | 0 | | 0 | v5 = "" |  
| 8 | String8 | 0 | 6 | 0 | ~~Your input is filled here~~ | 0 | v6 = flag |  
| 9 | Integer | -1 | 7 | 0 | | 0 | v7 = -1 |  
| 10 | MakeRecord | 5 | 3 | 8 | | 0 | v8 = Record(v5, 3) |  
| 11 | NewRowid | 5 | 9 | 0 | | 0 | v9 = NewRowID(c5) |  
| 12 | Insert | 5 | 8 | 9 | | 8 | Insert(c5, v8, v9) |  
| 13 | Rewind | 5 | 33 | 0 | | 0 | If c5 is empty jump to 33 |  
| 14 | NullRow | 3 | 0 | 0 | | 0 | c3 = null |  
| 15 | RowData | 5 | 4 | 0 | | 0 | v4 = Row(c5) |  
| 16 | Delete | 5 | 0 | 0 | | 0 | Delete(c5) |  
| 17 | Column | 3 | 0 | 10 | | 0 | v10 = c3[0] |  
| 18 | Column | 3 | 1 | 11 | | 0 | v11 = c3[1] |  
| 19 | Column | 3 | 2 | 12 | | 0 | v12 = c3[2] |  
| 20 | Yield | 3 | 0 | 0 | | 0 | |  
| 21 | Column | 3 | 1 | 8 | | 0 | v8 = c3[1] |  
| 22 | Eq | 13 | 32 | 8 | BINARY-8 | 80 | jumpto 32 if v8 == v13 |  
| 23 | Column | 3 | 1 | 14 | | 0 | v14 = c3[1] |  
| 24 | Function | 6 | 14 | 5 | substr(3) | 0 | v5 = substr(v14, v15, v16) |  
| 25 | Column | 3 | 1 | 17 | | 0 | v17 = c3[1] |  
| 26 | Function | 2 | 17 | 6 | substr(2) | 0 | v6 = substr(v17, v18) |  
| 27 | Column | 3 | 2 | 8 | | 0 | v8 = c3[2] |  
| 28 | Add | 19 | 8 | 7 | | 0 | v7 = v8 + v19 |  
| 29 | MakeRecord | 5 | 3 | 8 | | 0 | v8 = Record(v5, 3) |  
| 30 | NewRowid | 5 | 9 | 0 | | 0 | v9 = NewRowID(c5) |  
| 31 | Insert | 5 | 8 | 9 | | 8 | Insert(c5, v8, v9) |  
| 32 | Goto | 0 | 13 | 0 | | 0 | |  
| 33 | EndCoroutine | 3 | 0 | 0 | | 0 | |

| id | opcode | p1 | p2 | p3 | p4 | p5 | Comment |  
| --- | ------------- | --- | --- | --- | ---------- | --- | ------------------------- |  
| 34 | InitCoroutine | 3 | 0 | 5 | | 0 | |  
| 35 | Yield | 3 | 46 | 0 | | 0 | |  
| 36 | Copy | 10 | 20 | 0 | | 2 | v20 = v10 |  
| 37 | Eq | 13 | 45 | 20 | BINARY-8 | 80 | jump to 45 if v20 == v13 |  
| 38 | Copy | 10 | 20 | 0 | | 2 | |  
| 39 | Function | 0 | 20 | 21 | unicode(1) | 0 | v21 = unicode(v20) |  
| 40 | Copy | 12 | 22 | 0 | | 2 | v22 = v12 |  
| 41 | Integer | 0 | 23 | 0 | | 0 | v23 = 0 |  
| 42 | MakeRecord | 21 | 3 | 20 | | 0 | v20 = Record(v21, 3) |  
| 43 | NewRowid | 4 | 24 | 0 | | 0 | v24 = NewRowID(c4) |  
| 44 | Insert | 4 | 20 | 24 | | 8 | Insert(c4, v20, v24) |  
| 45 | Goto | 0 | 35 | 0 | | 0 | |  
| 46 | Rewind | 4 | 67 | 0 | | 0 | If c4 is empty jump to 67 |  
| 47 | NullRow | 1 | 0 | 0 | | 0 | c1 = Null |  
| 48 | RowData | 4 | 2 | 0 | | 0 | v2 = Row(c4) |  
| 49 | Delete | 4 | 0 | 0 | | 0 | |  
| 50 | Column | 1 | 0 | 25 | | 0 | v25 = c1[0] |  
| 51 | Column | 1 | 1 | 26 | | 0 | v26 = c1[1] |  
| 52 | Column | 1 | 2 | 27 | | 0 | v27 = c1[2] |  
| 53 | Yield | 1 | 0 | 0 | | 0 | |  
| 54 | Column | 1 | 2 | 20 | | 0 | v20 = c1[2] |  
| 55 | Ge | 28 | 66 | 20 | BINARY-8 | 80 | jump to 66 if v20 >= v28 |  
| 56 | Column | 1 | 0 | 29 | | 0 | v29 = c1[0] |  
| 57 | Multiply | 30 | 29 | 24 | | 0 | v24 = v29 * v30 |  
| 58 | Add | 31 | 24 | 20 | | 0 | v20 = v24 + v31 |  
| 59 | Remainder | 32 | 20 | 21 | | 0 | v21 = v20 % v32 |  
| 60 | Column | 1 | 1 | 22 | | 0 | v22 = c1[1] |  
| 61 | Column | 1 | 2 | 20 | | 0 | v20 = c1[2] |  
| 62 | Add | 19 | 20 | 23 | | 0 | v23 = v20 + v19 |  
| 63 | MakeRecord | 21 | 3 | 20 | | 0 | |  
| 64 | NewRowid | 4 | 24 | 0 | | 0 | |  
| 65 | Insert | 4 | 20 | 24 | | 8 | |  
| 66 | Goto | 0 | 46 | 0 | | 0 | |  
| 67 | EndCoroutine | 1 | 0 | 0 | | 0 | |

| id | opcode | p1 | p2 | p3 | p4 | p5 | Comment |  
| --- | ------------- | --- | --- | --- | -------- | --- | ------------------------ |  
| 68 | SorterOpen | 6 | 5 | 0 | k(1,B) | 0 | c6 = table(5) |  
| 69 | InitCoroutine | 1 | 0 | 2 | | 0 | |  
| 70 | Yield | 1 | 79 | 0 | | 0 | |  
| 71 | Copy | 27 | 33 | 0 | | 2 | v33 = v27 |  
| 72 | Ne | 28 | 78 | 33 | BINARY-8 | 80 | jump to 78 if v28 != v33 |  
| 73 | Copy | 25 | 35 | 0 | | 2 | v35 = v25 |  
| 74 | Copy | 27 | 36 | 0 | | 2 | v36 = v27 |  
| 75 | Copy | 26 | 34 | 0 | | 2 | v34 = v26 |  
| 76 | MakeRecord | 34 | 3 | 38 | | 0 | v38 = Record(v34, 3) |  
| 77 | SorterInsert | 6 | 38 | 34 | 3 | 0 | Insert(c6, v38, v34, 3) |  
| 78 | Goto | 0 | 70 | 0 | | 0 | |  
| 79 | OpenPseudo | 7 | 39 | 5 | | 0 | |  
| 80 | SorterSort | 6 | 87 | 0 | | 0 | |  
| 81 | SorterData | 6 | 39 | 7 | | 0 | |  
| 82 | Column | 7 | 2 | 37 | | 0 | v37 = c7[2] |  
| 83 | Column | 7 | 0 | 36 | | 0 | v36 = c7[0] |  
| 84 | Column | 7 | 1 | 35 | | 0 | v35 = c7[1] |  
| 85 | ResultRow | 35 | 3 | 0 | | 0 | |  
| 86 | SorterNext | 6 | 81 | 0 | | 0 | |  
| 87 | Halt | 0 | 0 | 0 | | 0 | |  
| 88 | String8 | 0 | 13 | 0 | | 0 | v13 = "" |  
| 89 | Integer | 1 | 15 | 0 | | 0 | v15 = 1 |  
| 90 | Integer | 1 | 16 | 0 | | 0 | v16 = 1 |  
| 91 | Integer | 2 | 18 | 0 | | 0 | v18 = 2 |  
| 92 | Integer | 1 | 19 | 0 | | 0 | v19 = 1 |  
| 93 | Integer | 10 | 28 | 0 | | 0 | v28 = 10 |  
| 94 | Integer | 7 | 30 | 0 | | 0 | v30 = 7 |  
| 95 | Integer | 2 | 31 | 0 | | 0 | v31 = 2 |  
| 96 | Integer | 256 | 32 | 0 | | 0 | v32 = 256 |  
| 97 | Goto | 0 | 1 | 0 | | 0 | |  
```

By analyzing the bytecode, it just splits the flag into characters, transforms them into unicode, and modifies each value $x$ to $(7x + 2) \bmod 256$.

```python  
flag_enc = [100, 115, 39, 99, 100, 54, 27, 115, 69, 220, 69, 99, 100, 191, 56, 161, 131, 11, 101, 162, 191, 54, 130, 175, 205, 191, 222, 101, 162, 116, 147, 191, 55, 24, 69, 130, 69, 191, 252, 101, 102, 101, 252, 189, 82, 116, 41, 147, 161, 147, 132, 101, 162, 82, 191, 220, 9, 205, 9, 100, 191, 38, 68, 253]

from sympy import mod_inverse

for i in range(len(flag_enc)):  
for j in range(10):  
flag_enc[i] = ((flag_enc[i] - 2) % 256) * mod_inverse(7, 256) % 256

print("".join([chr(x) for x in flag_enc]))  
# TSGCTF{SELECT_hacker_FROM_nerds_WHERE_level="disaster"_LIMIT_64}  
```
