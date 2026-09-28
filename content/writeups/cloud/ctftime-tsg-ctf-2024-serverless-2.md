---
title: "serverless - TSG CTF 2024"
category: "cloud"
type: "writeup"
tags: ["cloud", "regex", "serverless", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "We extract all the regex rules from the compose.yaml and divide them into two parts: ones are expanding the length, and the others are reducing."
source:
  name: "CTFtime writeup #39705"
  url: "https://ctftime.org/writeup/39705"
original_source: "https://yasarli.com/posts/tsg-ctf-2024-reverse-writeup/"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "serverless"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** serverless
- **Author team:** blue-lotus
- **CTFtime tags:** regex
- **CTFtime:** <https://ctftime.org/writeup/39705>
- **Original writeup:** <https://yasarli.com/posts/tsg-ctf-2024-reverse-writeup/>

---
We extract all the regex rules from the `compose.yaml` and divide them into two parts: ones are expanding the length, and the others are reducing.

Focus on the reducing part first.

```python  
[  
(r"^(.*)M\\(m\\).*", r"^(.*)M\\(m\\)", r"\1"),  
(r"^(.*)H\\(h\\).*", r"^(.*)H\\(h\\)", r"\1"),  
(r"^(.*)Y\\(y\\).*", r"^(.*)Y\\(y\\)", r"\1"),  
(r"^(.*)C\\(c\\).*", r"^(.*)C\\(c\\)", r"\1"),  
(r"^(.*)A\\(a\\).*", r"^(.*)A\\(a\\)", r"\1"),  
(r"^(.*)J\\(j\\).*", r"^(.*)J\\(j\\)", r"\1"),  
(r"^(.*)D\\(d\\).*", r"^(.*)D\\(d\\)", r"\1"),  
(r"^(.*)F\\(f\\).*", r"^(.*)F\\(f\\)", r"\1"),  
(r"^(.*)G\\(g\\).*", r"^(.*)G\\(g\\)", r"\1"),  
(r"^(.*)K\\(k\\).*", r"^(.*)K\\(k\\)", r"\1"),  
(r"^(.*)T\\(t\\).*", r"^(.*)T\\(t\\)", r"\1"),  
(r"^(.*)X\\(x\\).*", r"^(.*)X\\(x\\)", r"\1"),  
(r"^(.*)R\\(r\\).*", r"^(.*)R\\(r\\)", r"\1"),  
(r"^(.*)P\\(p\\).*", r"^(.*)P\\(p\\)", r"\1"),  
(r"^(.*)U\\(u\\).*", r"^(.*)U\\(u\\)", r"\1"),  
(r"^(.*)L\\(l\\).*", r"^(.*)L\\(l\\)", r"\1"),  
(r"^(.*)V\\(v\\).*", r"^(.*)V\\(v\\)", r"\1"),  
(r"^(.*)O\\(o\\).*", r"^(.*)O\\(o\\)", r"\1"),  
(r"^(.*)B\\(b\\).*", r"^(.*)B\\(b\\)", r"\1"),  
(r"^(.*)Q\\(q\\).*", r"^(.*)Q\\(q\\)", r"\1"),  
(r"^(.*)N\\(n\\).*", r"^(.*)N\\(n\\)", r"\1"),  
(r"^(.*)E\\(e\\).*", r"^(.*)E\\(e\\)", r"\1"),  
(r"^(.*)W\\(w\\).*", r"^(.*)W\\(w\\)", r"\1"),  
(r"^(.*)I\\(i\\).*", r"^(.*)I\\(i\\)", r"\1"),  
(r"^(.*)Z\\(z\\).*", r"^(.*)Z\\(z\\)", r"\1"),  
(r"^(.*)S\\(s\\).*", r"^(.*)S\\(s\\)", r"\1"),  
]  
```

It is easy to find that the rules are removing an uppercase letter with a corresponding lowercase letter. We know the flag starts with `TSGCTF`. If we want to remove all the characters, we need to construct `(f)(t)(c)(g)(s)(t)` within `{}`.

Pay attention to the expanding part next.

```python  
[  
(r"^(.*)/eq.*", r"^(.*)/eq", r"\1(w)(s)(p)/"),  
(r"^(.*)/6i.*", r"^(.*)/6i", r"\1(s)(y)(n)RZK/"),  
(r"^(.*)/g7.*", r"^(.*)/g7", r"\1(q)(k)(s)MFF/"),  
(r"^(.*)/9g.*", r"^(.*)/9g", r"\1(e)(f)(z)EFT/"),  
...,  
(r"^(.*)/n.*", r"^(.*)/n", r"\1(v)(g)(h)PRZ/"),  
(r"^(.*)%7D%7B.*", r"^(.*)%7D%7B", r"\1+"),  
(r"^(.*)%7D.*", r"^(.*)%7D", r"\1)"),  
(r"^(.*)%7B.*", r"^(.*)%7B", r"\1(/"),  
(r"^(.*)_.*", r"^(.*)_", r"\1)(/"),  
(r"^(.*)/\\).*", r"^(.*)/\\)", r"\1)"),  
]  
```

It can be noticed that an underscore `_` will be replaced by `)(`, which creates a new group. If we want to create 6 groups, we need to contain 5 underscores with in `{}`. The regex rules will generate a `/` right after the `{`, using it to replate the pattern one by one from left to right.

The pattern rules can be divided into three categories:

1\. Replace a pattern to `(a)(b)(c)DEF`.  
2\. Replace a pattern to `(a)(b)(c)`, which is the end of a group.  
3\. Replace a pattern to `aDEF`, which is the start of a group.

We can build a graph to represent the rules and use BFS to find the path.

```python  
rules = [  
(r"^(.*)/eq.*", r"^(.*)/eq", r"\1(w)(s)(p)/"),  
(r"^(.*)/6i.*", r"^(.*)/6i", r"\1(s)(y)(n)RZK/"),  
(r"^(.*)/g7.*", r"^(.*)/g7", r"\1(q)(k)(s)MFF/"),  
(r"^(.*)/9g.*", r"^(.*)/9g", r"\1(e)(f)(z)EFT/"),  
...,  
(r"^(.*)/n.*", r"^(.*)/n", r"\1(v)(g)(h)PRZ/"),  
]

import re

edges = []  
for i in range(26 * 26 * 26 + 26):  
edges.append([])

def get_num(node):  
if len(node) == 9:  
return ((ord(node[7]) - 97) * 26 + (ord(node[4]) - 97)) * 26 + (  
ord(node[1]) - 97  
)  
if len(node) == 3:  
return ((ord(node[0]) - 65) * 26 + (ord(node[1]) - 65)) * 26 + (  
ord(node[2]) - 65  
)  
if len(node) == 1:  
return ord(node) - 97 + 26 * 26 * 26

for rule in rules:  
if re.match(r"\\\1(\\([a-z]\\)){3}[A-Z]{3}", rule[2]):  
m = re.match(r"\\\1((\\([a-z]\\)){3})([A-Z]{3})", rule[2])  
fr = m.group(1)  
to = m.group(3)  
edges[get_num(fr)].append((get_num(to), rule[0][6:-2]))  
elif re.match(r"\\\1[a-z]([A-Z]{3})", rule[2]):  
m = re.match(r"\\\1([a-z])([A-Z]{3})", rule[2])  
fr = m.group(1)  
to = m.group(2)  
edges[get_num(fr)].append((get_num(to), rule[0][6:-2]))  
elif re.match(r"\\\1(\\([a-z]\\)){3}", rule[2]):  
m = re.match(r"\\\1((\\([a-z]\\)){3})", rule[2])  
fr = m.group(1)  
edges[get_num(fr)].append((-1, rule[0][6:-2]))

flag = ""  
for st in "ftcgst":  
qu = []  
vis = [False] * (26 * 26 * 26 + 26)  
qu.append((get_num(st), ""))  
vis[get_num(st)] = True  
while len(qu) > 0:  
u, path = qu.pop(0)  
if u == -1:  
flag += path + "_"  
break  
for v, p in edges[u]:  
if not vis[v]:  
vis[v] = True  
qu.append((v, path + p))  
print("TSGCTF{" + flag[:-1].replace("\\\", "") + "}")  
# TSGCTF{http-red1rect5-can_funct10n_as-tur1ng-c0mp1ete_m4rk0v-a1g0rithm_proce55ing_funct10n}  
```
