---
title: "Web - Mission Control - Hackअस्त्र"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "bot", "stored", "xss", "foremost", "headless-browser", "hack", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #40818"
  url: "https://ctftime.org/writeup/40818"
original_source: "https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/mission-control-hack-2026"
ctf:
  name: "Hackअस्त्र"
  challenge: "Web - Mission Control"
---

## Metadata

- **CTF:** Hackअस्त्र
- **Task:** Web - Mission Control
- **Author team:** Team0Skills
- **CTFtime tags:** bot, stored, xss
- **CTFtime:** <https://ctftime.org/writeup/40818>
- **Original writeup:** <https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/mission-control-hack-2026>

---
For the complete documentation index, see [llms.txt](https://l1nuxkid.gitbook.io/l1nuxkid-docs/llms.txt). This page is also available as [Markdown](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/mission-control-hack-2026.md).

**Challenge:** Mission Control 

**Category:** Web 

**Event:** [HackAstra CTF 2026](https://ctftime.org/event/3270) on CTFtime 

**Target:** `https://mission-control.hackastra.tech/`

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FExDxkOAhP2gwd8rLO47M%252Fimage.png%3Falt%3Dmedia%26token%3Dec15c65c-a734-4e0c-8e8f-761e924e8d54&width=768&dpr=3&quality=100&sign=829dbed170a9b80432d8736264bdd5e3&sv=3)

### Overview

This is a **stored XSS → bot cookie theft** chain a real-world attack class commonly seen in bug bounties. The interesting twist here is not just the XSS, but the two-phase exploitation: your payload executes not in _your_ browser, but in the headless browser of an internal bot running on a network you can't reach directly. You have to make the bot come to you.

The vulnerability is a **sanitizer bypass via SVG** : the HTML sanitizer correctly strips dangerous attributes from normal HTML tags, but forgets to apply the same rules to SVG elements. The page's own trusted JavaScript then executes those attributes.

### Step 1 Recon: Reading the Page Source

First and foremost i tried doing HTML Injection

The site says "File a crew status report. All submissions are sanitized and archived under a shareable viewer link." That word _sanitized_ is the first clue if they're advertising it, there's a chance they got it wrong.

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FYRDioqV0DBRetXNRfYeF%252Fimage.png%3Falt%3Dmedia%26token%3D4da79dc2-0d37-4f26-b9ed-abce61c6ecec&width=768&dpr=3&quality=100&sign=144767f0f98a7c6937c21dd1a92839dc&sv=3)

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FdOFTagckmv57VDS04aTM%252Fimage.png%3Falt%3Dmedia%26token%3Da539b2fc-02ac-425d-a041-bca8b87d5aa7&width=768&dpr=3&quality=100&sign=c5710024f88fdd6d9b231aba683fce83&sv=3)

Report _**Bfl6AkGtgpEy**_

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252F5Mn0NtQf3El6QmmJ65wT%252Fimage.png%3Falt%3Dmedia%26token%3D8380bf70-b5b4-4570-835f-5773b55ba717&width=768&dpr=3&quality=100&sign=fb22e2dff625533043ad3e868b1061d8&sv=3)

Viewing the viewer page source reveals this critical inline script:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FR0BjctKoIJGXdhdbh0gO%252Fimage.png%3Falt%3Dmedia%26token%3D9ee65f25-dc13-4235-8902-2a3e0a97f0ff&width=768&dpr=3&quality=100&sign=04554461d8b20a554ed3c54310df51ef&sv=3)

This is an XSS sink hiding in plain sight. Any element on the page carrying a `data-hook` attribute has its value executed as JavaScript via `new Function(code)()`. The errors are silently swallowed, which also means it won't crash if an attempt fails.

The question becomes: can we get a `data-hook` attribute to survive sanitization?

First, I Confirmed basic HTML injection works:

### Step 2 Testing the Sanitizer

the sanitizer is allowlist-based and permits common formatting tags. Now test the obvious attack:

Blocked `<script>` is stripped. Standard sanitizer behavior. But what about `data-hook` on a regular HTML tag?

Also stripped. The sanitizer correctly removes `data-hook` from HTML elements. Now the key test what about SVG?

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FKycja9nGwZ2TRQfR35wm%252Fimage.png%3Falt%3Dmedia%26token%3D047421dc-5f0d-4bb8-9291-0f8e2a798153&width=768&dpr=3&quality=100&sign=f55864c5a11ed1abe96ac726b5745969&sv=3)

The alert fires on the viewer page. The sanitizer allows SVG (a legitimate use case for diagrams) but fails to apply the same attribute filtering rules to it. This is the bypass.

### Step 3 Understanding the Bot Architecture

At this point we have XSS but when we view our own report link in the browser, we're stealing _our own_ cookie. The flag lives in Hal-9's session cookie on the `app.void:8080` origin.

The page source contains a comment revealing the internal URL format:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FjtAFQiHdRbXDpeobaJXr%252Fimage.png%3Falt%3Dmedia%26token%3Db822c96c-b99c-4250-8947-843c054b5640&width=768&dpr=3&quality=100&sign=81d887c305451e99c27de32008d9bb44&sv=3)

The `/triage` endpoint accepts a URL and dispatches Hal-9 to fetch and render it. Crucially:

  * Submitting a public URL to `/triage` is **rejected** the bot only fetches internal URLs

  * The bot runs on the internal network and **can** reach `app.void:8080`

  * When Hal-9 renders the page, it executes our `data-hook` payload in its own browser context, with its own cookies


So the full plan is: submit a malicious report → get the `/view/XXXX` link → submit that as an internal `app.void:8080` URL to `/triage` → the bot executes our payload → our webhook receives the bot's cookie.

### Step 4 Setting Up the Webhook

We need a public HTTPS endpoint to receive the exfiltrated data. Use [webhook.site](https://webhook.site) to get a unique listener URL:

This returns a UUID your webhook ID. All incoming requests to `https://webhook.site/YOUR-UUID` will be logged and visible in the dashboard

### Step 5 Crafting the Exfiltration Payload

A simple `fetch` with `document.cookie` is enough, but we go broader grab cookies, `localStorage`, `sessionStorage`, and the current URL to understand the full bot context:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FfuCZJElifi8xyiAaEcqu%252Fimage.png%3Falt%3Dmedia%26token%3D9acf66c2-48f2-464b-bb1c-bf74e9367da0&width=768&dpr=3&quality=100&sign=6d803c9c91ce5349397ca48627702d8c&sv=3)

`mode: 'no-cors'` is important it lets the fetch fire even without CORS headers on the webhook server, at the cost of not being able to read the response (which we don't need).

The server responds with a redirect header:

That `PM9HbTSwAxCe` is your report ID. Keep it.

> **Important:** If you open this URL in your own browser now, _you_ will execute the payload and send your own cookie to the webhook. Don't do that or if you do, ignore that hit and wait for the bot's hit which will come from `app.void`.

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FVYyRCXNMfpU4xu6MZlyP%252Fimage.png%3Falt%3Dmedia%26token%3Dc05ddc94-a6fb-46e0-8509-69aa26f50128&width=768&dpr=3&quality=100&sign=cade25568c52bc5f43e55ca54531f3e9&sv=3)

### Step 7 Trigger Hal-9

Submit the internal viewer URL to the triage endpoint:

Hal-9 fetches the internal URL, renders the page, `runHooks()` fires, our `data-hook` payload executes in the bot's context, and the exfiltration fetch goes out to our webhook.

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252Fn23aqEnXUt9JHaUVpyB0%252Fimage.png%3Falt%3Dmedia%26token%3D5001241f-baeb-4093-b3ad-ce868eb07642&width=768&dpr=3&quality=100&sign=f32e3421a47958961524a2583327bb38&sv=3)

The `href` confirms it came from the bot (`app.void`) and not our own browser. Flag captured.

### Vulnerability Summary

Issue

Impact

`data-hook` stripped from HTML tags but not SVG

Sanitizer bypass attacker-controlled JS survives

`new Function(code)()` executes surviving attributes

Any `data-hook` value becomes arbitrary JS execution

Bot views user-submitted reports

Stored XSS runs in bot context, not attacker's

Flag stored in bot's session cookie

Full cookie theft via exfiltration fetch

`/triage` accepts internal `app.void` URLs

Attacker can direct bot to any stored report

* * *

#### Root Cause & Fix

The sanitizer has an **inconsistent allowlist** it applies attribute filtering rules differently to HTML and SVG elements. The simplest fix:

More broadly, never execute user-controlled content with `new Function`, `eval`, or `setTimeout(string)`. If hook functionality is needed, map hook names to predefined server-side functions rather than executing arbitrary attribute values:

* * *

#### Key Lessons for Beginners

Three things make this challenge click:

First, **always read the page source of the viewer, not just the submission form**. The `runHooks()` function was right there it was the sink that made everything else possible.

Second, **sanitizers often have blind spots for SVG and MathML**. These are XML namespaces that legitimate HTML sanitizers need to support, and they're frequently undertested. When `<script>` is blocked, always try the same payload inside `<svg>`.

Third, **stored XSS against bots is more powerful than reflected XSS against users**. The bot had privileged cookies that a normal user wouldn't have. The two-phase attack submit payload, then trigger the bot via a separate endpoint is a pattern worth remembering.

* * *

#### References

  * [PortSwigger Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)

  * [OWASP — XSS Filter Evasion via SVG](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

  * [DOMPurify bypass research](https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/) real-world examples of namespace-based sanitizer bypasses


[PreviousSWAG — Hackअस्त्र 2026](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/swag-hack-2026)[NextXSS in API via Content-Type Misconfiguration](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/xss-in-api-via-content-type-misconfiguration)

Last updated 3 months ago
