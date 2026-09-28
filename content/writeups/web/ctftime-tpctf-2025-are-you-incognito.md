---
title: "Are you incognito? - TPCTF 2025"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "dom-clobbering", "extension", "incognito", "xss", "tpctf", "tpctf-2025", "2025", "ctf-writeup"]
summary: "Notice that the bot runs Chromium but the extension uses browser instead of chrome to access the extension API."
source:
  name: "CTFtime writeup #40069"
  url: "https://ctftime.org/writeup/40069"
original_source: "https://ouuan.moe/post/2025/03/tpctf-2025#are-you-incognito-3-solves"
ctf:
  name: "TPCTF 2025"
  year: 2025
  challenge: "Are you incognito?"
---

## Metadata

- **CTF:** TPCTF 2025
- **Task:** Are you incognito?
- **Author team:** TP-Link
- **CTFtime tags:** web, dom-clobbering, extension
- **CTFtime:** <https://ctftime.org/writeup/40069>
- **Original writeup:** <https://ouuan.moe/post/2025/03/tpctf-2025#are-you-incognito-3-solves>

---
Notice that the bot runs Chromium but the extension uses `browser` instead of `chrome` to access the extension API. It uses `webextension-polyfill` to provide the API under `browser`. We can pass the check if we modify the `browser` object. We cannot directly create JavaScript variables since the web page and the content script run JavaScript separately, but we can use [DOM clobbering](https://domclob.xyz/) to do so.

We need `[browser.runtime.id](http://browser.runtime.id)` to pass [the check in `webextension-polyfill`](<https://github.com/mozilla/webextension-polyfill/blob/6a42cbeaf637ba3f1283bdcdd657afd06454ca55/src/browser-polyfill.js#L13>) and then `browser.extension.inIncognitoContext` to pass the check in the challenge:

```html  
<form id="browser" name="runtime"></form>  
<form id="browser" name="extension">  
<input name="inIncognitoContext">  
</form>  
```

An alternative solution is found by USTC-NEBULA, that is to create a global variable `exports` instead of `[browser.runtime.id](http://browser.runtime.id)` to pass [the check in `babel-transform-to-umd-module.js`](<https://github.com/mozilla/webextension-polyfill/blob/6a42cbeaf637ba3f1283bdcdd657afd06454ca55/scripts/babel-transform-to-umd-module.js#L7>).

Some sites such as webhook.site use path instead of subdomain for each user and are thus unable to record the `/flag` request. You can use [[requestrepo.com](http://requestrepo.com)](<https://requestrepo.com>) or your own server.

This appears to be a 0-day vulnerability, but I couldn’t find a practical way to exploit it in real-world extensions. I suspect it may at most disrupt the normal execution of content scripts without posing significant security risks or providing strong attack incentives. Anyhow, I will report this to the upstream after the competition. It’s at least a bug if not a vulnerability.

P.S. A similar bug was once discovered and fixed in [#153](<https://github.com/mozilla/webextension-polyfill/pull/153>) but later introduced again in [#582](<https://github.com/mozilla/webextension-polyfill/pull/582>).
