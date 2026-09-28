---
title: "Debugging Client-Side JavaScript (HackTricks)"
category: "web"
subcategory: "xss-cross-site-scripting"
type: "reference"
tags: ["hacktricks", "web", "xss", "debugging", "client-side", "javascript", "xss-cross-site-scripting", "cross", "site", "scripting", "debugging-client-side-js", "client", "side"]
summary: "Client-side JavaScript debugging can become repetitive when navigation or parameter changes reload the page and invalidate temporary debugging state."
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xss-cross-site-scripting/debugging-client-side-js.md"
license: "CC BY-NC 4.0"
---

# Debugging Client-Side JavaScript


Client-side JavaScript debugging can become repetitive when navigation or parameter changes reload the page and invalidate temporary debugging state.

## `debugger;`

When developer tools are open, a `debugger;` statement pauses execution at that point unless breakpoints are disabled. Adding the statement to a persistent local copy is one way to keep the pause point across reloads.<sup>[[1]](#references)</sup>

## Overrides

Chrome DevTools Local Overrides stores a local replacement for a network resource and serves that replacement on subsequent page loads.<sup>[[2]](#references)</sup>

1. Open **DevTools > Sources > Overrides**.
2. Select an empty local folder and allow DevTools to access it.
3. In the **Page** tree, right-click the target script and select **Override content** or **Save for overrides**, depending on the Chrome version.
4. Add `debugger;`, save the file, and reload the page.

![Selecting a JavaScript file in the Sources panel and saving it as a local override](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/images/image%20(742).png)

The saved local copy now replaces the matching network resource while overrides are enabled. Changes therefore persist across reloads, but they affect only your local browser profile.<sup>[[2]](#references)</sup>

![A locally overridden JavaScript file containing a debugger statement](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/images/image%20(594).png)

The XSS challenge walkthrough in reference 3 demonstrates this `debugger;` and Local Overrides workflow during a practical client-side analysis.<sup>[[3]](#references)</sup>

## References

- [1] [Chrome for Developers - JavaScript debugging reference](https://developer.chrome.com/docs/devtools/javascript/reference)
- [2] [Chrome for Developers - Override web content and HTTP response headers locally](https://developer.chrome.com/docs/devtools/overrides/)
- [3] [YouTube - 4 hackers, one XSS challenge](https://www.youtube.com/watch?v=BW_-RCo9lo8&t=1529s)

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/pentesting-web/xss-cross-site-scripting/debugging-client-side-js.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.
