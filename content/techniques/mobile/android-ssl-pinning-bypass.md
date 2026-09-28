---
title: "Android SSL Pinning Bypass - Every Technique That Works"
category: mobile
subcategory: network
type: technique
tags: [ssl-pinning, certificate-pinning, frida, objection, okhttp3, trustmanager, conscrypt, network-security-config, xposed, lsposed, justtrustme, burp, mitmproxy, flutter, boringssl, apktool]
difficulty: medium
summary: "Defeat certificate pinning at runtime (Frida/objection/Xposed) or statically (network-security-config patch, cert swap), including Flutter/BoringSSL apps."
when_to_use:
  - "Burp shows a TLS handshake failure or the app shows 'network error' only when proxied"
  - "You found okhttp3.CertificatePinner, TrustKit or a pinned cert in res/raw"
  - "Traffic works on Android 6 but breaks on Android 7+"
tools: [frida, objection, apktool, apksigner, burp, mitmproxy, magisk]
related: [mobile-traffic-interception, android-frida-basics, android-smali-patching, android-root-detection-bypass]
---

## TL;DR

Pinning means the app rejects your CA even when the OS trusts it. Four ways out, in
order of cost: (1) Frida universal script, (2) `objection android sslpinning disable`,
(3) rebuild the APK with a permissive `network_security_config.xml`, (4) swap the pinned
certificate/hash for yours. Flutter apps pin inside BoringSSL and ignore the system
proxy - they need a native hook, not a Java one.

## Recognise it

- Proxy set correctly, CA installed, and you still get
  `javax.net.ssl.SSLHandshakeException: Trust anchor for certification path not found`.
- jadx hits on `CertificatePinner`, `okhttp3.CertificatePinner$Builder.add`,
  `TrustManagerFactory`, `checkServerTrusted`, `TrustKit`, `sha256/`.
- `res/xml/network_security_config.xml` with a `<pin-set>` block.
- `.crt` / `.cer` / `.bks` / `.p12` in `res/raw/` or `assets/`.
- `WebViewClient.onReceivedSslError` overridden with a `handler.cancel()`.
- Absolutely no Java pinning found, app is Flutter (`libflutter.so` present),
  and traffic never even reaches the proxy -> Dart does not honour the WiFi proxy.

## Theory

The TLS trust decision happens in one of these layers, and you must hook the one in use:

| Layer | Class / symbol | Typical library |
|---|---|---|
| App-level pin check | `okhttp3.CertificatePinner.check` | OkHttp / Retrofit |
| Hostname verify | `okhttp3.internal.tls.OkHostnameVerifier.verify` | OkHttp |
| Custom TrustManager | `X509TrustManager.checkServerTrusted` | anything |
| SSLContext seeding | `javax.net.ssl.SSLContext.init` | anything |
| Platform trust | `com.android.org.conscrypt.Platform.checkServerTrusted` | Android 7+ default |
| TrustKit | `com.datatheorem.android.trustkit.pinning.OkHostnameVerifier` | TrustKit |
| WebView | `WebViewClient.onReceivedSslError` | WebView |
| Native (Dart/Go/C++) | `SSL_CTX_set_custom_verify` / `ssl_crypto_x509_session_verify_cert_chain` | BoringSSL |

Also remember the **Android 7 (API 24) change**: apps targeting 24+ no longer trust the
user CA store by default. That is not pinning, it is the default
`network_security_config`. Fixing it may be all you need - see `mobile-traffic-interception`.

## Attack

1. Confirm it is pinning and not just the API-24 user-CA default
   (test with an app that targets < 24, or read the manifest's `targetSdkVersion`).
2. Try `objection` first - one command, no script.
3. If that fails, run the universal Frida script (covers OkHttp, TrustManager, Conscrypt,
   WebView, TrustKit).
4. If the app is Flutter/Go/native, hook BoringSSL by pattern or export.
5. If you cannot run Frida (no root, gadget blocked), patch statically:
   network-security-config + re-sign.
6. If a specific cert is pinned by SHA-256, compute your proxy CA's pin and just replace
   the string in `strings.xml` / `res/raw`.

## Code

### 1. objection (fastest)

```bash
# patch nothing, just disable pinning at runtime
objection -g com.ctf.app explore -s "android sslpinning disable"

# non-rooted: repackage the app with frida-gadget embedded, then run the same command
objection patchapk -s app.apk
adb install -r app.objection.apk
```

### 2. Universal Frida pinning bypass

```js
// pinning-bypass.js - disable every common Android pinning mechanism
// run: frida -U -f com.ctf.app -l pinning-bypass.js --no-pause
'use strict';

Java.perform(function () {

  // ---- 1. install a permissive TrustManager into every SSLContext -------------
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var SSLContext = Java.use('javax.net.ssl.SSLContext');

  var TrustAll = Java.registerClass({
    name: 'com.ctf.TrustAll',
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function (chain, authType) {},
      checkServerTrusted: function (chain, authType) {},
      getAcceptedIssuers: function () { return []; }
    }
  });

  var init = SSLContext.init.overload(
    '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
  init.implementation = function (km, tm, sr) {
    console.log('[pin] SSLContext.init -> injecting TrustAll');
    init.call(this, km, [TrustAll.$new()], sr);
  };

  // ---- 2. okhttp3 CertificatePinner -------------------------------------------
  try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
      .implementation = function (host, peers) {
        console.log('[pin] okhttp3 CertificatePinner.check(' + host + ') bypassed');
      };
    if (CertificatePinner['check$okhttp']) {
      CertificatePinner['check$okhttp'].implementation = function (host, fn) {
        console.log('[pin] okhttp3 check$okhttp(' + host + ') bypassed');
      };
    }
  } catch (e) { console.log('[pin] no okhttp3 CertificatePinner'); }

  // ---- 3. okhttp hostname verifier ---------------------------------------------
  try {
    var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
    OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
      .implementation = function (host, session) {
        console.log('[pin] OkHostnameVerifier.verify(' + host + ') -> true');
        return true;
      };
  } catch (e) { console.log('[pin] no OkHostnameVerifier'); }

  // ---- 4. Conscrypt / platform trust manager -----------------------------------
  ['com.android.org.conscrypt.Platform', 'org.conscrypt.Platform'].forEach(function (cls) {
    try {
      var Platform = Java.use(cls);
      Platform.checkServerTrusted.overloads.forEach(function (ov) {
        ov.implementation = function () {
          console.log('[pin] ' + cls + '.checkServerTrusted bypassed');
        };
      });
    } catch (e) { /* class not present */ }
  });

  // ---- 5. TrustManagerImpl (Android 7+ internal verifier) ----------------------
  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI.checkTrustedRecursive.implementation = function () {
      console.log('[pin] TrustManagerImpl.checkTrustedRecursive bypassed');
      return Java.use('java.util.ArrayList').$new();
    };
    TMI.verifyChain.implementation = function (untrusted, trustAnchor, host, clientAuth, ocsp, tlsSct) {
      console.log('[pin] TrustManagerImpl.verifyChain(' + host + ') bypassed');
      return untrusted;
    };
  } catch (e) { /* older android */ }

  // ---- 6. TrustKit --------------------------------------------------------------
  try {
    var TK = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
    TK.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
      .implementation = function () { return true; };
  } catch (e) { /* not present */ }

  // ---- 7. WebView ssl errors -----------------------------------------------------
  try {
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.onReceivedSslError.overload(
      'android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError')
      .implementation = function (view, handler, error) {
        console.log('[pin] WebView SslError -> proceed()');
        handler.proceed();
      };
  } catch (e) { /* no webview */ }

  // ---- 8. HttpsURLConnection default verifier -----------------------------------
  try {
    var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
    HUC.setDefaultHostnameVerifier.implementation = function (v) {
      console.log('[pin] blocked setDefaultHostnameVerifier');
    };
    HUC.setSSLSocketFactory.implementation = function (f) {
      console.log('[pin] blocked setSSLSocketFactory');
    };
  } catch (e) { /* ignore */ }

  console.log('[pin] all hooks installed');
});
```

### 3. Flutter / BoringSSL (native) bypass

Flutter bundles its own BoringSSL and its own CA list, and ignores the device proxy.
Two steps: force traffic to the proxy (transparent proxy, or `ProxyDroid`/VPN mode),
then neuter the verification callback.

```js
// flutter-pinning.js - patch ssl_crypto_x509_session_verify_cert_chain in libflutter.so
// run: frida -U -f com.ctf.app -l flutter-pinning.js --no-pause
'use strict';

function patchFlutter() {
  var mod = Process.findModuleByName('libflutter.so');
  if (mod === null) { return false; }
  console.log('[flutter] base=' + mod.base + ' size=' + mod.size);

  // Signature of the epilogue of ssl_crypto_x509_session_verify_cert_chain on arm64.
  // Different flutter builds differ, so scan for the common prologue instead and
  // verify by cross-referencing the "x509.cc" string the function logs from.
  var patterns = [
    'F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9',   // arm64 large prologue
    '55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC'     // x86_64 prologue
  ];

  var found = [];
  patterns.forEach(function (p) {
    try {
      Memory.scanSync(mod.base, mod.size, p).forEach(function (m) { found.push(m.address); });
    } catch (e) { /* pattern invalid for this arch */ }
  });

  if (found.length === 0) {
    console.log('[flutter] no candidate found; fall back to hooking SSL_get_psk_identity');
    var sym = Module.findExportByName('libflutter.so', 'SSL_get_psk_identity');
    if (sym !== null) {
      // In stripped flutter builds this is one of the few exports; the verify function
      // is commonly found by walking backwards from it in published research.
      console.log('[flutter] SSL_get_psk_identity @ ' + sym);
    }
    return false;
  }

  console.log('[flutter] candidates: ' + found.length + ', replacing the first one');
  Interceptor.replace(found[0], new NativeCallback(function () {
    console.log('[flutter] verify_cert_chain -> 1');
    return 1;
  }, 'int', ['pointer', 'pointer', 'pointer']));
  return true;
}

if (!patchFlutter()) {
  var dl = Module.findExportByName(null, 'android_dlopen_ext');
  Interceptor.attach(dl, {
    onEnter: function (args) { this.p = args[0].readCString(); },
    onLeave: function () {
      if (this.p && this.p.indexOf('libflutter.so') !== -1) { patchFlutter(); }
    }
  });
}
```

### 4. Static patch: network-security-config

```bash
#!/bin/sh
# nsc-patch.sh - rebuild an APK so it trusts the user CA store and ignores pins
set -eu
APK="${1:?usage: nsc-patch.sh app.apk}"
OUT=nsc-work

apktool d -f -o "$OUT" "$APK"

# 1. write a permissive config
mkdir -p "$OUT/res/xml"
cat > "$OUT/res/xml/network_security_config.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
XML

# 2. point the manifest at it (and remove any existing pin-set reference)
python3 - "$OUT/AndroidManifest.xml" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
s = re.sub(r'\s+android:networkSecurityConfig="[^"]*"', '', s)
s = s.replace('<application ',
              '<application android:networkSecurityConfig="@xml/network_security_config" '
              'android:usesCleartextTraffic="true" ', 1)
open(p, 'w', encoding='utf-8').write(s)
print('manifest patched')
PY

# 3. rebuild, align, sign
apktool b "$OUT" -o unsigned.apk --use-aapt2
zipalign -p -f 4 unsigned.apk aligned.apk
[ -f debug.keystore ] || keytool -genkeypair -v -keystore debug.keystore \
    -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass android -keypass android -dname "CN=Android Debug,O=Android,C=US"
apksigner sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android \
    --out patched.apk aligned.apk
echo "built patched.apk"

# apk-mitm does all of the above in one command:
#   apk-mitm app.apk
```

### 5. Swap the pinned hash for your proxy CA's

```bash
# compute the SPKI SHA-256 pin of your Burp/mitmproxy CA - this is the value
# okhttp's CertificatePinner and <pin digest="SHA-256"> compare against
openssl x509 -in burp-ca.der -inform DER -pubkey -noout |
  openssl pkey -pubin -outform DER |
  openssl dgst -sha256 -binary |
  openssl enc -base64

# find the pins currently baked into the app
grep -rn 'sha256/' out-apktool/ || true
grep -rn '<pin ' out-apktool/res/xml/*.xml || true

# replace the old pin string in smali/resources, then rebuild as above
grep -rl 'sha256/OLDBASE64VALUE' out-apktool/ |
  xargs sed -i '' 's#sha256/OLDBASE64VALUE#sha256/YOURNEWPINVALUE#g'
```

### 6. Xposed / LSPosed

```bash
# JustTrustMe / SSLUnpinning are Xposed modules that hook the same Java APIs
# as the frida script, but survive reboots and need no host connection.
adb install -r JustTrustMe.apk
# then: LSPosed app -> Modules -> enable JustTrustMe -> scope: the target app -> force stop
adb shell am force-stop com.ctf.app
```

## Variants & pitfalls

- **It was never pinning.** On `targetSdk >= 24` the user CA store is untrusted by default.
  Install the CA into the system store (see `mobile-traffic-interception`) before
  concluding the app pins.
- **Certificate transparency / `CTVerifier`** failures look identical; hook
  `org.certificate-transparency.*` or just use the config patch.
- **Pinning inside a native lib written in Go** - hook
  `crypto/tls.(*Conn).clientHandshake` by symbol; Go binaries keep symbols unless stripped.
- **gRPC / non-HTTP** traffic will not appear in Burp's HTTP history even after the
  bypass - use `mitmproxy --mode transparent` with raw TCP, or tcpdump.
- **Two-way (mutual) TLS**: the app also presents a client cert from a `.p12` in
  `assets/`. Extract it and load it into Burp; the password is usually in the code.
- **Bypass works but the app still fails** - it may also pin the response body signature
  (JWS) or refuse to run with a proxy configured. Check for `Settings.Global.HTTP_PROXY`
  reads.
- **`Java.registerClass` fails** on some obfuscated apps because of a missing classloader;
  pass `{ loader: Java.classFactory.loader }`.
- Re-signing changes the signature, so an app doing a signature check will now fail -
  chain with `android-root-detection-bypass`.

## Tools

- `frida` + the universal script above; `objection` for the one-liner.
- `apk-mitm` - automated network-security-config patch and re-sign.
- `burp` / `mitmproxy` - the proxy itself.
- `LSPosed` + `JustTrustMe` - persistent, no host needed.
- `apktool`, `apksigner`, `zipalign` - static patching chain.

## References

- Android developer documentation: Network Security Configuration and the API 24 trust change.
- OkHttp documentation for `CertificatePinner`.
- `objection` documentation: `android sslpinning disable`.
