---
title: "Mobile Traffic Interception - Burp and mitmproxy for Android and iOS"
category: mobile
subcategory: network
type: technique
tags: [burp, mitmproxy, proxy, ca-certificate, system-store, android, ios, tcpdump, pcap, transparent-proxy, magisk, network-security-config, subject-hash-old, frida, wireshark]
difficulty: medium
summary: "Get an app's HTTPS into your proxy: CA installation on Android 7+ and iOS, transparent proxying, and capturing traffic that ignores the proxy."
when_to_use:
  - "You need to see or tamper with the app's API calls"
  - "The app shows a network error the moment you set a proxy"
  - "Traffic never reaches the proxy at all (Flutter, gRPC, raw sockets)"
tools: [burp, mitmproxy, adb, frida, objection, tcpdump, wireshark]
related: [android-ssl-pinning-bypass, android-frida-basics, ios-frida-runtime, android-apk-triage]
---

## TL;DR

Three independent things must all be true: the app must **route** through you, it must
**trust** your CA, and it must not **pin**. Solve them in that order. On Android 7+ a
user-installed CA is ignored by default, so either patch `network_security_config.xml`
or push the CA into the system store. If the app ignores the proxy entirely, go
transparent or capture with `tcpdump`.

## Recognise it

| Symptom | Cause |
|---|---|
| No requests in the proxy at all | routing problem (no proxy set, or the app ignores it) |
| `SSLHandshakeException: Trust anchor ... not found` | CA not trusted (Android 7+ default) |
| Handshake completes then the app closes the connection | pinning |
| HTTP works, HTTPS does not | CA trust |
| Works on an old emulator, fails on a new one | `targetSdk >= 24` user-CA change |
| Only some hosts fail | per-domain `<pin-set>` or `<domain-config>` |

## Theory

### Android CA trust by API level

- **API < 24**: the user CA store (`Settings > Security > Install from storage`) is trusted
  by every app. Install and you are done.
- **API >= 24** with no `networkSecurityConfig`: the implicit default is
  `<certificates src="system" />` only. A user CA is installed but ignored.
- **`android:debuggable="true"`** activates `<debug-overrides>`, which is the cleanest
  legitimate way to trust a user CA - but only if the app's config declares it.

Three fixes, in increasing effort:

1. Patch the APK: add a permissive `network_security_config.xml` and re-sign
   (`apk-mitm` automates this).
2. Put the CA in the system store: `/system/etc/security/cacerts/<hash>.0`,
   where `<hash>` comes from `openssl x509 -inform PEM -subject_hash_old -noout`.
   On Android 10+ `/system` is read-only and often on a dm-verity partition - use a
   Magisk module (`AlwaysTrustUserCerts`, `MagiskTrustUserCerts`) which bind-mounts
   the user certs into the system store at boot.
3. Hook the trust check with Frida (see `android-ssl-pinning-bypass`), which also
   covers pinning in one step.

### iOS CA trust

Installing a `.pem`/`.der` profile is two steps and people forget the second:

1. Open `http://<proxy-ip>:8080` in Safari on the device and install the profile
   (`Settings > General > VPN & Device Management > <profile> > Install`).
2. **`Settings > General > About > Certificate Trust Settings` -> enable full trust.**
   Without this the CA is installed but not trusted for TLS.

### Routing

| Method | Covers |
|---|---|
| WiFi manual proxy | apps using the system `HttpProxy` (most Java/OkHttp/NSURLSession) |
| `adb shell settings put global http_proxy ip:port` | same, without touching the UI |
| transparent proxy (iptables REDIRECT) | everything TCP, including apps that ignore the proxy |
| VPN-mode app (proxy-over-tun) | everything, no root, no iptables |
| `mitmproxy --mode wireguard` | whole device over WireGuard, no root |
| `tcpdump` + Wireshark | everything, but encrypted unless you also get keys |

Flutter/Dart, Go, and some gRPC stacks do **not** read the system proxy setting. They need
transparent/VPN routing.

## Attack

1. Put host and device on the same network; note the host IP.
2. Start the proxy bound to all interfaces.
3. Configure routing (WiFi proxy first, transparent if that yields nothing).
4. Install the CA and make it trusted for the platform/API level.
5. Confirm with plain HTTP, then HTTPS to a known host.
6. If HTTPS still fails, it is pinning -> `android-ssl-pinning-bypass` / `ios-frida-runtime`.
7. If nothing appears even for HTTP, it is routing -> transparent proxy or tcpdump.

## Code

### Start the proxy

```bash
# mitmproxy on all interfaces; the CA is generated at ~/.mitmproxy on first run
mitmproxy --listen-host 0.0.0.0 --listen-port 8080
mitmweb --listen-host 0.0.0.0 --listen-port 8080 --web-host 0.0.0.0
mitmdump -w flows.mitm --listen-port 8080          # headless capture to a file
mitmdump -r flows.mitm "~u /api/"                  # replay and filter a saved capture

# transparent mode (device routed via iptables / default gateway)
mitmproxy --mode transparent --showhost --listen-port 8080

# whole-device wireguard mode: scan the printed QR with the WireGuard app, no root
mitmproxy --mode wireguard

# burp: Proxy > Options > add listener 0.0.0.0:8080, and export the CA:
#   Proxy > Options > Import/Export CA certificate > Certificate in DER format
#   -> cacert.der
openssl x509 -inform DER -in cacert.der -out burp.pem     # convert for android/ios
```

### Android: routing

```bash
# system-wide proxy without touching the UI (survives until you clear it)
adb shell settings put global http_proxy 192.168.1.10:8080
adb shell settings get global http_proxy
adb shell settings put global http_proxy :0            # clear it

# emulator started with a proxy
emulator -avd Pixel_API_30 -writable-system -http-proxy http://192.168.1.10:8080

# reverse tunnel: the device reaches the host proxy over usb, no shared network
adb reverse tcp:8080 tcp:8080
adb shell settings put global http_proxy 127.0.0.1:8080

# transparent: redirect all app tcp to the proxy (needs root on the device)
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80  -j DNAT --to 192.168.1.10:8080'
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to 192.168.1.10:8080'
adb shell su -c 'iptables -t nat -L OUTPUT -n -v'
adb shell su -c 'iptables -t nat -F OUTPUT'            # undo
```

### Android: installing the CA

```bash
#!/bin/sh
# push-ca.sh - install a proxy CA into the android system trust store
set -eu
PEM="${1:?usage: push-ca.sh burp.pem}"

# 1. android names system certs by the OLD openssl subject hash, with a .0 suffix
HASH="$(openssl x509 -inform PEM -subject_hash_old -in "$PEM" -noout)"
echo "hash = $HASH"

# 2. the file must contain the PEM followed by a human-readable dump
cp "$PEM" "${HASH}.0"
openssl x509 -inform PEM -in "$PEM" -text -fingerprint -noout >> "${HASH}.0"

# 3a. user store (works on API < 24, or with <debug-overrides>)
adb push "${HASH}.0" /sdcard/
echo "then: Settings > Security > Encryption & credentials > Install a certificate > CA cert"

# 3b. system store on a rooted device / emulator with -writable-system
adb root
adb remount || adb shell su -c 'mount -o rw,remount /system'
adb push "${HASH}.0" /data/local/tmp/
adb shell su -c "cp /data/local/tmp/${HASH}.0 /system/etc/security/cacerts/"
adb shell su -c "chmod 644 /system/etc/security/cacerts/${HASH}.0"
adb shell su -c "chown root:root /system/etc/security/cacerts/${HASH}.0"
adb reboot

# 3c. android 10+ with magisk: certs live on a tmpfs, so bind-mount instead
#     install the "AlwaysTrustUserCerts" magisk module, add the CA as a USER cert,
#     and reboot - the module copies user certs into the system store at every boot.

# 4. verify
adb shell ls -la /system/etc/security/cacerts/ | grep "${HASH}"
```

```bash
# android 14+: the trust store moved to an apex module
adb shell ls /apex/com.android.conscrypt/cacerts/
# a rooted workaround remounts a tmpfs copy of that directory:
adb shell su -c '
  mkdir -p /data/local/tmp/cacopy
  cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/cacopy/
  cp /data/local/tmp/*.0 /data/local/tmp/cacopy/
  mount -t tmpfs tmpfs /apex/com.android.conscrypt/cacerts
  cp /data/local/tmp/cacopy/* /apex/com.android.conscrypt/cacerts/
  chmod 644 /apex/com.android.conscrypt/cacerts/*
  chcon u:object_r:system_file:s0 /apex/com.android.conscrypt/cacerts/* '
```

### iOS

```bash
# 1. route: Settings > Wi-Fi > (i) > Configure Proxy > Manual > host + 8080
#    or use the usb tunnel:
iproxy 8080 8080 &

# 2. serve the CA to the device: open http://<proxy-ip>:8080 in Safari
#    mitmproxy serves it at http://mitm.it ; burp serves it at http://burp

# 3. install: Settings > General > VPN & Device Management > Profile > Install
# 4. TRUST IT:  Settings > General > About > Certificate Trust Settings > toggle on
#    (skipping step 4 is the single most common mistake)

# jailbroken device: drop the CA straight into the system store over ssh
iproxy 2222 22 &
scp -P 2222 burp.pem root@127.0.0.1:/tmp/
ssh -p 2222 root@127.0.0.1 "security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain /tmp/burp.pem"

# check which certs the device trusts
ssh -p 2222 root@127.0.0.1 "security dump-trust-settings -d"
```

### When the app ignores the proxy

```bash
# capture raw traffic on the device and analyse it on the host
adb shell su -c 'tcpdump -i any -s 0 -w /sdcard/cap.pcap' &
# ... exercise the app ...
adb shell su -c 'pkill tcpdump'
adb pull /sdcard/cap.pcap
wireshark cap.pcap

# stream a capture straight into wireshark over adb (no file on the device)
adb shell su -c 'tcpdump -i any -s 0 -w -' | wireshark -k -i -

# which hosts does the app talk to, without decryption
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name | sort -u

# ios: rvictl creates a virtual interface mirroring the device (macOS only)
UDID="$(idevice_id -l | head -1)"
rvictl -s "$UDID"
tcpdump -i rvi0 -s 0 -w ios.pcap
rvictl -x "$UDID"

# ios on a jailbroken device
ssh -p 2222 root@127.0.0.1 "tcpdump -i any -s 0 -w /tmp/cap.pcap"
scp -P 2222 root@127.0.0.1:/tmp/cap.pcap .
```

### mitmproxy addon: log, rewrite and dump

```python
#!/usr/bin/env python3
"""ctf_addon.py - a mitmproxy addon that logs every request, extracts tokens, and
rewrites responses so you can flip client-side checks.

Run:  mitmproxy -s ctf_addon.py --listen-port 8080
      mitmdump  -s ctf_addon.py -w flows.mitm
"""
from __future__ import annotations

import json
import re
import sys

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}")
SECRET_RE = re.compile(r"(?i)(api[_-]?key|token|secret|password|authorization)")

HOST_ALLOW: list[str] = []   # empty = log everything; otherwise only these hosts


class CTFAddon:
    def __init__(self) -> None:
        self.tokens: set[str] = set()
        self.hosts: set[str] = set()

    # ---- helpers ---------------------------------------------------------
    def _interesting(self, host: str) -> bool:
        return not HOST_ALLOW or any(h in host for h in HOST_ALLOW)

    def _scan(self, label: str, blob: str) -> None:
        for t in JWT_RE.findall(blob):
            if t not in self.tokens:
                self.tokens.add(t)
                print(f"[jwt] ({label}) {t[:80]}...")

    # ---- mitmproxy hooks -------------------------------------------------
    def request(self, flow) -> None:                 # noqa: ANN001 - mitmproxy type
        host = flow.request.pretty_host
        self.hosts.add(host)
        if not self._interesting(host):
            return
        print(f"\n>>> {flow.request.method} {flow.request.pretty_url}")
        for k, v in flow.request.headers.items():
            if SECRET_RE.search(k) or SECRET_RE.search(v):
                print(f"    {k}: {v}")
        body = flow.request.get_text(strict=False) or ""
        if body:
            print(f"    body: {body[:400]}")
            self._scan("req", body)
        self._scan("hdr", str(flow.request.headers))

    def response(self, flow) -> None:                # noqa: ANN001
        host = flow.request.pretty_host
        if not self._interesting(host):
            return
        body = flow.response.get_text(strict=False) or ""
        print(f"<<< {flow.response.status_code} {flow.request.path} ({len(body)} bytes)")
        self._scan("resp", body)

        # flip a client-side gate: {"premium": false} -> {"premium": true}
        ctype = flow.response.headers.get("content-type", "")
        if "json" in ctype and body:
            try:
                data = json.loads(body)
            except ValueError:
                return
            changed = False
            if isinstance(data, dict):
                for key in ("premium", "isPremium", "verified", "admin", "isAdmin", "valid"):
                    if data.get(key) is False:
                        data[key] = True
                        changed = True
            if changed:
                flow.response.text = json.dumps(data)
                print(f"    [patched] {flow.request.path}")

    def done(self) -> None:
        print("\n=== hosts seen ===")
        for h in sorted(self.hosts):
            print("  " + h)
        print(f"=== {len(self.tokens)} jwt(s) captured ===")


addons = [CTFAddon()]


if __name__ == "__main__":
    # self-test with fake flow objects so the logic can be checked without mitmproxy
    class _Headers(dict):
        def items(self):  # noqa: D102
            return dict.items(self)

        def get(self, k, d=None):  # noqa: D102
            return dict.get(self, k, d)

    class _Req:
        method = "POST"
        pretty_url = "https://api.ctf.example/login"
        pretty_host = "api.ctf.example"
        path = "/login"
        headers = _Headers({"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.abcd"})

        def get_text(self, strict: bool = True) -> str:
            return '{"user":"a"}'

    class _Resp:
        status_code = 200
        headers = _Headers({"content-type": "application/json"})
        text = '{"premium": false}'

        def get_text(self, strict: bool = True) -> str:
            return self.text

    class _Flow:
        request = _Req()
        response = _Resp()

    addon = CTFAddon()
    flow = _Flow()
    addon.request(flow)
    addon.response(flow)
    assert addon.tokens, "jwt not captured"
    assert json.loads(flow.response.text)["premium"] is True, flow.response.text
    addon.done()
    print("selftest ok", file=sys.stderr)
```

## Variants & pitfalls

- **"Nothing in the proxy"** is almost always routing, not TLS. Test with
  `adb shell curl -x 192.168.1.10:8080 http://example.com` (or a browser on the device).
- **Android 7+**: installing the CA as a *user* cert and expecting it to work is the
  classic mistake. Check `targetSdkVersion`.
- **`-writable-system`** must be passed when the emulator *starts*; you cannot enable it
  later, and it disables Play Store images on some API levels.
- **`subject_hash` vs `subject_hash_old`** - Android uses the **old** (MD5-based) hash.
  Using the new one silently does nothing.
- **Certificate pinning looks like a CA problem.** Distinguish them: if a browser on the
  same device works through the proxy but the app does not, it is pinning.
- **HTTP/2 and gRPC** need `mitmproxy` (Burp handles h2 but its history view can hide
  gRPC bodies); use `--set http2=true` and the gRPC content-view.
- **QUIC/HTTP3** is not proxied by default - block UDP/443 so the app falls back to TCP:
  `iptables -A OUTPUT -p udp --dport 443 -j REJECT`.
- **The emulator host is `10.0.2.2`** from inside a standard AVD, not `127.0.0.1`.
- **iOS profile installed but not trusted** - repeat: Certificate Trust Settings.

## Tools

- `burp` - best for manual tampering; `mitmproxy` for scripting and raw modes.
- `apk-mitm` - one-command network-security-config patch and re-sign.
- `frida` / `objection` - pinning bypass once routing and trust work.
- `tcpdump`, `wireshark`, `tshark`, `rvictl` - when the proxy is not an option.
- `adb reverse` / `iproxy` - proxying over USB without a shared network.

## References

- Android developer documentation: Network Security Configuration and CA trust changes in API 24.
- mitmproxy documentation: transparent mode, WireGuard mode, and addon scripting API.
- Apple support documentation on installing and trusting a configuration profile.
