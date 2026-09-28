---
title: "SSRF - Parser Confusion, IP Representations and Why Blocklists Lose"
category: web
subcategory: ssrf
type: technique
tags: [ssrf, url-parser, parser-differential, whatwg-url, rfc3986, userinfo, fragment, backslash, ip-representation, decimal-ip, octal-ip, hexadecimal-ip, ipv6-mapped, nip-io, dns-rebinding, allowlist, blocklist, ipaddress, burp]
difficulty: medium
summary: "Two parsers disagree about which host a URL names, and one integer has a dozen spellings - that is why SSRF blocklists fail and allowlists do not."
when_to_use:
  - "A URL parameter is validated and you need to know how the validator and fetcher can disagree"
  - "An internal address is rejected as a literal but the feature still fetches URLs"
  - "You are reviewing SSRF validation code for structural soundness"
  - "You need to explain why adding another blocked pattern is not a fix"
related: [ssrf-fundamentals, ssrf-cloud-metadata, lfi-path-traversal, sqli-waf-bypass]
tools: [burp, curl]
---

## TL;DR

An SSRF blocklist has to answer "which host will this URL reach" using a different parser from the one that
will actually reach it, over an input space where a single address has many equivalent spellings. Both halves
of that are lost causes. The parser question is a **differential** - the same string yields different hosts
to different libraries - and the address question is a **notation** problem, because IPv4 parsers accept
decimal, octal, hex and truncated forms. An allowlist over the *resolved address* sidesteps both.

## Recognise it

- A URL parameter that rejects `http://127.0.0.1/` with a specific error rather than a generic failure - the
  sign of a blocklist.
- Validation code containing a regex over the URL string, or a list of blocked substrings.
- Different behaviour between `http://localhost/` and `http://127.0.0.1/` - two spellings, one destination,
  and only one blocked.
- A validator written in one language and a fetcher in another (a Node gateway in front of a Python service,
  for instance) - guaranteed parser differential.

## Theory

### Two specifications, two answers

There are two live URL specifications, and they disagree:

- **RFC 3986** defines a generic URI grammar, and is what most server-side parsing libraries implement.
- **The WHATWG URL Standard** defines what browsers do, which includes a great deal of error recovery for
  malformed input.

Where they differ, a validator implementing one and a fetcher implementing the other reach different
conclusions about the same string. The important cases:

**Userinfo (`@`).** In `http://expected.example@127.0.0.1/`, everything before the `@` is userinfo and the
host is `127.0.0.1`. A validator that extracts the host with a naive regex - or that simply looks for an
allowed string anywhere in the URL - sees `expected.example` and approves. Variations include multiple `@`
characters, where parsers disagree about which one delimits, and userinfo containing encoded characters.

**Fragment (`#`).** Everything after `#` is a fragment and is not sent to the server. In
`http://127.0.0.1#@expected.example/`, a parser that splits on `@` before stripping the fragment can
misidentify the host.

**Backslash.** RFC 3986 does not treat `\` as a separator; WHATWG converts it to `/`. So
`http://expected.example\@127.0.0.1/` parses differently in a browser-style parser than in a strict one.

**Other separators.** Whitespace, control characters, and encoded delimiters are handled with varying
tolerance. WHATWG's error recovery strips some characters entirely, which can change the host.

The generalisation, and the thing actually worth remembering: **any design where one component decides and a
different component acts is vulnerable to a differential between them**. This is the same structural bug as
the decode-order problems in `lfi-path-traversal` and `sqli-waf-bypass`.

### One address, many spellings

An IPv4 address is a 32-bit integer. The dotted-quad notation is one rendering among several that
`inet_aton`-style parsers accept:

| Form | `127.0.0.1` | Why it parses |
|------|-------------|---------------|
| dotted decimal | `127.0.0.1` | the familiar form |
| decimal integer | `2130706433` | the whole 32-bit value |
| hexadecimal | `0x7f000001` | `0x` prefix |
| octal | `0177.0.0.1` | a leading zero means octal |
| mixed | `0x7f.0.0.1` | per-octet radix |
| short forms | `127.1` | the final part fills the remaining octets |
| zero | `0.0.0.0` | routes to localhost on many stacks |
| IPv6 loopback | `[::1]` | a different family entirely |
| IPv4-mapped IPv6 | `[::ffff:127.0.0.1]` | IPv4 inside IPv6 |

The short-form rule is the one people find surprising: in a two-part address `a.b`, `b` is a 24-bit quantity,
so `127.1` is `127.0.0.1`. The same applies to `169.254.169.254`, which has decimal, hex, octal and
short-form spellings.

Octal handling deserves specific mention because implementations genuinely disagree. Some parsers treat a
leading zero as octal; others ignore it and parse decimal; Python's `ipaddress` module **rejects** leading
zeros outright (since 3.9.5) precisely because the ambiguity caused security bugs. That means a validator
using `ipaddress` and a fetcher using `inet_aton` can reach different addresses for the same text - a real,
current differential rather than a historical one.

### DNS is not under your control

Even a validator that correctly parses and correctly recognises every internal range still has a problem:
**a hostname is not an address**. A name you control can have an A record pointing anywhere, including
`127.0.0.1`. No string analysis of the URL can detect that, because the answer lives in DNS.

Consequences:

- Wildcard resolver services (`nip.io`, `sslip.io`) encode an address in the name, so `127.0.0.1.nip.io`
  resolves to `127.0.0.1` without you operating any infrastructure.
- A CNAME to an internal name resolves inside the target's network, where the internal view may differ from
  yours.
- Rebinding (covered in `ssrf-fundamentals`) changes the answer between the check and the connection.

This is why "validate the URL" is the wrong frame entirely. The only thing worth validating is the **address
you are about to connect to**, at the moment you connect to it.

### Why allowlists work and blocklists do not

A blocklist must enumerate everything dangerous, over an input space that includes every notation, every
parser disagreement, every redirect target, and every possible DNS answer - a space that is effectively
unbounded and changes without your involvement.

An allowlist enumerates what is *permitted*, which is finite and known. And since almost every legitimate
URL-fetching feature has a small set of intended destinations, the allowlist is usually short.

When arbitrary destinations are genuinely required, the equivalent of an allowlist is to allowlist the
**address space**: resolve the name, require the result to be a public unicast address, and connect to that
address. This defeats notation tricks (you are checking an integer, not a string), parser differentials (you
are checking the resolved result, not the text), and rebinding (you connect to the address you checked).

## Attack

1. **Establish that a blocklist exists** - a specific rejection rather than a generic failure.
2. **Test notation first.** It is the cheapest probe and tells you whether the check is on the string or on a
   parsed address.
3. **Test parser confusion next**: `@`, `#`, backslash, multiple `@`. One per request.
4. **Test a name that resolves inward** - a wildcard resolver, or a domain you control. This distinguishes
   string-level checks from resolution-level ones.
5. **Test redirect following** separately (see `ssrf-fundamentals`).
6. **Note which layer rejected you.** A CDN, a gateway and the application will each reject differently, and
   the differences map the pipeline.

## Code

Two demonstrations: that a single address has many spellings which all normalise to the same integer, and
that a string blocklist fails against them while a resolve-and-check allowlist does not.

```python
#!/usr/bin/env python3
"""IPv4 notation and why SSRF blocklists fail.

Part 1: generate equivalent representations of an address and verify each
        parses back to the same 32-bit value.
Part 2: run a string blocklist and an address allowlist against them all.

Stdlib only; no network. inet_aton is used for parsing because it accepts the
permissive forms that a real HTTP client's resolver path does.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
from urllib.parse import urlparse


def to_int(address: str) -> int:
    """Parse permissively, the way inet_aton does, and return the 32-bit value."""
    return struct.unpack("!I", socket.inet_aton(address))[0]


def representations(dotted: str) -> dict[str, str]:
    """Equivalent spellings of one IPv4 address."""
    value = to_int(dotted)
    a, b, c, d = (value >> 24) & 255, (value >> 16) & 255, (value >> 8) & 255, value & 255
    forms = {
        "dotted decimal": dotted,
        "decimal integer": str(value),
        "hexadecimal": hex(value),
        "octal per-octet": f"{a:04o}.{b:04o}.{c:04o}.{d:04o}",
        "hex per-octet": f"0x{a:02x}.0x{b:02x}.0x{c:02x}.0x{d:02x}",
        "mixed radix": f"0x{a:02x}.{b}.{c}.{d}",
        "two-part short": f"{a}.{(b << 16) | (c << 8) | d}",
        "three-part short": f"{a}.{b}.{(c << 8) | d}",
    }
    return forms


def ipv6_forms(dotted: str) -> list[str]:
    """IPv6 spellings that reach the same IPv4 destination."""
    packed = ipaddress.IPv4Address(dotted)
    return [f"::ffff:{packed}", f"::ffff:{int(packed):08x}"[:-8] + f"::ffff:{packed}"]


BLOCKED_SUBSTRINGS = ["127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0", "::1"]

PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]


def blocklist_allows(url: str) -> bool:
    """The failing design: look for known-bad strings in the URL text."""
    lowered = url.lower()
    return not any(bad in lowered for bad in BLOCKED_SUBSTRINGS)


def naive_host(url: str) -> str:
    """A regex-free but still naive host extraction: split on '/' and take [2]."""
    parts = url.split("/")
    return parts[2] if len(parts) > 2 else ""


def resolved_address_allows(url: str, resolve) -> tuple[bool, str]:
    """The sound design: resolve to an address, then check the address."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, f"scheme {parsed.scheme!r} not allowed"
    host = parsed.hostname or ""
    if not host:
        return False, "no host"
    try:
        address = resolve(host)
        ip = ipaddress.ip_address(address)
    except (ValueError, KeyError):
        return False, f"cannot resolve {host!r}"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if any(ip in net for net in PRIVATE_NETWORKS) or ip.is_loopback or ip.is_link_local:
        return False, f"{ip} is not a public unicast address"
    return True, str(ip)


def fake_resolver(host: str) -> str:
    """Stand-in resolver: literals parse permissively, names use a fixed table."""
    table = {
        "localhost": "127.0.0.1",
        "127.0.0.1.nip.io": "127.0.0.1",      # wildcard resolver encodes the address
        "internal.attacker.example": "127.0.0.1",
        "metadata.google.internal": "169.254.169.254",
        "api.partner.example": "203.0.113.20",
    }
    if host in table:
        return table[host]
    try:
        return str(ipaddress.ip_address(to_int(host)))
    except OSError as exc:
        raise KeyError(host) from exc


if __name__ == "__main__":
    print("== 1. one address, many spellings ==")
    for target in ("127.0.0.1", "169.254.169.254"):
        forms = representations(target)
        print(f"\n  {target}")
        for name, form in forms.items():
            value = to_int(form)
            print(f"    {name:<18} {form:<28} -> {value} ({ipaddress.ip_address(value)})")
            assert value == to_int(target), f"{form} must be the same address"
        # Python's ipaddress rejects the ambiguous octal form that inet_aton accepts.
        octal = forms["octal per-octet"]
        try:
            ipaddress.ip_address(octal)
            strict_rejects = False
        except ValueError:
            strict_rejects = True
        assert strict_rejects, "ipaddress rejects leading zeros; inet_aton does not"
    print("\n  -> a validator using ipaddress and a client using inet_aton")
    print("     disagree about the SAME string. That is a live differential.")

    print("\n== 2. parser confusion: which host does this URL name? ==")
    confusing = [
        "http://api.partner.example@127.0.0.1/admin",
        "http://127.0.0.1#@api.partner.example/",
        "http://api.partner.example@@127.0.0.1/",
    ]
    for url in confusing:
        real = urlparse(url).hostname
        naive = naive_host(url)
        print(f"  {url}\n    urlparse host = {real!r}   naive split = {naive!r}")
        assert real != naive, "the two extractions disagree - that gap is the bug"

    print("\n== 3. blocklist vs resolve-and-check ==")
    candidates = [
        "http://127.0.0.1/admin",
        "http://2130706433/admin",
        "http://0x7f000001/admin",
        "http://0177.0000.0000.0001/admin",
        "http://127.1/admin",
        "http://127.0.0.1.nip.io/admin",
        "http://internal.attacker.example/admin",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://api.partner.example@127.0.0.1/admin",
        "http://api.partner.example/v1/data",
    ]
    print(f"  {'url':<52} {'blocklist':<12} resolve+check")
    bypasses = 0
    for url in candidates:
        blocked_ok = blocklist_allows(url)
        allow_ok, why = resolved_address_allows(url, fake_resolver)
        if blocked_ok and not allow_ok:
            bypasses += 1
        print(f"  {url:<52} {('allows' if blocked_ok else 'blocks'):<12} "
              f"{'allows' if allow_ok else 'blocks'}  ({why})")

    # The blocklist only catches the spellings that literally contain a blocked
    # string; every alternative notation and every inward-resolving name walks past.
    assert bypasses == 6, f"expected 6 blocklist bypasses, got {bypasses}"
    # Every internal destination is refused by the sound design...
    for url in candidates[:-1]:
        assert not resolved_address_allows(url, fake_resolver)[0], url
    # ...and the legitimate one still works.
    assert resolved_address_allows(candidates[-1], fake_resolver)[0]
    print(f"\n  {bypasses} of {len(candidates) - 1} internal URLs passed the blocklist;")
    print("  0 passed the resolve-and-check. The legitimate URL passed both.")

    print("\nself-test ok")
```

## Variants & pitfalls

- **Test notation before cleverness.** If a decimal IP walks through, the check is on the string.
- **`ipaddress` and `inet_aton` disagree about leading zeros.** That is a current differential, not history.
- **Wildcard resolvers need no infrastructure** - `127.0.0.1.nip.io` is one request to test with.
- **IPv6 is routinely forgotten**, especially IPv4-mapped forms like `::ffff:127.0.0.1`.
- **`0.0.0.0` reaches localhost** on many stacks and is frequently absent from blocklists.
- **The validator and fetcher may be different languages.** Find out; it predicts which differentials exist.
- **Multiple layers reject differently.** Note *which* one rejected you.
- **A short-form address (`127.1`) is not a typo** - it is a valid spelling.
- **Blocklists miss more than loopback**: CGNAT (`100.64.0.0/10`), multicast, reserved ranges, and the
  organisation's own internal ranges.
- **Even a perfect address check is defeated by redirects and rebinding** unless the connection is pinned to
  the validated address.

### Defence / what closes this

Allowlist destination hosts wherever the feature permits it - most URL-fetching features have a short list of
intended targets, and an allowlist is finite where a blocklist is not. Where arbitrary destinations are
required, do not validate the URL string at all: parse it with a single well-tested library, allow only
`http` and `https`, resolve the hostname once, reject unless the resolved address is public unicast (checking
loopback, link-local, RFC1918, CGNAT, multicast, reserved and the IPv6 equivalents including IPv4-mapped),
and then **connect to that validated address** rather than re-resolving the name. Disable redirect following,
or re-run the whole validation on every hop. Use the same URL-parsing library in the validator and the
fetcher, in the same process, so no differential can exist. Never compare host strings or use regexes over
URLs. Route outbound fetches through an egress proxy with its own allowlist so the application host's network
position is not the one being lent, and apply network policy blocking `169.254.0.0/16` and internal ranges at
the container level, so that an application-layer mistake reaches nothing.

## Tools

- Burp Repeater - one notation per request; the rejection message identifies the layer.
- `python3 -c "import socket,struct;print(struct.unpack('!I',socket.inet_aton('127.1'))[0])"` - confirm a
  spelling parses as you expect.
- `nip.io` / `sslip.io` - wildcard resolvers for testing name-based routes without infrastructure.
- `curl -v` - shows which host it resolved and connected to, settling parser questions quickly.

## References

- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger, SSRF: https://portswigger.net/web-security/ssrf
- WHATWG URL Standard: https://url.spec.whatwg.org/
- RFC 3986, URI generic syntax: https://www.rfc-editor.org/rfc/rfc3986
- Python `ipaddress` module: https://docs.python.org/3/library/ipaddress.html
- "A New Era of SSRF" (Orange Tsai, Black Hat USA 2017): https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
- PayloadsAllTheThings, server-side request forgery: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- nip.io: https://nip.io/
