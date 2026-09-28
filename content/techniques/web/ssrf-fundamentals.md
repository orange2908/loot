---
title: "SSRF - The Request-Origin Model and Protocol Reach"
category: web
subcategory: ssrf
type: technique
tags: [ssrf, server-side-request-forgery, request-origin, loopback, link-local, gopher, dict, file-scheme, redirect-following, dns-rebinding, toctou, out-of-band, blind-ssrf, egress-filtering, curl, libcurl, interactsh, collaborator, burp]
difficulty: medium
summary: "The primitive is the server's network position, not the URL; what you get depends on protocol reach, redirect handling and how the validator resolves names."
when_to_use:
  - "A parameter contains a URL, hostname or IP that the server fetches"
  - "A webhook, URL preview, PDF renderer, image fetcher or import-from-URL feature"
  - "You need to reason about why a fetch is or is not reachable through a filter"
  - "The response is not returned, so detection has to be out-of-band"
related: [ssrf-bypass-filters, ssrf-cloud-metadata, xxe-full, upload-image-processing]
tools: [burp, interactsh, curl]
---

## TL;DR

Server-side request forgery is not about URLs. It is about **whose network stack makes the request**. A
server sits somewhere you do not: inside the perimeter, next to loopback-only admin interfaces, on a pod
network with unauthenticated internal services, on an IP that other systems trust. SSRF lends you that
position. How much it is worth is determined by three things: which protocols the client supports, whether it
follows redirects, and whether the thing that validated the URL is the same thing that connected.

## Recognise it

- A parameter that takes a URL: `?url=`, `?next=`, `?image=`, `?callback=`, `?webhook=`, `?feed=`,
  `?target=`, `?proxy=`, `?dest=`.
- Features that inherently fetch: link previews, "import from URL", avatar-by-URL, PDF/HTML rendering,
  webhooks, RSS readers, health checks, OAuth discovery, XML parsing with external entities.
- A response containing content you did not upload, or an error naming a connection failure:
  `Connection refused`, `Name or service not known`, `certificate verify failed`.
- Response-time differences between a closed port (fast refusal) and a filtered one (timeout) - a port
  oracle even with no content returned.
- A hostname field anywhere - it does not have to look like a URL.

## Theory

### What the position buys you

The value of SSRF is entirely contextual, so the first question is what the server can reach that you cannot:

- **Loopback services.** Admin interfaces, debug endpoints, metrics, message brokers and databases bound to
  `127.0.0.1` on the assumption that binding to loopback *is* the access control.
- **Internal network services.** Unauthenticated internal APIs, Kubernetes services, service meshes, CI
  systems - things protected by network placement rather than by authentication.
- **Cloud metadata.** A link-local endpoint that answers to any local process. Important enough to have its
  own page - see `ssrf-cloud-metadata`.
- **IP-based trust.** Systems that authorise by source address see the server's address, not yours.

The shared theme: SSRF defeats controls that are **implicit in network topology**. Anything protected by
"only our servers can reach it" is in scope; anything protected by a credential is not, unless the
credential is also reachable.

### Protocol reach

What you can do depends on which URL schemes the client supports, and that varies enormously by library:

| Scheme | What it does | Typically available in |
|--------|-------------|----------------------|
| `http` / `https` | ordinary request | everything |
| `file` | read a local file | libcurl (if enabled), Java, PHP streams |
| `ftp` | fetch over FTP | libcurl, Java |
| `gopher` | send near-arbitrary bytes over TCP | libcurl (if compiled in) |
| `dict` | a simple line protocol; useful as a banner grabber | libcurl |
| `ldap` | directory queries | Java |
| `jar` | fetch and unpack an archive | Java |
| `netdoc` | a legacy file-read alias | old Java |

`gopher` deserves the attention it gets. The protocol is so minimal that the URL path is effectively written
to the socket verbatim, which means a `gopher://` URL can express an arbitrary byte stream to an arbitrary
TCP port. That turns "the server fetches a URL" into "the server speaks a protocol of my choosing" - Redis,
memcached, SMTP, and other line-oriented protocols become reachable. CRLF sequences have to be URL-encoded
into the path, which is why gopher payloads look the way they do. Many distributions now compile libcurl
without gopher for exactly this reason, so its presence is worth testing rather than assuming.

The practical step: **fingerprint the client** before theorising. An error message frequently names it, and
the set of schemes it accepts tells you which library you are talking to. Python's `requests` supports only
HTTP(S); libcurl may support a dozen schemes; a Java `URLConnection` supports a different dozen.

### Redirect following

A validator that checks the URL and then hands it to a client that follows redirects has checked the wrong
thing. Your host returns `302 Location: http://127.0.0.1:8080/admin`, and the client follows it. The check
passed; the request went somewhere else.

This is a **time-of-check to time-of-use** problem, and it generalises. Any gap between validating a URL and
connecting to an address is a window:

- The validator resolves a hostname, approves the IP, and then the client resolves the name *again* when it
  connects. Two resolutions, two opportunities for different answers.
- The validator inspects the first URL; the client follows a chain of them.

**DNS rebinding** is the systematic exploitation of the first case. You control a domain whose records have a
very short TTL. The first lookup returns a public address, which passes validation. The second lookup - made
moments later by the HTTP client - returns `127.0.0.1`. Nothing in the URL changed; the *name-to-address
mapping* changed between the check and the use.

The condition for rebinding is precise and worth remembering: it requires the validator and the connecting
client to perform **separate resolutions**. A client that resolves once and connects to that resolved address
is immune, which is exactly why "resolve, validate the IP, connect to the IP you validated" is the correct
defensive pattern.

### Blind SSRF and out-of-band detection

Most SSRF returns nothing useful. The response is discarded, or replaced with a generic message. Detection
therefore depends on observing the request from the other side.

A canary domain per injection point is the discipline that makes this tractable: give every parameter its own
unique subdomain so that an interaction identifies *which* parameter fired, possibly long after you tested
it. Then watch two signals, which mean different things:

- **DNS lookup only.** Something resolved your name. That may be the application, but it may equally be a
  scanner, a mail gateway, or a corporate resolver. It proves parsing and resolution, not fetching.
- **HTTP request received.** The server actually connected. This is the strong signal, and the source IP
  tells you where the fetch came from - often revealing a proxy or an egress gateway rather than the
  application host.

The gap between the two is itself informative: DNS but no HTTP usually means egress filtering, which narrows
what the SSRF is worth before you spend time on it.

Timing is the third channel, for when there is no egress at all. A closed port refuses quickly; a filtered
one hangs until timeout. That difference is a port scanner, slowly.

### What SSRF is not

- It is not a way to read responses unless the response is reflected or inferable. Blind SSRF against a
  service you cannot observe is often worth very little.
- It does not by itself defeat authentication. An internal service requiring a credential still requires one.
- It does not give you a shell. Escalation depends entirely on what is reachable and what that thing does.

Being honest about this saves time: establish the reach first, then decide whether it is worth pursuing.

## Attack

1. **Confirm the fetch happens.** Point the parameter at a host you control and watch for the interaction.
   Nothing else matters until this is established.
2. **Identify the client** from errors, headers (a `User-Agent` in your log is a gift), and which schemes are
   accepted.
3. **Map the reach.** Loopback ports first, then the internal ranges, then link-local. Use timing if there is
   no content.
4. **Test redirect following** - a `302` from your host to an internal address is one request and answers a
   structural question.
5. **Test whether validation and connection resolve separately** - that is the rebinding precondition.
6. **Decide what it is worth** before going deeper. Reach without a reachable, exploitable service is a
   finding but not a foothold.

## Code

An offline model of the validator-versus-client gap: the same URL flow evaluated by a naive validator, a
redirect-aware one, and the resolve-once-then-connect pattern. It uses a simulated resolver and client so
the TOCTOU and rebinding conditions can be demonstrated deterministically, with no network.

```python
#!/usr/bin/env python3
"""Why URL validation and URL fetching disagree.

Models a resolver whose answers can change between calls (DNS rebinding) and a
client that can follow redirects, then runs three validator designs against
both. Shows which designs are structurally immune and why.

Deterministic simulation; no sockets, no network.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def is_internal(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in net for net in BLOCKED_NETWORKS)


@dataclass
class Resolver:
    """A resolver whose answers may change between calls, as a short TTL allows."""
    answers: dict[str, list[str]]
    calls: dict[str, int] = field(default_factory=dict)

    def resolve(self, host: str) -> str:
        n = self.calls.get(host, 0)
        self.calls[host] = n + 1
        sequence = self.answers.get(host, ["203.0.113.10"])
        return sequence[min(n, len(sequence) - 1)]


@dataclass
class Client:
    """A fetching client that resolves names itself and may follow redirects."""
    resolver: Resolver
    redirects: dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True

    def fetch(self, url: str, _depth: int = 0) -> str:
        """Return the address actually connected to."""
        if _depth > 5:
            raise RuntimeError("redirect loop")
        host = urlparse(url).hostname or ""
        address = self.resolver.resolve(host)
        if self.follow_redirects and url in self.redirects:
            return self.fetch(self.redirects[url], _depth + 1)
        return address

    def fetch_address(self, address: str) -> str:
        """Connect to an already-resolved address; no further name lookup."""
        return address


def validate_hostname_only(url: str, _resolver: Resolver) -> bool:
    """Weakest: reject literal internal addresses in the URL text."""
    host = urlparse(url).hostname or ""
    return not is_internal(host)


def validate_resolved(url: str, resolver: Resolver) -> bool:
    """Better: resolve and check the address - but the client resolves again."""
    host = urlparse(url).hostname or ""
    return not is_internal(resolver.resolve(host))


def validate_and_pin(url: str, resolver: Resolver) -> tuple[bool, str]:
    """Correct: resolve once, validate that address, and connect to it."""
    host = urlparse(url).hostname or ""
    address = resolver.resolve(host)
    return (not is_internal(address)), address


if __name__ == "__main__":
    print("== 1. literal internal address: even the weakest check catches it ==")
    resolver = Resolver({"127.0.0.1": ["127.0.0.1"]})
    assert not validate_hostname_only("http://127.0.0.1/admin", resolver)
    print("  http://127.0.0.1/admin -> rejected")

    print("\n== 2. a name that resolves inward defeats a text-only check ==")
    resolver = Resolver({"internal.example": ["127.0.0.1"]})
    url = "http://internal.example/admin"
    assert validate_hostname_only(url, resolver), "the hostname is not a literal IP"
    client = Client(resolver)
    reached = client.fetch(url)
    print(f"  {url} -> validator says OK, client reached {reached}")
    assert is_internal(reached), "the text check never looked at where the name points"

    print("\n== 3. redirects: the validator checked a different URL ==")
    resolver = Resolver({"evil.example": ["203.0.113.10"], "127.0.0.1": ["127.0.0.1"]})
    client = Client(resolver, redirects={"http://evil.example/r": "http://127.0.0.1/admin"})
    url = "http://evil.example/r"
    assert validate_resolved(url, resolver), "the first URL resolves to a public address"
    reached = client.fetch(url)
    print(f"  {url} -> validator says OK, client followed the 302 to {reached}")
    assert is_internal(reached)
    # Disabling redirect following closes this one specifically.
    strict_client = Client(resolver, redirects=client.redirects, follow_redirects=False)
    assert not is_internal(strict_client.fetch(url)), "no redirect, no escape"
    print("  with follow_redirects=False the same URL stays external")

    print("\n== 4. DNS rebinding: two resolutions, two answers ==")
    # First lookup public (passes validation), second lookup loopback (the fetch).
    resolver = Resolver({"rebind.example": ["203.0.113.10", "127.0.0.1"]})
    url = "http://rebind.example/"
    assert validate_resolved(url, resolver), "first resolution is public - validation passes"
    client = Client(resolver, follow_redirects=False)
    reached = client.fetch(url)
    print(f"  resolution 1 (validator) -> 203.0.113.10  [allowed]")
    print(f"  resolution 2 (client)    -> {reached}  [connected]")
    assert is_internal(reached), "the mapping changed between check and use"
    assert resolver.calls["rebind.example"] == 2, "two separate resolutions is the precondition"

    print("\n== 5. resolve once, validate the address, connect to that address ==")
    resolver = Resolver({"rebind.example": ["203.0.113.10", "127.0.0.1"]})
    allowed, pinned = validate_and_pin("http://rebind.example/", resolver)
    client = Client(resolver, follow_redirects=False)
    reached = client.fetch_address(pinned)
    print(f"  validated and pinned {pinned}, connected to {reached}")
    assert allowed and reached == "203.0.113.10", "no second lookup, so nothing can change"
    assert resolver.calls["rebind.example"] == 1, "one resolution closes the window"

    # The same design is immune to the name-points-inward case, because it
    # checks the resolved address rather than the text.
    resolver = Resolver({"internal.example": ["127.0.0.1"]})
    allowed, pinned = validate_and_pin("http://internal.example/admin", resolver)
    assert not allowed, "resolves internally, so it is rejected before any connection"
    print("  the same design also rejects a name that resolves inward")

    print("\nself-test ok")
```

## Variants & pitfalls

- **Confirm the fetch first.** Everything else is speculation until an interaction lands.
- **DNS-only interactions are weak evidence.** They prove resolution, not connection.
- **Use a unique canary per parameter.** Interactions can arrive hours later, and you need to know from where.
- **The source IP of the interaction is informative** - it often reveals a proxy or egress gateway rather
  than the application host.
- **`gopher` is frequently not compiled in.** Test rather than assume.
- **Scheme support identifies the library.** That is worth more than any single payload.
- **Timing is a port oracle** even with no content and no egress.
- **A validator that runs on a different host from the fetcher** can see a different DNS view entirely.
- **IPv6 is routinely forgotten** by blocklists - see `ssrf-bypass-filters`.
- **Some "SSRF" is just an open redirect.** If the server only tells the browser to go somewhere, the request
  is the browser's, and it is a different bug with different impact.

### Defence / what closes this

Prefer an allowlist of exact destination hosts; almost every legitimate URL-fetching feature has a short,
knowable list. If arbitrary URLs must be supported, use the resolve-once pattern: parse the URL, allow only
`http`/`https`, resolve the hostname to an address, reject the request unless that address is a public
unicast address (check loopback, link-local, RFC1918, CGNAT, multicast, reserved ranges, and their IPv6
equivalents including IPv4-mapped forms), then **connect to that validated address** rather than re-resolving
the name. That single change closes DNS rebinding structurally. Disable redirect following, or re-run the
full validation on every hop. Use a library that supports only the schemes you need, and never one that
supports `file`, `gopher` or `dict` for this purpose. Route outbound fetches through a dedicated egress proxy
with its own allowlist, so that the application host's network position is not the one being lent. Do not
return the fetched response body or error text to the user. Require authentication on internal services
rather than relying on network placement, and apply egress network policy so a successful SSRF reaches
nothing interesting.

## Tools

- Burp Collaborator - per-parameter canaries with DNS and HTTP correlation.
- `interactsh` - self-hosted equivalent.
- `curl -v` - check which schemes a local libcurl supports (`curl --version` lists them).
- Burp Repeater - for timing-based port probing, where consistency matters more than speed.

## References

- OWASP, server side request forgery: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Testing Guide, testing for SSRF: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery
- PortSwigger, SSRF: https://portswigger.net/web-security/ssrf
- PortSwigger, blind SSRF: https://portswigger.net/web-security/ssrf/blind
- PayloadsAllTheThings, server-side request forgery: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- curl documentation, supported protocols: https://curl.se/docs/protdocs.html
- interactsh: https://github.com/projectdiscovery/interactsh
