---
title: "php://filter Simulator and a Log-Poisoning Fixture"
category: web
subcategory: lfi
type: script
tags: [lfi, php-filter, stream-filter, convert-base64-encode, zlib-deflate, string-rot13, iconv, log-poisoning, access-log, user-agent, source-disclosure, fixture, simulation, python, offline]
summary: "A local implementation of php://filter's read pipeline plus a self-built log fixture, so the encoding mechanics and the poisoning preconditions can be checked offline."
tools: [python, php]
related: [lfi-php-filter-chain, lfi-to-rce, lfi-path-traversal, upload-to-rce]
---

## Usage

```bash
# Builds its own fixtures in a temp directory, runs, and cleans up.
python3 lfi_log_poison.py

# The filter pipeline is importable and works on any local file.
python3 -c "
from lfi_log_poison import read_php_filter
print(read_php_filter('php://filter/convert.base64-encode/resource=/etc/hostname'))
"
```

Two things are worth being able to check without a server: **what a `php://filter` URI actually does to a
stream**, and **which bytes of a log line are attacker-controlled**. This file implements the first as a
local simulation and builds the second as a fixture, so both can be reasoned about concretely. See
`lfi-php-filter-chain` for the filter-chain theory and `lfi-to-rce` for the escalation preconditions.

## What the filter pipeline does

`php://filter/<filters>/resource=<stream>` opens `<stream>` and pushes the bytes through each filter in
order. Two properties matter and are easy to get wrong from reading alone:

- **Order is left to right**, and `resource=` must come last. `convert.base64-encode|string.rot13` is not the
  same as `string.rot13|convert.base64-encode`.
- **The filters are transformations, not code.** Nothing in this pipeline executes; that is exactly why
  `convert.base64-encode` is the source-disclosure primitive. An `include` of a base64 stream emits text
  because there is no `<?php` left in it to parse.

The simulation below implements the filters whose behaviour is deterministic and checkable in Python:
`convert.base64-encode`, `convert.base64-decode`, `zlib.deflate`, `zlib.inflate`, `string.toupper`,
`string.tolower`, `string.rot13`, and the `convert.iconv.*` family. It is honest about its limits - PHP's
`iconv` is the platform's, and the chain technique in `lfi-php-filter-chain` depends on byte-level details
that this does not reproduce.

## Why log poisoning works, and when it does not

A web server writes request data into its access log verbatim. Several fields are entirely attacker-supplied:
the request line, the `User-Agent`, and the `Referer`. Nothing validates them, because a log is a record of
what was received.

That makes the log a file whose contents you partly control. Combined with an inclusion sink, it is the
classic escalation route. But three preconditions must all hold, and in practice the second one usually does
not:

1. You know the log's path.
2. The PHP process can **read** it. On Debian-family systems `/var/log/apache2/access.log` is mode 640,
   owned `root:adm`, and `www-data` is not in `adm`.
3. The sink is `include`/`require` rather than a read-only function.

The fixture below demonstrates (1) and the mechanics of getting bytes in, and checks (2) explicitly against
real file permissions - which is the step most writeups skip and most real attempts fail on.

The demonstration uses an inert marker rather than code. What it shows is the part that generalises: **which
bytes of the log line came from the request**, and whether a reader with the PHP process's permissions can
see them.

## Code

```python
#!/usr/bin/env python3
"""A local php://filter read pipeline, and a log-poisoning fixture.

Part 1: parse and apply php://filter read filters to a local file, so the
        encoding mechanics can be checked without PHP.
Part 2: build an access-log fixture, write an attacker-controlled field into
        it, and check the preconditions that decide whether log poisoning is
        reachable - including the file-permission one that usually fails.

Stdlib only. Creates and removes its own fixtures. No network.
"""
from __future__ import annotations

import base64
import codecs
import grp
import os
import pwd
import stat
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path

MARKER = "POISON-MARKER-7f3a"


# ------------------------------------------------------------ filters

def _b64_encode(data: bytes) -> bytes:
    return base64.b64encode(data)


def _b64_decode(data: bytes) -> bytes:
    """PHP's convert.base64-decode skips characters outside the alphabet."""
    alphabet = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    kept = bytes(c for c in data if c in alphabet)
    kept = kept[:len(kept) - len(kept) % 4]
    return base64.b64decode(kept) if kept else b""


def _deflate(data: bytes) -> bytes:
    """Raw deflate, matching PHP's zlib.deflate (no zlib header)."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def _inflate(data: bytes) -> bytes:
    return zlib.decompress(data, -zlib.MAX_WBITS)


def _rot13(data: bytes) -> bytes:
    return codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1")


def _iconv(data: bytes, src: str, dst: str) -> bytes:
    """Stand-in for convert.iconv.<src>.<dst>.

    Python's codecs are not the platform's iconv. Conversions that both
    understand behave the same; the exotic ones the filter-chain technique
    relies on do not, and this raises rather than pretending otherwise.
    """
    try:
        return data.decode(src, errors="strict").encode(dst, errors="strict")
    except (LookupError, UnicodeError) as exc:
        raise ValueError(f"iconv {src}->{dst} not reproducible here: {exc}") from exc


FILTERS = {
    "convert.base64-encode": _b64_encode,
    "convert.base64-decode": _b64_decode,
    "zlib.deflate": _deflate,
    "zlib.inflate": _inflate,
    "string.toupper": lambda d: d.upper(),
    "string.tolower": lambda d: d.lower(),
    "string.rot13": _rot13,
}


def apply_filter(data: bytes, name: str) -> bytes:
    if name in FILTERS:
        return FILTERS[name](data)
    if name.startswith("convert.iconv."):
        parts = name[len("convert.iconv."):].split(".")
        if len(parts) != 2:
            raise ValueError(f"malformed iconv filter: {name}")
        return _iconv(data, parts[0], parts[1])
    raise ValueError(f"unknown filter: {name}")


@dataclass
class FilterUri:
    filters: list[str]
    resource: str


def parse_filter_uri(uri: str) -> FilterUri:
    """Parse php://filter/[read=]<f1>|<f2>/resource=<path>."""
    if not uri.startswith("php://filter/"):
        raise ValueError("not a php://filter URI")
    body = uri[len("php://filter/"):]
    marker = "resource="
    index = body.find(marker)
    if index == -1:
        raise ValueError("resource= is required and must come last")
    resource = body[index + len(marker):]
    chain = body[:index].rstrip("/")
    if chain.startswith("read="):
        chain = chain[len("read="):]
    filters = [f for f in chain.split("|") if f]
    return FilterUri(filters, resource)


def read_php_filter(uri: str, root: str | None = None) -> bytes:
    """Open the resource and push it through the filter chain, in order."""
    parsed = parse_filter_uri(uri)
    path = Path(parsed.resource)
    if root is not None:
        path = Path(root) / parsed.resource
    data = path.read_bytes()
    for name in parsed.filters:
        data = apply_filter(data, name)
    return data


# ------------------------------------------------------- log fixture

LOG_FORMAT = ('{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} '
              '"{referer}" "{agent}"')

ATTACKER_CONTROLLED = {"path", "method", "referer", "agent"}


def log_line(**fields: str) -> str:
    """One combined-format access-log line."""
    defaults = {"ip": "203.0.113.9", "ts": "10/Oct/2026:13:55:36 +0000",
                "method": "GET", "path": "/", "status": "200", "size": "2326",
                "referer": "-", "agent": "curl/8.4.0"}
    defaults.update(fields)
    return LOG_FORMAT.format(**defaults)


def controlled_spans(line: str, fields: dict[str, str]) -> list[tuple[str, int, int]]:
    """Locate each attacker-controlled field's bytes within the rendered line."""
    spans = []
    for name in sorted(ATTACKER_CONTROLLED):
        value = fields.get(name)
        # Skip absent fields and values too short to locate unambiguously -
        # a one-character path matches the timestamp's separators.
        if not value or value == "-" or len(value) < 3:
            continue
        start = line.find(value)
        if start != -1:
            spans.append((name, start, start + len(value)))
    return spans


@dataclass
class ReadCheck:
    readable: bool
    reason: str


def can_process_read(path: str) -> ReadCheck:
    """Would a process with this script's identity be able to read the file?

    Models precondition 2 for log poisoning. On a real target the PHP process
    is www-data, which is typically NOT in the log file's group - which is why
    this precondition fails far more often than writeups suggest.
    """
    info = os.stat(path)
    mode = stat.S_IMODE(info.st_mode)
    try:
        owner = pwd.getpwuid(info.st_uid).pw_name
        group = grp.getgrgid(info.st_gid).gr_name
    except KeyError:                       # pragma: no cover - unusual systems
        owner, group = str(info.st_uid), str(info.st_gid)
    world_readable = bool(mode & stat.S_IROTH)
    detail = f"mode {mode:04o} {owner}:{group}"
    if world_readable:
        return ReadCheck(True, f"{detail} - world-readable")
    if info.st_uid == os.getuid() and mode & stat.S_IRUSR:
        return ReadCheck(os.access(path, os.R_OK), f"{detail} - readable by the owner only")
    return ReadCheck(os.access(path, os.R_OK), f"{detail} - not world-readable")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # ---------------------------------------------------- part 1
        print("== 1. php://filter read pipeline ==")
        config = root / "config.php"
        config.write_text("<?php $DB_PASS = 'hunter2'; // secret\n")

        raw = read_php_filter("php://filter/resource=config.php", root=str(root))
        encoded = read_php_filter(
            "php://filter/convert.base64-encode/resource=config.php", root=str(root))
        print(f"  no filters : {raw!r}")
        print(f"  base64     : {encoded!r}")
        assert b"<?php" in raw, "unfiltered, the stream still contains PHP tags"
        assert b"<?php" not in encoded, "base64 output has no tag left to execute"
        assert base64.b64decode(encoded) == raw, "and it round-trips to the source"
        print("  -> this is why base64 is the source-disclosure primitive")

        # read= prefix is optional and means the same thing.
        assert read_php_filter(
            "php://filter/read=convert.base64-encode/resource=config.php",
            root=str(root)) == encoded

        print("\n  chaining is ordered, left to right:")
        a = read_php_filter(
            "php://filter/string.rot13|convert.base64-encode/resource=config.php",
            root=str(root))
        b = read_php_filter(
            "php://filter/convert.base64-encode|string.rot13/resource=config.php",
            root=str(root))
        print(f"    rot13 then base64 : {a[:32]!r}...")
        print(f"    base64 then rot13 : {b[:32]!r}...")
        assert a != b, "order changes the result"
        # Undo in reverse order. Strict decoding here: the output is clean
        # base64, so the padding-tolerant decoder is not what we want.
        assert _rot13(base64.b64decode(a)) == raw, "undo in reverse order to recover"

        print("\n  deflate shrinks a large file before encoding:")
        big = root / "big.php"
        big.write_text("<?php\n" + ("// filler line to make this compressible\n" * 200))
        plain = read_php_filter(
            "php://filter/convert.base64-encode/resource=big.php", root=str(root))
        squeezed = read_php_filter(
            "php://filter/zlib.deflate|convert.base64-encode/resource=big.php",
            root=str(root))
        ratio = len(squeezed) / len(plain)
        print(f"    base64 alone        : {len(plain)} bytes")
        print(f"    deflate then base64 : {len(squeezed)} bytes ({ratio:.1%})")
        assert len(squeezed) < len(plain) / 4, "worth it when the response is size-limited"
        assert _inflate(base64.b64decode(squeezed)) == big.read_bytes()

        print("\n  resource= must come last:")
        for bad in ("php://filter/resource=config.php/convert.base64-encode",
                    "php://filter/convert.base64-encode"):
            try:
                read_php_filter(bad, root=str(root))
                raise AssertionError(f"should have been rejected: {bad}")
            except (ValueError, OSError) as exc:
                # Note what happens to the first one: everything after
                # 'resource=' is taken as the path, so the filter name becomes
                # part of the filename rather than a filter.
                print(f"    {bad[:52]:<52} -> {type(exc).__name__}")

        # The iconv stand-in is honest about what it cannot reproduce.
        try:
            apply_filter(b"AA", "convert.iconv.UTF-8.UTF-16LE")
            print("\n  iconv UTF-8 -> UTF-16LE reproduced locally")
        except ValueError as exc:
            print(f"\n  iconv note: {exc}")

        # ---------------------------------------------------- part 2
        print("\n== 2. log-poisoning fixture ==")
        logdir = root / "log"
        logdir.mkdir()
        access = logdir / "access.log"

        # Ordinary traffic.
        access.write_text("\n".join(
            log_line(path="/index.html"),
            ) + "\n")

        # A request whose User-Agent carries an attacker-chosen string. Nothing
        # validates it, because a log records what was received.
        fields = {"path": "/", "agent": f"Mozilla/5.0 {MARKER}"}
        poisoned = log_line(**fields)
        with access.open("a", encoding="utf-8") as handle:
            handle.write(poisoned + "\n")

        print(f"  appended line:\n    {poisoned}")
        spans = controlled_spans(poisoned, fields)
        print("  attacker-controlled spans in that line:")
        for name, start, end in spans:
            print(f"    {name:<8} [{start:>3}:{end:>3}] {poisoned[start:end]!r}")
        assert any(name == "agent" for name, _, _ in spans)
        assert MARKER in poisoned

        # Precondition 1: the reader must find the file.
        assert access.exists()

        # Precondition 2: the PHP process must be able to read it.
        check = can_process_read(str(access))
        print(f"\n  readable by this process? {check.readable}  ({check.reason})")
        assert check.readable, "the fixture is ours, so this one passes here"

        # The same check against a file the PHP user could not read. Simulated
        # by removing all permissions; on a real host the log is 640 root:adm
        # and the PHP user is www-data, which is not in adm.
        locked = logdir / "root-owned.log"
        locked.write_text(poisoned + "\n")
        os.chmod(locked, 0o000)
        locked_check = can_process_read(str(locked))
        print(f"  a 0000 log readable?      {locked_check.readable}  ({locked_check.reason})")
        if os.getuid() == 0:
            print("  (running as root, so permissions do not bite here)")
        else:
            assert not locked_check.readable, "mode 000 blocks the read"
            print("  -> this is the precondition that fails on real hosts")
        os.chmod(locked, 0o644)

        # Reading the log back through the filter pipeline: the controlled
        # bytes are present in what a reader receives.
        seen = read_php_filter(
            "php://filter/convert.base64-encode/resource=log/access.log", root=str(root))
        decoded = base64.b64decode(seen).decode()
        assert MARKER in decoded, "the request-supplied bytes reached the reader"
        print(f"\n  marker present in the filtered read: {MARKER in decoded}")
        print("  -> attacker-chosen bytes are now inside a file the sink may open")
        print("     (an inert marker here; what makes it RCE is the sink executing,")
        print("      which is the include-vs-read distinction in lfi-to-rce)")

    print("\nself-test ok")
```

## Notes on fidelity

- **`convert.iconv.*` is the weak point of the simulation.** PHP delegates to the platform's `iconv`, whose
  behaviour for unusual encodings differs between glibc, musl and macOS. The function above raises rather
  than guessing, which is the honest behaviour - a chain built against one platform's `iconv` genuinely can
  fail on another.
- **`zlib.deflate` is raw deflate** (no zlib wrapper), which is why the code uses `-zlib.MAX_WBITS`. Getting
  this wrong is the usual reason a locally-decoded `zlib.deflate` output looks corrupt.
- **`convert.base64-decode`'s tolerance** of non-alphabet characters is reproduced, because it is the
  property the chain technique depends on. Note the truncation of a trailing partial group - a stray
  alphabet character shifts everything after it.
- **The log fixture is a model.** Real formats vary (combined, common, JSON), and a real server may escape or
  truncate fields. Check the actual format before assuming which bytes survive.

## Variants & pitfalls

- **`resource=` last, filters first.** The parser above enforces it because PHP does.
- **A forced `.php` suffix does not break the wrapper**, since the suffix lands on the resource name rather
  than on a filesystem path.
- **`allow_url_fopen=Off` disables `php://filter` entirely** - the one setting that closes it.
- **`open_basedir` still applies** to the underlying resource.
- **Log readability is the binding constraint** for poisoning, not payload construction. Check it first.
- **Some servers escape control characters** in logged fields, and some truncate long User-Agent values.
- **Writing to a log is one-way.** If a line corrupts the file for your purposes, you cannot remove it, and
  every subsequent request appends more noise.
- **Read source before anything else.** Dumping the including file and the config usually shortens the rest
  of the problem substantially.

### Defence / what closes this

Do not pass user input to a function that opens a path - map it through a hard-coded allowlist to a fixed
filename, which closes the wrapper and the traversal routes together. Reject any value containing `://`
before it reaches a stream function, since every wrapper is reached through a scheme. Set
`allow_url_fopen=Off` and `allow_url_include=Off` unless a feature needs them, and confine `open_basedir` to
the application directory so logs and `/proc` are unreachable. Run PHP as a user that cannot read the web
server's logs - the default `640 root:adm` on Debian-family systems is doing real work, so do not add the
web user to `adm`. Keep secrets out of PHP files that user input could name, using environment variables or a
secret store. Disable `display_errors` in production so include paths are not disclosed.

## References

- PHP manual, `php://` wrappers: https://www.php.net/manual/en/wrappers.php.php
- PHP manual, available filters: https://www.php.net/manual/en/filters.php
- PHP manual, `convert.*` filters: https://www.php.net/manual/en/filters.convert.php
- PHP manual, `zlib.*` filters: https://www.php.net/manual/en/filters.compression.php
- Apache, log files and the combined log format: https://httpd.apache.org/docs/current/logs.html
- OWASP Testing Guide, testing for local file inclusion: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- PayloadsAllTheThings, file inclusion: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
