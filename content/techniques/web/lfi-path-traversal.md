---
title: "Path Traversal - Encodings, Normalisation Order and Zip Slip"
category: web
subcategory: lfi
type: technique
tags: [path-traversal, directory-traversal, lfi, normalisation, url-encoding, double-encoding, overlong-utf8, null-byte, realpath, open-basedir, windows-paths, unc-path, alternate-data-stream, zip-slip, tarfile, zipfile, safe-join, ffuf]
difficulty: medium
summary: "Traversal survives because the check and the filesystem disagree about what a path is - decode order, platform separators and archive members are all the same bug."
when_to_use:
  - "A parameter names a file and `../` is stripped, rejected or normalised"
  - "You need to work out whether a filter runs before or after decoding"
  - "The target is Windows and POSIX traversal assumptions are not holding"
  - "An application extracts an archive you supply"
related: [lfi-to-rce, lfi-php-filter-chain, upload-to-rce, sqli-waf-bypass]
tools: [burp, ffuf, curl]
---

## TL;DR

A path check is a claim about which file a string will resolve to. The claim breaks whenever the checking
code and the resolving code interpret the string differently - because one decoded and the other did not,
because the platform accepts separators the check did not consider, or because the string is a member name
inside an archive that the extractor will join onto a directory. Same bug, three surfaces.

## Recognise it

- A parameter naming a file: `?file=`, `?path=`, `?doc=`, `?download=`, `?template=`, `?lang=`.
- `../` is removed from your input but the rest survives - a removal filter, which is not idempotent.
- The response differs between a file that exists and one that does not (a 200 with empty body versus a 404),
  which gives you an oracle even without content.
- Error messages containing absolute paths.
- An upload feature that extracts archives, or an import that accepts `.zip`, `.tar.gz`, `.jar`, `.docx`.

## Theory

### The core disagreement

Consider `check(path) && open(path)`. Safety requires that `check` evaluates the same string that `open`
resolves. Four ways that fails:

1. **Decoding between the check and the open.** The check sees `%2e%2e%2f`, finds no `../`, and a later
   decode turns it into traversal. Double encoding (`%252e`) extends this to pipelines that decode twice.
2. **Normalisation after the check.** The check sees a literal string; the filesystem collapses `.` and `..`
   and duplicate separators when resolving. Anything the check did not collapse, the OS will.
3. **Platform separator differences.** On Windows both `/` and `\` separate path components. A check that
   looks for `../` misses `..\`.
4. **Removal instead of rejection.** `str_replace('../', '', $p)` applied once to `....//` yields `../` -
   the filter reconstructs what it removes. Identical to the strip-once problem in `sqli-waf-bypass`.

### The encoding ladder

Each rung exists because some layer decodes at a different point:

| Form | Becomes | Defeats |
|------|---------|---------|
| `../` | - | nothing; the baseline |
| `..%2f` | `../` | a check on the raw string |
| `%2e%2e%2f` | `../` | a check looking for literal dots |
| `%252e%252e%252f` | `%2e%2e%2f` then `../` | a pipeline that decodes twice |
| `....//` | `../` after one strip pass | strip-once removal |
| `..././` | `../` after one strip pass | strip-once removal |
| `..%c0%af` | `../` on decoders accepting overlong UTF-8 | strict-looking byte checks |
| `..%u2215` | `../` on some legacy Windows decoders | historical only |

The overlong-UTF-8 rung is worth understanding rather than memorising: UTF-8 requires the *shortest*
encoding of a code point, so `%c0%af` is an illegal two-byte encoding of `/`. A decoder that accepts it
anyway produces a separator that a byte-level check never saw. Modern decoders reject overlong forms, which
is why this is a legacy rung - but it illustrates the general principle that any decoder with a permissive
error mode is a place where the string changes after inspection.

### Prefix and suffix constraints

Real code rarely uses the parameter raw:

- **Forced prefix**: `include('/var/www/pages/' . $p)`. Traversal must climb out, so you need enough `../`.
  Extra levels are harmless - the root directory's parent is itself - so over-climbing is the safe default.
- **Forced suffix**: `include($p . '.php')`. This is the harder one. Historical answers: a null byte
  (`%00`), which terminated the C string and was **fixed in PHP 5.3.4**; and path truncation by exceeding
  `PATH_MAX` with thousands of `/.` sequences, also long fixed. On a modern target, the working answer is a
  wrapper whose name is not a filesystem path - `php://filter/...` - because the suffix lands harmlessly on
  the resource name. See `lfi-php-filter-chain`.

### Windows specifics

Windows path handling has more accepting behaviour than POSIX, and a filter written with POSIX in mind
misses most of it:

- **Both separators work**: `..\..\..\windows\win.ini` and `../../../windows/win.ini`.
- **Drive-relative paths**: `C:file` means "file in the current directory on C:", which is not the same as
  `C:\file`.
- **Trailing dots and spaces are stripped** by the Win32 path normaliser, so `secret.php.` and `secret.php `
  open `secret.php`. That is the mechanism behind several upload-filter bypasses too (`upload-to-rce`).
- **8.3 short names**: `PROGRA~1` for `Program Files`. A check for a long name misses the short one.
- **Reserved device names**: `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9` resolve to devices
  regardless of directory, historically a denial-of-service and confusion source.
- **Alternate data streams**: `file.txt::$DATA` reads the default stream, so a suffix or extension check that
  matches on the visible name can be sidestepped.
- **UNC paths**: `\\host\share\file`. On Windows this makes an **outbound SMB connection**, which turns a
  traversal into an SSRF-shaped primitive: it can leak NTLM credentials to a host you control, or reach an
  internal share. `\\?\` disables normalisation entirely, which is its own class of surprise.

### Zip slip

An archive member name is a *path*, and extractors join it onto a destination directory. If the member name
is `../../../etc/cron.d/x`, a naive extractor writes outside the destination. Same bug, applied to a
different string source - and the check is missing in exactly the same way.

Two variants beyond the obvious one:

- **Absolute member names.** `/etc/passwd` as a member name; some extractors honour it.
- **Symlink members.** Both tar and zip can store a symlink. Extract a symlink pointing at `/`, then a second
  member that writes *through* it. The individual member names look harmless in isolation, which defeats a
  name-only check.

The safe extraction pattern is the same as the safe path-join pattern: resolve the final destination and
verify it is inside the intended directory, per member, *before* writing. Python 3.12 added
`tarfile.extractall(filter='data')` to do this by default; earlier versions extract unsafely unless you
implement the check.

## Attack

1. **Establish an oracle.** Find the difference between a file that exists and one that does not. Without it
   you are guessing blind.
2. **Test one rung at a time.** `../`, then `..%2f`, then `%2e%2e%2f`, then double-encoded. One variable per
   request tells you *which layer* is doing the decoding.
3. **Over-climb.** Use more `../` than you think you need; the root's parent is the root.
4. **Determine the platform** before assuming separators - a Windows target changes the whole ladder.
5. **Look for a suffix.** If the error shows `.php` appended, stop trying null bytes and reach for a wrapper.
6. **For archives**, check whether the extractor validates member names, and try a symlink member as well as
   a traversing name.

## Code

Two demonstrations: that decode order decides what was actually checked, and that a per-member destination
check is what makes extraction safe. Both build their own fixtures in a temporary directory and clean up.

```python
#!/usr/bin/env python3
"""Path traversal as a normalisation-order problem, and safe archive extraction.

Part 1: the same input passes or fails depending on whether the check runs
        before or after decoding - and a realpath-based check is order-immune.
Part 2: builds a traversing zip in a temp directory and shows the naive
        extractor escaping the destination while a checked extractor refuses.

Stdlib only; creates and removes its own fixtures. No network.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import unquote

BASE = "/var/www/pages"


def decode_to_fixpoint(value: str, limit: int = 10) -> str:
    """Percent-decode until stable, modelling a multi-layer pipeline."""
    for _ in range(limit):
        nxt = unquote(value)
        if nxt == value:
            return value
        value = nxt
    return value


def check_then_decode(user: str) -> tuple[bool, str]:
    """Wrong order: inspect the raw string, decode afterwards."""
    if ".." in user:
        return False, ""
    return True, os.path.normpath(os.path.join(BASE, decode_to_fixpoint(user)))


def decode_then_check(user: str) -> tuple[bool, str]:
    """Better: decode fully first, then inspect. Still a blocklist."""
    decoded = decode_to_fixpoint(user)
    if ".." in decoded or decoded.startswith("/"):
        return False, ""
    return True, os.path.normpath(os.path.join(BASE, decoded))


def strip_once(user: str) -> tuple[bool, str]:
    """The removal anti-pattern: delete '../' in a single pass."""
    cleaned = decode_to_fixpoint(user).replace("../", "")
    return True, os.path.normpath(os.path.join(BASE, cleaned))


def resolve_and_confine(user: str) -> tuple[bool, str]:
    """The sound check: resolve the final path, then verify containment."""
    decoded = decode_to_fixpoint(user)
    candidate = os.path.normpath(os.path.join(BASE, decoded))
    base = os.path.normpath(BASE)
    if candidate != base and not candidate.startswith(base + os.sep):
        return False, ""
    return True, candidate


def escapes(result: tuple[bool, str]) -> bool:
    """Did the check allow a path outside the base directory?"""
    allowed, path = result
    base = os.path.normpath(BASE)
    return allowed and path != base and not path.startswith(base + os.sep)


def safe_members(archive: zipfile.ZipFile, dest: Path) -> list[str]:
    """Member names that resolve inside dest. The per-member containment check."""
    root = dest.resolve()
    ok: list[str] = []
    for name in archive.namelist():
        target = (root / name).resolve()
        if target == root or root in target.parents:
            ok.append(name)
    return ok


if __name__ == "__main__":
    print("== 1. decode order decides what was inspected ==")
    payloads = [
        ("../../../etc/passwd", "plain traversal"),
        ("..%2f..%2f..%2fetc%2fpasswd", "single-encoded separators"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "encoded dots as well"),
        ("%252e%252e%252fetc%252fpasswd", "double-encoded"),
        ("....//....//etc/passwd", "strip-once reconstruction"),
    ]
    header = f"  {'payload':<44} {'check|decode':<13} {'decode|check':<13} {'strip-once':<11} confine"
    print(header)
    for payload, _ in payloads:
        row = (f"  {payload:<44} "
               f"{('ESCAPES' if escapes(check_then_decode(payload)) else 'blocked'):<13} "
               f"{('ESCAPES' if escapes(decode_then_check(payload)) else 'blocked'):<13} "
               f"{('ESCAPES' if escapes(strip_once(payload)) else 'blocked'):<11} "
               f"{'ESCAPES' if escapes(resolve_and_confine(payload)) else 'blocked'}")
        print(row)

    # Encoding only the separator does not help against a check for '..',
    # because the dots are still literal. Encode the dots too and the raw-string
    # check finds nothing, while the filesystem still resolves the traversal.
    assert not escapes(check_then_decode("..%2f..%2f..%2fetc%2fpasswd")), \
        "literal '..' is still visible to the raw check"
    assert escapes(check_then_decode("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd")), \
        "checking before decoding inspects a string the filesystem never sees"
    assert not escapes(decode_then_check("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"))
    # One decode pass is not enough when the pipeline decodes more than once.
    assert escapes(check_then_decode("%252e%252e%252fetc%252fpasswd"))
    # Removal is not idempotent: the filter rebuilds the sequence it removes.
    assert escapes(strip_once("....//....//etc/passwd"))
    assert not escapes(strip_once("../../etc/passwd")), "the simple form IS removed - hence the false confidence"
    # Resolving and confining is immune to all of them, because it checks the
    # answer rather than the question.
    for payload, _ in payloads:
        assert not escapes(resolve_and_confine(payload)), payload
    print("  -> only the confinement check is order-independent")

    print("\n== 2. zip slip: the same bug with archive member names ==")
    work = Path(tempfile.mkdtemp(prefix="zipslip-"))
    try:
        archive_path = work / "payload.zip"
        dest = work / "dest"
        dest.mkdir()
        (work / "outside").mkdir()

        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("legit.txt", "harmless\n")
            zf.writestr("../outside/escaped.txt", "written outside the destination\n")

        with zipfile.ZipFile(archive_path) as zf:
            names = zf.namelist()
            print(f"  members: {names}")

            # Naive extraction, member by member, joining onto the destination.
            for name in names:
                target = dest / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(name))

            escaped = work / "outside" / "escaped.txt"
            assert escaped.exists(), "the traversing member escaped the destination"
            print(f"  naive extract wrote {escaped}")
            print("  -> outside the destination directory entirely")

            # Checked extraction: resolve each member and require containment.
            shutil.rmtree(dest)
            dest.mkdir()
            escaped.unlink()
            allowed = safe_members(zf, dest)
            print(f"  containment check allows: {allowed}")
            assert allowed == ["legit.txt"], "the traversing member is refused"
            for name in allowed:
                target = (dest / name).resolve()
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(name))
            assert not escaped.exists(), "nothing written outside this time"
            assert (dest / "legit.txt").exists(), "the legitimate member still extracts"
            print("  -> same archive, nothing escapes, legitimate content unaffected")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\n  note: Python 3.12+ provides tarfile.extractall(filter='data'),")
    print("        which applies this check for tar archives by default.")
    print("\nself-test ok")
```

## Variants & pitfalls

- **Over-climb freely.** `../` past the root is a no-op, so too many is safe and too few fails silently.
- **Removal filters reconstruct.** `....//` and `..././` defeat a single strip pass.
- **Decoding layers are invisible from outside.** Test each encoding rung separately to find out how many
  decodes happen and where.
- **A forced suffix beats traversal but not wrappers.** Reach for `php://filter` rather than null bytes.
- **Null bytes died in PHP 5.3.4.** Only relevant on genuinely old targets.
- **Windows is a different ladder.** Backslashes, trailing dots, short names, ADS and UNC.
- **UNC paths make outbound connections** - a traversal on Windows can become credential leakage.
- **`realpath()` returns false for a non-existent path**, so a confinement check built on it must handle the
  "not yet created" case explicitly, or it will reject legitimate writes.
- **Symlink members** defeat member-name checks that do not resolve the final target.
- **Archive extraction in `.docx`/`.jar`/`.apk` handlers** is the same code path with a different extension.
- **The oracle may be a timing or length difference**, not content. Establish it before enumerating.

### Defence / what closes this

Do not build filesystem paths from user input. Map the input to a fixed filename through a hard-coded
allowlist, or use an opaque identifier (a UUID or a database row id) that names the file indirectly - then
traversal has nothing to act on. Where a path must be constructed, use the *resolve-then-confine* pattern:
join, resolve to a canonical absolute path, and verify it is inside the intended directory before opening;
check the answer, never the input. Reject rather than sanitise, and never use removal filters. Decode fully
before validating, and prefer to reject input containing encoded separators outright. On Windows, normalise
with the platform API rather than string operations, and block UNC paths explicitly. For archives, apply the
containment check per member and refuse symlink and absolute members - on Python 3.12+, use
`tarfile.extractall(filter='data')`, and implement the equivalent for zip. Run the application with an OS
user whose filesystem access is limited, and set `open_basedir` (PHP) or equivalent so that a bypass is still
confined.

## Tools

- Burp Intruder - one encoding rung per payload position makes the decode-layer question answerable quickly.
- `ffuf` - traversal wordlists with a length filter to spot the oracle.
- SecLists `Discovery/Web-Content/LFI/` - platform-specific candidate paths.
- `python3 -c "import tarfile; ..."` - check an archive's member names before trusting an extractor.

## References

- OWASP, path traversal: https://owasp.org/www-community/attacks/Path_Traversal
- OWASP Testing Guide, testing directory traversal / file include: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include
- PortSwigger, file path traversal: https://portswigger.net/web-security/file-path-traversal
- Snyk, "Zip Slip" research: https://security.snyk.io/research/zip-slip-vulnerability
- Python docs, `tarfile` extraction filters: https://docs.python.org/3/library/tarfile.html#extraction-filters
- Microsoft, naming files, paths and namespaces: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
- PayloadsAllTheThings, directory traversal: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
