---
title: "Corporate, Document and Code OSINT"
category: osint
subcategory: documents
type: technique
tags: [osint, exiftool, docprops, ooxml, pdf-metadata, github-dorking, gitleaks, trufflehog, secret-scanning, job-listings, npm, pypi, s3-bucket, ci-logs, code-leak]
difficulty: medium
summary: "Published files carry author names and paths, job ads describe the stack, and code forges leak secrets in history, logs and package metadata."
when_to_use:
  - "The challenge gives you a PDF, DOCX, XLSX or PPTX and asks who made it"
  - "You must find a secret committed to a public repository"
  - "You need to work out an organisation's technology stack from public sources"
  - "A package, a CI log or a bucket name is the pivot"
tools: [exiftool, unzip, pdfinfo, oletools, gitleaks, trufflehog, git, curl, jq]
related: [osint-methodology, osint-people-pivoting, osint-infrastructure, git-data-recovery, osint-tools-cheatsheet, metadata-hiding]
---

## TL;DR

Documents leak the author's username, their software, their directory paths and often their
printer. Code forges leak secrets in **history** (not just the current tree), in CI logs, in
package manifests and in maintainer email addresses. Job listings leak the entire technology
stack in plain English.

## Recognise it

- A PDF/DOCX attached to a challenge with no obvious content clue.
- "Who is the author of this report?", "what internal path does this reveal?"
- A GitHub organisation or a personal repository referenced anywhere in the challenge.
- A package name on npm/PyPI that matches the challenge's theme.
- An error page or a JS bundle mentioning an S3/GCS bucket.

## Document metadata

```bash
# the universal first command
exiftool -a -u -g1 report.pdf
exiftool -a -u -g1 report.docx

# PDF specifics
pdfinfo report.pdf
exiftool -Creator -Producer -Author -Title -Subject -Keywords -CreateDate -ModifyDate report.pdf
# the XMP stream, which often has more than /Info
exiftool -xmp -b report.pdf > report.xmp
# incremental updates: a PDF saved repeatedly keeps every previous revision
grep -aoba '%%EOF' report.pdf          # more than one = incremental updates -> older content
qpdf --qdf --object-streams=disable report.pdf out.pdf && grep -a '/Author' out.pdf
pdftotext -layout report.pdf - | head -50
pdfimages -list report.pdf             # embedded images, which have their own metadata
```

```bash
# OOXML (docx/xlsx/pptx) is a zip - look inside it
unzip -l report.docx
unzip -p report.docx docProps/core.xml     # dc:creator, cp:lastModifiedBy, revision, dates
unzip -p report.docx docProps/app.xml      # Application, Company, Template, TotalTime
unzip -p report.docx docProps/custom.xml
unzip -p report.docx word/document.xml | head -c 2000
# hyperlinks, including internal file:// paths
unzip -p report.docx word/_rels/document.xml.rels
# tracked changes and comments
unzip -p report.docx word/comments.xml
unzip -p report.docx word/people.xml
# embedded media keeps its own EXIF
unzip -o report.docx -d docx_out && exiftool -a -u -g1 docx_out/word/media/*
```

```bash
# legacy Office (.doc/.xls/.ppt) - OLE compound files
olemeta report.doc
oleid report.doc
oledump.py report.doc
# macros
olevba report.doc
```

What to harvest: `dc:creator` and `cp:lastModifiedBy` (usernames), `Company`, `Application`
and its version (software inventory), `TotalTime` (how long it was edited), the template path,
and any `file://` hyperlink (which reveals an internal share or a local user directory).

## Hidden document content

- **Excel**: hidden rows, hidden columns, hidden sheets, and the shared strings table
  (`xl/sharedStrings.xml`) which keeps text even after a cell is cleared.
- **Word**: tracked changes, comments, and text under an image or with white font.
- **PowerPoint**: the notes pane (`ppt/notesSlides/`), and slides moved off the canvas.
- **PDF**: text under a black rectangle is still text - `pdftotext` extracts it. Redaction done
  with a drawing tool is not redaction.

```bash
# the "black box redaction" check
pdftotext -layout report.pdf - | grep -i -A3 'redacted\|confidential'
# hidden sheets in xlsx
unzip -p book.xlsx xl/workbook.xml | grep -o 'state="[^"]*"'
unzip -p book.xlsx xl/sharedStrings.xml | head -c 3000
```

## Job listings and public pages

A careers page is a free technology inventory:

- Named products (specific database, cloud, CI, EDR, ticketing system) and their versions.
- Team structure and reporting lines.
- Office locations and timezones.
- The ATS the listing is hosted on, which is itself a subdomain.
- Employee names in "meet the team" pages, conference talks and press releases.

Also check: `security.txt`, status pages, public API documentation, the sitemap, RSS feeds,
SSL certificate subject fields, and the organisation's public cloud-provider marketplace
listings.

## Code forge OSINT

### Search qualifiers

```text
org:exampleorg            user:exampleuser         repo:owner/name
path:.github/workflows    filename:.env            extension:pem
language:python           in:file  in:path  in:name
created:>2026-01-01       pushed:>2026-01-01       size:<1000
is:public  is:fork  archived:false
```

Combine a qualifier with a secret-shaped keyword:

```text
org:exampleorg AKIA                       org:exampleorg "BEGIN RSA PRIVATE KEY"
org:exampleorg filename:.env              org:exampleorg "api_key"
org:exampleorg extension:pem              org:exampleorg "xoxb-"
org:exampleorg path:.github "secrets."    org:exampleorg "password" language:yaml
user:exampleuser filename:id_rsa          user:exampleuser "Authorization: Bearer"
```

### The history matters more than the tree

```bash
git clone --mirror https://github.com/owner/repo && cd repo.git
git log --all --oneline | wc -l
git log -p --all -S 'AKIA'                 # commits that ADDED or REMOVED that string
git log -p --all -G 'BEGIN .*PRIVATE KEY'
git log --all --diff-filter=D --name-only  # files that were deleted
git rev-list --objects --all | wc -l
git fsck --full --unreachable --dangling   # objects no branch points at
git cat-file -p <sha>
git log --format='%ae %an' | sort -u       # every author identity
```

```bash
# automated secret scanners over the full history
gitleaks detect --source . --report-format json --report-path leaks.json
gitleaks detect --source . --log-opts='--all'
trufflehog git file://. --json
trufflehog github --org=exampleorg --json
```

### The other leak surfaces

- **GitHub Actions logs and artifacts**: a workflow that echoed an environment variable; logs
  are public for public repositories.
- **Gists**: often forgotten, frequently contain a config file.
- **Forks**: a secret removed from the upstream repository survives in a fork.
- **Package registries**: `npm view <pkg>` and PyPI JSON include maintainer emails, repository
  URLs and every published version - including one that was unpublished from the index but
  still has metadata.
- **Docker images**: layer history (`docker history --no-trunc`) shows build-time `ARG`s and
  `ENV`s; `.git` directories sometimes ship inside the image.
- **Source maps** (`.js.map`) reconstruct the original source of a bundled front end.

```bash
npm view express                          # maintainers, repository, versions, dist tags
curl -s https://registry.npmjs.org/express | jq '.maintainers, .repository'
curl -s https://pypi.org/pypi/requests/json | jq '.info.author_email, .info.project_urls'
docker history --no-trunc image:tag
curl -s https://example.com/static/app.js.map | jq -r '.sources[]' | head -30
```

## Cloud bucket naming

Organisations name buckets predictably: `<org>-backup`, `<org>-assets`, `<org>-prod-data`,
`<org>.<domain>`, `<project>-static`. Generate and test the obvious permutations **passively**
(a HEAD request to a public endpoint is not an attack, but respect the event's scope).

```bash
# S3 style endpoints
curl -sI https://example-backup.s3.amazonaws.com/
curl -s  https://example-backup.s3.amazonaws.com/?list-type=2 | head -c 500
# GCS
curl -s  https://storage.googleapis.com/example-backup
# Azure
curl -s  'https://example.blob.core.windows.net/backup?restype=container&comp=list'
```

## Code

```python
#!/usr/bin/env python3
"""Document and code OSINT helpers: OOXML metadata, secret scanning, dork and
bucket-name generation.

  python3 doccode.py meta report.docx
  python3 doccode.py scan /path/to/repo
  python3 doccode.py dorks exampleorg
  python3 doccode.py buckets example example.com
  python3 doccode.py --selftest
"""
from __future__ import annotations

import os
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

# --------------------------------------------------------------------------- #
# OOXML metadata
# --------------------------------------------------------------------------- #
OOXML_PROP_FILES = ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml")


def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def ooxml_metadata(path: str) -> dict[str, str]:
    """Every docProps field from a docx/xlsx/pptx, with namespaces stripped."""
    out: dict[str, str] = {}
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        for prop in OOXML_PROP_FILES:
            if prop not in names:
                continue
            try:
                root = ET.fromstring(zf.read(prop))
            except ET.ParseError:
                continue
            for child in root.iter():
                if child is root:
                    continue
                text = (child.text or "").strip()
                if text:
                    out[f"{os.path.basename(prop)}:{strip_ns(child.tag)}"] = text
    return out


def ooxml_extras(path: str) -> dict[str, list[str]]:
    """Hyperlinks (including file:// paths), hidden sheets and embedded media."""
    out: dict[str, list[str]] = {"hyperlinks": [], "hidden_sheets": [], "media": [],
                                 "comments": []}
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if name.startswith(("word/media/", "xl/media/", "ppt/media/")):
                out["media"].append(name)
            if name.endswith(".rels"):
                try:
                    root = ET.fromstring(zf.read(name))
                except ET.ParseError:
                    continue
                for rel in root:
                    target = rel.attrib.get("Target", "")
                    if target.startswith(("http://", "https://", "file://", "mailto:",
                                          "\\\\")):
                        out["hyperlinks"].append(target)
            if name == "xl/workbook.xml":
                text = zf.read(name).decode("utf-8", "replace")
                for m in re.finditer(r'<sheet[^>]*name="([^"]+)"[^>]*state="(hidden|veryHidden)"',
                                     text):
                    out["hidden_sheets"].append(f"{m.group(1)} ({m.group(2)})")
            if name in ("word/comments.xml", "ppt/comments.xml"):
                try:
                    root = ET.fromstring(zf.read(name))
                except ET.ParseError:
                    continue
                for node in root.iter():
                    if (node.text or "").strip():
                        out["comments"].append(node.text.strip())
    return out


# --------------------------------------------------------------------------- #
# secret scanning
# --------------------------------------------------------------------------- #
SECRET_PATTERNS: dict[str, re.Pattern] = {
    "aws-access-key-id": re.compile(rb"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    "aws-secret-hint": re.compile(rb"(?i)aws_?secret_?access_?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    "github-token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack-token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "google-api-key": re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"),
    "stripe-key": re.compile(rb"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "private-key-block": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(rb"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "generic-password": re.compile(rb"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s]{6,})"),
    "generic-api-key": re.compile(rb"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|token)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})"),
    "connection-string": re.compile(rb"(?i)\b(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"]{8,}"),
    "slack-webhook": re.compile(rb"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    "email": re.compile(rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
             ".mypy_cache", ".pytest_cache", "vendor"}


def scan_bytes(data: bytes) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(data):
            value = (m.group(1) if m.groups() else m.group(0))
            hits.append((name, value.decode("utf-8", "replace")))
    return hits


def scan_tree(root: str, max_file_bytes: int = 2_000_000) -> list[tuple[str, str, str]]:
    """Return (path, kind, value) for every match in a directory tree."""
    out: list[tuple[str, str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > max_file_bytes:
                    continue
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            for kind, value in scan_bytes(data):
                out.append((path, kind, value))
    return out


# --------------------------------------------------------------------------- #
# dorks and bucket names
# --------------------------------------------------------------------------- #
SECRET_KEYWORDS = ["AKIA", "BEGIN RSA PRIVATE KEY", "api_key", "apikey", "secret",
                   "password", "token", "xoxb-", "connectionstring", "client_secret"]
SECRET_FILENAMES = [".env", "id_rsa", "credentials", "config.json", "settings.py",
                    "secrets.yml", "docker-compose.yml", ".npmrc", ".pypirc", "wp-config.php"]
SECRET_EXTENSIONS = ["pem", "key", "pfx", "p12", "kdbx", "ovpn", "sql", "bak"]


def code_dorks(scope: str, scope_kind: str = "org") -> list[str]:
    """GitHub code-search queries for an org or a user."""
    prefix = f"{scope_kind}:{scope} "
    out = [prefix + f'"{k}"' for k in SECRET_KEYWORDS]
    out += [prefix + f"filename:{f}" for f in SECRET_FILENAMES]
    out += [prefix + f"extension:{e}" for e in SECRET_EXTENSIONS]
    out += [
        prefix + 'path:.github/workflows "secrets."',
        prefix + '"Authorization: Bearer"',
        prefix + '"-----BEGIN OPENSSH PRIVATE KEY-----"',
        prefix + 'language:yaml password',
        prefix + 'filename:.git-credentials',
    ]
    return out


BUCKET_SUFFIXES = ["", "-backup", "-backups", "-assets", "-static", "-data", "-prod",
                   "-production", "-dev", "-staging", "-test", "-uploads", "-media",
                   "-logs", "-public", "-private", "-files", "-images", "-archive",
                   "-cdn", "-www", "-internal"]


def bucket_names(org: str, domain: str | None = None) -> list[str]:
    base = re.sub(r"[^a-z0-9-]", "", org.lower())
    names = [base + s for s in BUCKET_SUFFIXES]
    names += ["backup-" + base, "assets-" + base, "static-" + base]
    if domain:
        d = domain.lower()
        names += [d, d.replace(".", "-"), base + "." + d]
    seen: set[str] = set()
    out = []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def bucket_urls(name: str) -> list[str]:
    return [
        f"https://{name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{name}/",
        f"https://storage.googleapis.com/{name}",
        f"https://{name}.blob.core.windows.net/?comp=list",
    ]


# --------------------------------------------------------------------------- #
def main(argv: list[str]) -> int:
    if not argv or argv[0] == "--selftest":
        _selftest()
        return 0
    cmd = argv[0]
    if cmd == "meta":
        for k, v in sorted(ooxml_metadata(argv[1]).items()):
            print(f"{k:<34} {v}")
        for k, vals in ooxml_extras(argv[1]).items():
            for v in vals:
                print(f"{k:<34} {v}")
    elif cmd == "scan":
        for path, kind, value in scan_tree(argv[1]):
            shown = value if len(value) < 70 else value[:67] + "..."
            print(f"{kind:<22} {shown:<72} {path}")
    elif cmd == "dorks":
        kind = argv[2] if len(argv) > 2 else "org"
        for d in code_dorks(argv[1], kind):
            print(d)
    elif cmd == "buckets":
        domain = argv[2] if len(argv) > 2 else None
        for n in bucket_names(argv[1], domain):
            print(n)
    else:
        print(__doc__)
        return 1
    return 0


def _build_docx(path: str) -> None:
    """Build a minimal OOXML file with metadata, a file:// hyperlink and a hidden sheet."""
    core = ('<?xml version="1.0"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
            'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
            '<dc:creator>j.mendel</dc:creator>'
            '<cp:lastModifiedBy>admin</cp:lastModifiedBy>'
            '<dc:title>Quarterly Report</dc:title>'
            '</cp:coreProperties>')
    app = ('<?xml version="1.0"?>'
           '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/'
           'extended-properties">'
           '<Application>Microsoft Office Word</Application>'
           '<Company>Example Inc</Company><TotalTime>42</TotalTime>'
           '</Properties>')
    rels = ('<?xml version="1.0"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
            '2006/relationships/hyperlink" Target="file:///S:/finance/secret.xlsx"/>'
            '</Relationships>')
    workbook = ('<?xml version="1.0"?><workbook><sheets>'
                '<sheet name="Summary" sheetId="1" state="visible"/>'
                '<sheet name="Raw Salaries" sheetId="2" state="hidden"/>'
                '</sheets></workbook>')
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("docProps/core.xml", core)
        zf.writestr("docProps/app.xml", app)
        zf.writestr("word/_rels/document.xml.rels", rels)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("word/media/image1.png", b"\x89PNG\r\n\x1a\n")


def _selftest() -> None:
    import tempfile

    tmp = tempfile.mkdtemp(prefix="doccode_")

    # --- OOXML metadata ----------------------------------------------------
    docx = os.path.join(tmp, "report.docx")
    _build_docx(docx)
    meta = ooxml_metadata(docx)
    assert meta.get("core.xml:creator") == "j.mendel", meta
    assert meta.get("core.xml:lastModifiedBy") == "admin", meta
    assert meta.get("app.xml:Company") == "Example Inc", meta
    assert meta.get("app.xml:TotalTime") == "42", meta

    extras = ooxml_extras(docx)
    assert "file:///S:/finance/secret.xlsx" in extras["hyperlinks"], extras
    assert any("Raw Salaries" in s for s in extras["hidden_sheets"]), extras
    assert "word/media/image1.png" in extras["media"], extras

    # --- secret scanning ---------------------------------------------------
    sample = (b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
              b"github_token = ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
              b"password: 'hunter2hunter2'\n"
              b"DATABASE_URL=postgres://user:pw@db.internal:5432/app\n"
              b"-----BEGIN RSA PRIVATE KEY-----\n"
              b"contact: dev@example.com\n"
              b"slack=xox[REDACTED]\n"
              b"nothing to see on this line\n")
    kinds = {k for k, _ in scan_bytes(sample)}
    for expected in ("aws-access-key-id", "github-token", "generic-password",
                     "connection-string", "private-key-block", "email", "slack-token"):
        assert expected in kinds, (expected, kinds)
    values = dict(scan_bytes(sample))
    assert values["aws-access-key-id"] == "AKIAIOSFODNN7EXAMPLE"
    assert values["generic-password"] == "hunter2hunter2"
    assert scan_bytes(b"this file has no secrets in it at all") == []

    # tree scanning skips the noise directories
    src = os.path.join(tmp, "repo")
    os.makedirs(os.path.join(src, "node_modules"), exist_ok=True)
    with open(os.path.join(src, "config.py"), "wb") as fh:
        fh.write(sample)
    with open(os.path.join(src, "node_modules", "junk.js"), "wb") as fh:
        fh.write(b"AKIAIOSFODNN7EXAMPLE")
    found = scan_tree(src)
    assert any(p.endswith("config.py") for p, _k, _v in found)
    assert not any("node_modules" in p for p, _k, _v in found), found

    # --- dorks -------------------------------------------------------------
    dorks = code_dorks("exampleorg")
    assert 'org:exampleorg "AKIA"' in dorks, dorks[:3]
    assert "org:exampleorg filename:.env" in dorks
    assert "org:exampleorg extension:pem" in dorks
    assert any("path:.github/workflows" in d for d in dorks)
    user_dorks = code_dorks("someone", "user")
    assert all(d.startswith("user:someone ") for d in user_dorks)

    # --- buckets -----------------------------------------------------------
    names = bucket_names("Example Inc", "example.com")
    assert "exampleinc" in names and "exampleinc-backup" in names, names[:5]
    assert "example.com" in names and "example-com" in names, names
    assert len(names) == len(set(names))
    urls = bucket_urls("exampleinc-backup")
    assert any("s3.amazonaws.com" in u for u in urls)
    assert any("storage.googleapis.com" in u for u in urls)
    assert any("blob.core.windows.net" in u for u in urls)

    print(f"selftest ok: docProps ({len(meta)} fields), hyperlink and hidden sheet found, "
          f"{len(kinds)} secret kinds matched, {len(dorks)} dorks, {len(names)} bucket names")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

## Variants and pitfalls

- **`exiftool -a -u -g1` before anything else.** It reads OOXML, PDF, OLE and media in one
  command.
- **`cp:lastModifiedBy` is the most useful single field**: it is a username on the machine that
  last saved the file, and it survives most "clean document" workflows.
- **PDF incremental updates** mean older content is still in the file. More than one `%%EOF` is
  the tell; `qpdf --qdf` normalises the file so you can read the earlier objects.
- **Black rectangles are not redaction.** `pdftotext` recovers the text underneath.
- **The current tree is not the repository.** Always search the full history (`git log -S`,
  `--all`), the forks, the gists and the CI logs.
- **A rotated secret is still a finding in a CTF** - the flag may be the old value.
- **Regex secret scanners produce false positives.** Verify format-specific constraints (an
  AWS key id is exactly 20 characters starting with `AKIA`/`ASIA`).
- **Do not use a discovered credential.** Finding it is OSINT; using it against a real service
  is an intrusion and almost certainly out of scope.
- **Bucket enumeration can be noisy.** Keep it to a handful of obvious names, and respect the
  event's scope rules.
- **Package registries keep unpublished metadata.** A version removed from the index often
  still has a JSON record with the maintainer's email.
- **Source maps rebuild the whole front end.** If `.js.map` files are served, you effectively
  have the original source.

## Tools

`exiftool`, `unzip`, `pdfinfo`/`pdftotext`/`pdfimages`/`qpdf` (poppler and qpdf), `oletools`
(`olemeta`, `oleid`, `olevba`, `oledump`), `gitleaks`, `trufflehog`, `git` (especially
`log -S`, `log --all`, `fsck`), `npm view`, the PyPI JSON API, `docker history`, `jq`.

## References

- ExifTool documentation: https://exiftool.org/
- ECMA-376 (Office Open XML) defines the `docProps/core.xml` and `app.xml` property sets.
- gitleaks: https://github.com/gitleaks/gitleaks
- trufflehog: https://github.com/trufflesecurity/trufflehog
- GitHub documentation for code search qualifiers (`org:`, `path:`, `language:` and friends).
