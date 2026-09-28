---
title: "Media Processing - ImageMagick, ffmpeg and Ghostscript as Attack Surface"
category: web
subcategory: upload
type: technique
tags: [imagemagick, imagetragick, policy-xml, delegates-xml, coder, ghostscript, dsafer, ffmpeg, hls, m3u8, concat-demuxer, protocol-whitelist, pdf-pipeline, thumbnail, file-read, ssrf, exiftool, identify, upload]
cves: [CVE-2016-3714, CVE-2022-44268, CVE-2018-16509]
difficulty: medium
summary: "Handing an uploaded file to a media library invokes a parser stack with more reach than the format suggests - delegates, demuxers and PostScript interpreters."
when_to_use:
  - "An upload is resized, thumbnailed, converted, or has metadata read from it"
  - "The application generates previews for PDFs or videos"
  - "You need to know which policy or version check decides whether a class applies"
  - "Reviewing a media pipeline for what it actually invokes"
related: [upload-to-rce, ssrf-fundamentals, xxe-full]
tools: [imagemagick, ffmpeg, ghostscript, exiftool]
---

## TL;DR

"It is only a thumbnail" understates what happens. ImageMagick dispatches to external programs based on file
content, ffmpeg's demuxers follow references to other files and URLs, and Ghostscript is a full PostScript
interpreter. In each case the reach comes from a documented feature of the tool, and in each case the control
is a **policy or flag**, not the file format. So the useful work is establishing which version is installed
and what its policy permits.

## Recognise it

- Uploads come back resized, cropped, converted, or with a generated thumbnail.
- The application shows EXIF data, dimensions, duration or page count.
- PDF uploads render a preview image.
- Video uploads produce a poster frame or a transcoded copy.
- Error output leaking a tool's name: `convert: no decode delegate`, `gs: Unrecoverable error`,
  `ffmpeg version 4.x`, `identify: unable to open image`.
- Response timing that scales with the file, indicating real processing rather than a stored blob.

## Theory

### ImageMagick: delegates and coders

ImageMagick decides how to handle a file by inspecting its content, not its extension. For formats it does
not decode natively, it consults `delegates.xml`, which maps a format to an **external command line**. That
is the design: PDF is handed to Ghostscript, some vector formats to other tools.

Two historically important consequences:

- **ImageTragick (CVE-2016-3714, 2016).** Several coders, notably `https`/`ephemeral`/`msl`/`mvg`, took
  values out of the file and interpolated them into a delegate command line without adequate escaping. A file
  whose content named a crafted "URL" therefore influenced the command that got executed. The class is
  *command construction from file content*, and the fix was both escaping and a shipped `policy.xml` that
  disables those coders.
- **CVE-2022-44268.** The PNG encoder honoured a `profile` directive naming a local file, embedding that
  file's contents into the output image's metadata. Processing an image therefore leaked a server-side file
  into the *result* - which the application then serves back to the uploader. This is an arbitrary file read
  with no command execution at all, and a good illustration that "the tool did exactly what it documents" is
  often the whole vulnerability.

`policy.xml` is the real control surface. It lists rights per coder, per delegate, per path and per resource:

```xml
<policymap>
  <policy domain="coder" rights="none" pattern="{PS,PS2,PS3,EPS,PDF,XPS}"/>
  <policy domain="delegate" rights="none" pattern="*"/>
  <policy domain="path" rights="none" pattern="@*"/>
</policymap>
```

Reading it tells you immediately whether the PDF/PostScript path (and therefore Ghostscript) is reachable,
whether delegates run at all, and whether `@file` indirection is permitted. The `@*` path policy matters
because `@filename` syntax in several ImageMagick arguments means "read this value from a file".

Note the ordering rule: policies are evaluated in order and the *first* match wins, so a broad allow above a
narrow deny defeats the deny. A policy file is not safe merely because the right line appears somewhere in it.

### ffmpeg: demuxers that follow references

Several container formats are **playlists or manifests**: they describe where the media actually lives rather
than containing it.

- **HLS (`.m3u8`)** lists segment URIs. A segment URI can be a local path.
- **The concat demuxer** takes a text file listing input files to join.

When ffmpeg processes such a file, it opens what the manifest names. If a manifest names `file:///etc/passwd`,
that file's bytes are read and muxed into the output. When the application then hands the transcoded output
back to the uploader - as a video, or as a rendered frame - the file contents come with it. The same mechanism
pointed at an `http://` URL is server-side request forgery from the media server's network position.

The control is `-protocol_whitelist`, which restricts which protocols the demuxer may use. The defaults have
tightened over the years, and modern ffmpeg is considerably more restrictive, but pipelines that explicitly
widen the whitelist (often to make a legitimate HLS feature work) reopen it. The version and the exact
invocation both matter, which is why reading the command line the application builds is the highest-value
step.

An important framing point: the file that triggers this does not have to look like a playlist to the
application. Container detection is content-based, so a file uploaded as `movie.mp4` is processed as whatever
its content says it is.

### Ghostscript: a PostScript interpreter

PostScript is a programming language, and Ghostscript executes it. The `-dSAFER` flag exists to restrict file
and command access, and the history of the class is essentially a sequence of sandbox escapes from it:
CVE-2018-16509 and CVE-2019-6116 are two well-known examples, both operating by reaching a privileged operator
that `-dSAFER` failed to restrict.

Two things make this matter more than it might:

1. **ImageMagick delegates PDF handling to Ghostscript.** So a PDF uploaded to an image-processing pipeline
   reaches the PostScript interpreter, and a `policy.xml` that permits the `PDF` coder is what allows it.
2. **`-dSAFER` became the default in Ghostscript 9.50.** Before that, pipelines had to opt in, and many did
   not. The version is therefore a genuine branch point.

### The shape shared by all three

Each of these is a program doing what it documents: ImageMagick dispatches to helpers, ffmpeg resolves
manifests, Ghostscript interprets a language. None is a memory-corruption bug. The vulnerability is
architectural - untrusted input is handed to an engine whose reach exceeds the task - and consequently the
fix is architectural too: restrict the engine's rights, or do not use that engine for untrusted input.

### Fingerprinting: what to establish

Before reasoning about any of this, establish the stack. These are the checks worth running (locally, or
inferring from application behaviour and error strings):

```sh
# Which ImageMagick, and which delegates were compiled in
convert --version
convert -list delegate
convert -list policy          # the effective policy, merged from all policy.xml files

# Where the policy files live (distributions ship more than one)
find / -name policy.xml 2>/dev/null

# ffmpeg version and the protocols it supports
ffmpeg -version
ffmpeg -protocols

# Ghostscript version - 9.50+ defaults to -dSAFER
gs --version

# What the file actually is, as the tools see it (content, not extension)
identify -verbose sample.jpg | head -40
exiftool sample.jpg
```

`convert -list policy` is the single most informative command here, because it shows the *merged, effective*
policy rather than one file's contents.

## Attack

1. **Establish that processing happens**, and what kind: resize, metadata read, preview render, transcode.
2. **Identify the tool and version** from error strings, output metadata (ImageMagick writes its version into
   output files unless stripped), or response behaviour.
3. **Determine the policy.** If you can read files by some other means, `policy.xml` answers most of the
   remaining questions.
4. **Work out whether output returns to you.** The file-read classes depend on getting the processed result
   back; a pipeline that discards the output is a much weaker target.
5. **Check whether format detection is content-based** - upload a file whose extension and content disagree
   and see which one the pipeline believes.
6. **Consider the SSRF framing.** A media server that fetches URLs has a network position; see
   `ssrf-fundamentals`.

## Code

A `policy.xml` auditor. It parses ImageMagick's policy file, applies the first-match-wins ordering, and
reports which risky coders and delegates remain permitted - the check that decides whether any of the
ImageMagick or Ghostscript classes apply at all.

```python
#!/usr/bin/env python3
"""Audit an ImageMagick policy.xml for the coders and rights that matter.

Applies first-match-wins ordering across policy entries, expands brace patterns,
and reports which risky coders/delegates remain permitted, plus which classes
each finding corresponds to.

Stdlib only; parses XML text. No network, no ImageMagick required.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

# Coders whose reach exceeds "decode an image".
RISKY_CODERS = {
    "PS": "PostScript - dispatched to Ghostscript",
    "PS2": "PostScript - dispatched to Ghostscript",
    "PS3": "PostScript - dispatched to Ghostscript",
    "EPS": "encapsulated PostScript - dispatched to Ghostscript",
    "PDF": "PDF - dispatched to Ghostscript (CVE-2018-16509 class)",
    "XPS": "XPS - external delegate",
    "MSL": "Magick Scripting Language - scripted operations from file content",
    "MVG": "Magick Vector Graphics - ImageTragick (CVE-2016-3714) class",
    "EPHEMERAL": "deletes after read - ImageTragick class",
    "URL": "fetches a URL - server-side request forgery",
    "HTTPS": "fetches a URL - ImageTragick class",
    "HTTP": "fetches a URL - server-side request forgery",
    "TEXT": "renders text files - can disclose file contents",
    "SHOW": "displays via an external program",
    "WIN": "external program",
    "PLT": "external delegate",
}


@dataclass
class Finding:
    severity: str
    subject: str
    detail: str

    def __str__(self) -> str:
        return f"  [{self.severity:<8}] {self.subject:<12} {self.detail}"


def expand(pattern: str) -> list[str]:
    """Expand ImageMagick's brace syntax: '{PS,PDF}' -> ['PS', 'PDF']."""
    match = re.fullmatch(r"\{([^}]*)\}", pattern.strip())
    if match:
        return [p.strip() for p in match.group(1).split(",") if p.strip()]
    return [pattern.strip()]


def parse_policy(xml_text: str) -> list[dict[str, str]]:
    """Return policy entries in document order."""
    root = ET.fromstring(xml_text)
    entries: list[dict[str, str]] = []
    for element in root.iter("policy"):
        entries.append({
            "domain": (element.get("domain") or "").lower(),
            "rights": (element.get("rights") or "").lower(),
            "pattern": element.get("pattern") or "",
            "name": element.get("name") or "",
        })
    return entries


def effective_rights(entries: list[dict[str, str]], domain: str, coder: str) -> str:
    """First matching policy wins - a broad allow above a narrow deny defeats it."""
    for entry in entries:
        if entry["domain"] != domain:
            continue
        for pattern in expand(entry["pattern"]):
            if pattern == "*" or pattern.upper() == coder.upper():
                return entry["rights"] or "none"
    return "default-allow"


def audit(xml_text: str) -> list[Finding]:
    entries = parse_policy(xml_text)
    findings: list[Finding] = []

    for coder, why in sorted(RISKY_CODERS.items()):
        rights = effective_rights(entries, "coder", coder)
        if rights in ("none",):
            continue
        severity = "high" if coder in {"MSL", "MVG", "EPHEMERAL", "HTTPS", "URL", "HTTP"} else "medium"
        state = "unrestricted (no matching policy)" if rights == "default-allow" else f"rights={rights}"
        findings.append(Finding(severity, coder, f"{state} - {why}"))

    delegate = effective_rights(entries, "delegate", "*")
    if delegate != "none":
        findings.append(Finding("high", "delegate",
                                "external delegate programs permitted - the ImageTragick dispatch path"))

    path = effective_rights(entries, "path", "@*")
    if path != "none":
        findings.append(Finding("medium", "path",
                                "'@*' indirection permitted - arguments can be read from local files"))

    if not any(e["domain"] == "resource" for e in entries):
        findings.append(Finding("low", "resource",
                                "no resource limits - decompression bombs are unbounded"))

    findings.sort(key=lambda f: {"high": 0, "medium": 1, "low": 2}[f.severity])
    return findings


PERMISSIVE = """<policymap>
  <policy domain="resource" name="memory" value="256MiB"/>
</policymap>"""

PARTIAL = """<policymap>
  <policy domain="coder" rights="none" pattern="{PS,EPS}"/>
  <policy domain="resource" name="memory" value="256MiB"/>
</policymap>"""

MISORDERED = """<policymap>
  <policy domain="coder" rights="read|write" pattern="*"/>
  <policy domain="coder" rights="none" pattern="{PS,PS2,PS3,EPS,PDF,XPS,MSL,MVG,EPHEMERAL,URL,HTTPS,HTTP}"/>
  <policy domain="delegate" rights="none" pattern="*"/>
</policymap>"""

HARDENED = """<policymap>
  <policy domain="coder" rights="none" pattern="{PS,PS2,PS3,EPS,PDF,XPS}"/>
  <policy domain="coder" rights="none" pattern="{MSL,MVG,EPHEMERAL,URL,HTTPS,HTTP,TEXT,SHOW,WIN,PLT}"/>
  <policy domain="delegate" rights="none" pattern="*"/>
  <policy domain="path" rights="none" pattern="@*"/>
  <policy domain="resource" name="memory" value="256MiB"/>
  <policy domain="resource" name="width" value="16KP"/>
</policymap>"""


if __name__ == "__main__":
    for name, xml_text in [("no policy at all", PERMISSIVE),
                           ("partial (PS/EPS only)", PARTIAL),
                           ("misordered - allow before deny", MISORDERED),
                           ("hardened", HARDENED)]:
        findings = audit(xml_text)
        print(f"\n== {name} == ({len(findings)} findings)")
        for finding in findings:
            print(finding)
        if not findings:
            print("  (no risky coder or delegate permitted)")

    # An empty policy leaves every risky coder reachable.
    permissive = audit(PERMISSIVE)
    assert len(permissive) >= len(RISKY_CODERS), "nothing is restricted"
    assert any(f.subject == "PDF" for f in permissive), "PDF reaches Ghostscript"
    assert any(f.subject == "delegate" for f in permissive)

    # Disabling PS/EPS but not PDF leaves the Ghostscript path open - the most
    # common real-world half-fix.
    partial = audit(PARTIAL)
    subjects = {f.subject for f in partial}
    assert "PS" not in subjects and "EPS" not in subjects, "those two are closed"
    assert "PDF" in subjects, "but PDF still dispatches to Ghostscript"
    assert "MSL" in subjects and "MVG" in subjects

    # First-match-wins: a broad allow above the deny defeats every line below it.
    misordered = audit(MISORDERED)
    assert any(f.subject == "PDF" for f in misordered), \
        "the 'rights=read|write pattern=*' line above the denies wins"
    assert any(f.subject == "MVG" for f in misordered)
    print("\n  note: the misordered policy contains the correct deny lines and is still open,")
    print("        because an earlier entry matched first.")

    # A correctly ordered, complete policy closes the modelled classes.
    assert audit(HARDENED) == [], [str(f) for f in audit(HARDENED)]

    print("\nself-test ok")
```

## Variants & pitfalls

- **Extension is irrelevant.** These tools detect format from content, so the upload filter's view of the
  file and the processor's view can differ entirely.
- **Distributions ship several `policy.xml` files** and merge them. `convert -list policy` shows the
  effective result; reading one file can mislead.
- **First match wins.** A policy containing all the right deny lines can still be open if a broad allow
  precedes them.
- **Version is the branch point.** ImageMagick 7 ships a restrictive default policy; Ghostscript 9.50+
  defaults to `-dSAFER`; modern ffmpeg restricts protocols by default. An old pinned container is the
  interesting case.
- **The output has to come back to you** for the file-read classes to yield anything.
- **ImageMagick writes its version into output metadata** unless stripped - a free fingerprint.
- **Decompression bombs** are the reliable denial-of-service in this area, and `resource` policies are the
  control.
- **`exiftool` had its own command-injection history** (DjVu parsing); any metadata tool in the pipeline is
  part of the surface.
- **A pipeline that shells out** with a filename in the command line is a separate and simpler problem - see
  `cmdi-injection-and-bypass`.

### Defence / what closes this

Do not hand untrusted files to a general-purpose media engine. Prefer a narrow, memory-safe decoder for the
specific formats you accept, decode to a raster, and re-encode from pixel data. If ImageMagick is required,
deploy a restrictive `policy.xml` with `rights="none"` for the PS/EPS/PDF/XPS/MSL/MVG/EPHEMERAL/URL/HTTP(S)
coders, `delegate` rights of `none`, `path` rights of `none` for `@*`, and resource limits for width, height,
memory and time - then verify it with `convert -list policy`, ordering denies before any broad allow. For
ffmpeg, pass an explicit `-protocol_whitelist` limited to `file` (or less) and reject playlist/manifest
container formats outright unless the feature needs them. For PDFs, use Ghostscript 9.50+ so `-dSAFER` is the
default, or avoid Ghostscript entirely. Run the whole pipeline as an unprivileged user in a container with no
network egress and a read-only filesystem apart from a scratch directory, so a successful escape reaches
nothing. Process asynchronously, off the request path, with CPU and memory limits. Keep every component
patched - this is one area where the CVE stream is the primary control.

## Tools

- `convert -list policy` / `convert -list delegate` - the effective ImageMagick configuration.
- `identify -verbose` - what ImageMagick believes a file is.
- `ffmpeg -protocols` / `ffmpeg -version` - which protocols the build supports.
- `gs --version` - the `-dSAFER` default branch point.
- `exiftool` - metadata inspection and stripping.

## References

- ImageMagick, security policy documentation: https://imagemagick.org/script/security-policy.php
- ImageMagick, `policy.xml` reference: https://imagemagick.org/script/resources.php
- CVE-2016-3714 (ImageTragick): https://nvd.nist.gov/vuln/detail/CVE-2016-3714
- ImageTragick advisory site: https://imagetragick.com/
- CVE-2022-44268 (ImageMagick PNG profile file read): https://nvd.nist.gov/vuln/detail/CVE-2022-44268
- CVE-2018-16509 (Ghostscript -dSAFER bypass): https://nvd.nist.gov/vuln/detail/CVE-2018-16509
- Ghostscript documentation, `-dSAFER` and file access: https://ghostscript.readthedocs.io/en/latest/Use.html
- FFmpeg documentation, protocols and `-protocol_whitelist`: https://ffmpeg.org/ffmpeg-protocols.html
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
