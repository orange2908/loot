---
title: "File Upload - The Validation Layers and What Each Misses"
category: web
subcategory: upload
type: technique
tags: [file-upload, unrestricted-upload, rce, webshell, extension-bypass, mime-type, magic-bytes, getimagesize, polyglot, htaccess, web-config, double-extension, content-type, move-uploaded-file, finfo, race-condition, svg-xss, burp]
difficulty: medium
summary: "Each validation layer answers a different question, and none answers 'will the server execute this' - only the storage decision does."
when_to_use:
  - "An application accepts uploads and you need to know which checks it actually performs"
  - "You are working out why a given upload is or is not reachable as code"
  - "You need the defensive check that closes a specific bypass"
  - "Reviewing upload handling in challenge or application source"
related: [upload-image-processing, lfi-to-rce, lfi-path-traversal, xss-contexts]
tools: [burp, curl, exiftool]
---

## TL;DR

Upload validation is usually a stack of checks, each answering a narrow question: what is the extension, what
did the client claim, what do the first bytes look like, does an image decoder accept it. None of those
questions is "will the web server execute this file", and that is the question that matters. The decisive
controls are **where the file is stored** and **how it is served** - everything else is a delaying action.

## Recognise it

- Any avatar, attachment, import, document or "add a photo" feature.
- The response discloses the stored path, or the file appears at a predictable URL under the web root.
- The filename is preserved rather than replaced with a generated identifier.
- Client-side-only validation - a JavaScript `accept` check, which is not a control at all.
- The application is PHP/JSP/ASP and uploads land under the document root.

## Theory

### The layers, and what each actually verifies

| Layer | Question it answers | What it misses |
|-------|--------------------|----------------|
| Client-side check | did the *browser* like it | everything - the request is attacker-generated |
| Extension denylist | is the suffix on a bad list | every suffix not on the list |
| Extension allowlist | is the suffix on a good list | parsing disagreements about what "the suffix" is |
| `Content-Type` header | what did the client claim | it is a client claim, nothing more |
| Magic bytes / `finfo` | do the first bytes look like type X | the rest of the file |
| `getimagesize()` | does an image parser accept it | that the file can also be valid PHP |
| Image re-encode | does it survive decode-and-re-encode | metadata, if preserved |

Reading down that table, the pattern is that each check validates a *property of the bytes* while the risk
comes from a *property of the storage*. A file is dangerous because the server will hand it to an
interpreter, not because of what is in it.

### Extension handling: where the disagreements live

The interesting failures are all parser disagreements about which part of a filename is the extension:

- **Double extensions**: `shell.php.jpg`. Dangerous when a server is configured to execute on *any* matching
  extension in the name rather than the last one - the historical Apache `AddHandler` behaviour, where
  `.php` anywhere in the name triggered the handler.
- **Reverse double extension**: `shell.jpg.php` - relevant when a denylist checks only the *first* extension.
- **Case**: `.pHP`, `.PhP`. Windows filesystems are case-insensitive, and so is the handler match; a
  case-sensitive denylist is not.
- **Alternate executable suffixes**: `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.pht`, `.phar`,
  `.inc`. The denylist that blocks `.php` and stops there is extremely common. ASP equivalents: `.asp`,
  `.aspx`, `.asa`, `.cer`, `.cdx`. JSP: `.jsp`, `.jspx`, `.jsw`, `.jsv`.
- **Trailing dot or space**: `shell.php.` and `shell.php ` - the Win32 path normaliser strips both, so the
  stored file is `shell.php` while the validated string was not. Same mechanism as in `lfi-path-traversal`.
- **Null byte**: `shell.php%00.jpg` - historical, fixed in PHP 5.3.4 and in most other stacks.
- **Alternate data streams**: `shell.php::$DATA` on IIS/NTFS.
- **Path in the filename**: `../../../var/www/html/shell.php` - if the filename is joined onto a directory
  without confinement, this is path traversal and the extension check is beside the point.

### Content-Type and magic bytes

`Content-Type` in a multipart part is supplied by the client. It is not evidence. Changing it in a proxy is
a single edit.

Magic bytes are more interesting, because they are a real property of the file - but "the first bytes look
like a GIF" and "this file is a valid PHP script" are not mutually exclusive. A file beginning with `GIF89a`
followed by PHP source satisfies a magic-byte check and is still executed as PHP when the server routes it
to the interpreter, because the interpreter passes through everything outside `<?php ... ?>` tags as literal
output. The same reasoning applies to `getimagesize()`: it parses a header, not the whole file.

This is the general shape of a **polyglot** - a file that is simultaneously valid in two formats because each
format's parser ignores what the other cares about. Image formats with comment or metadata fields make this
easy, since the payload can live in a field the image parser is required to skip.

### Image re-encoding

Decoding an image and re-encoding it from pixel data is genuinely effective, because the output is generated
from the decoded raster and any non-pixel content is discarded. The caveats:

- Metadata is often **deliberately preserved** (EXIF, comments) for legitimate reasons. If so, a payload in
  those fields survives.
- Re-encoding is only as safe as the decoder. Handing an untrusted file to an image library is itself
  attack surface - see `upload-image-processing`.
- It does not address storage: a re-encoded image stored as `avatar.php` is still executed.

### Server configuration files

If the upload directory is served by a web server that reads per-directory configuration from it, uploading
that configuration file changes how sibling files are handled:

- **Apache `.htaccess`**: `AddType application/x-httpd-php .xyz` makes `.xyz` execute; `php_value
  auto_prepend_file` pulls in another file on every request. Requires `AllowOverride` to permit it, which is
  not the modern default.
- **IIS `web.config`**: the equivalent, mapping a handler to an extension.
- **`.user.ini`**: in php-fpm/CGI setups, sets `auto_prepend_file` per directory without needing Apache
  overrides.

These matter because the extension allowlist is usually written without considering that the *configuration*
is also a file the allowlist might permit.

### Other outcomes besides RCE

An upload that cannot execute can still matter:

- **SVG** is XML with scripting, so an SVG served inline from the application's origin is stored XSS. It is
  also an XXE entry point (see `xxe-full`).
- **HTML** uploads served from the origin are stored XSS directly.
- **Content-Disposition** decides whether the browser renders or downloads; `attachment` neutralises both of
  the above.
- **Archive uploads** reach the zip-slip surface in `lfi-path-traversal`.
- **Filename reflection** in a page is an ordinary XSS sink.

### The upload/scan race

Some applications write the upload, scan or validate it, then delete it if it fails. Between the write and
the delete the file exists and is reachable. Whether this is exploitable depends on whether the file is
served during that window and how long the window is - which is a property of the implementation, and one of
the reasons "validate then delete" is a worse design than "write to a quarantine location and promote on
success".

## Attack

1. **Establish the stored path.** Without it, nothing else matters. Look for it in the response, in the
   rendered page, or by fetching a predictable directory.
2. **Determine what is served from there.** Upload a plain text file and fetch it. Does it render? What
   `Content-Type` comes back? Is there a `Content-Disposition: attachment`?
3. **Test which layer rejects you** by changing one thing at a time: extension only, `Content-Type` only,
   magic bytes only. The layer that changes the verdict is the one in play.
4. **Check whether the filename is preserved.** A generated name closes traversal and most extension games.
5. **Try a configuration file** if the extension allowlist looks narrow but includes unexpected entries.
6. **If execution is closed, pivot**: SVG/HTML for stored XSS, archive for zip-slip, or the media-processing
   surface in `upload-image-processing`.

## Code

An offline auditor for an upload handler's configuration: given which checks it performs and how it stores
files, report which bypass classes remain open and which defensive control closes each. It reasons about a
configuration, and builds no payloads.

```python
#!/usr/bin/env python3
"""Audit an upload handler's validation layers.

Given the checks a handler performs and its storage decisions, report which
bypass classes remain open and name the control that closes each.

Offline; pure decision logic over a configuration.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Handler:
    # --- validation layers ---
    client_side_only: bool = False
    extension_mode: str = "allowlist"      # "none" | "denylist" | "allowlist"
    extension_list: list[str] = field(default_factory=lambda: ["jpg", "png", "gif"])
    extension_match: str = "last"          # "last" | "any" | "first"
    case_sensitive: bool = False
    checks_content_type: bool = False
    checks_magic_bytes: bool = False
    reencodes_images: bool = False
    preserves_metadata: bool = False
    # --- storage decisions (the ones that actually decide execution) ---
    stores_under_webroot: bool = True
    preserves_filename: bool = True
    execution_disabled_in_dir: bool = False
    serves_as_attachment: bool = False
    validate_then_delete: bool = False
    platform: str = "linux"                # "linux" | "windows"


@dataclass
class Gap:
    name: str
    detail: str
    closed_by: str

    def __str__(self) -> str:
        return f"  - {self.name}\n      {self.detail}\n      closed by: {self.closed_by}"


EXECUTABLE_SUFFIXES = {
    "php", "php3", "php4", "php5", "php7", "phtml", "pht", "phar", "phps", "inc",
    "asp", "aspx", "asa", "cer", "cdx", "jsp", "jspx", "jsw", "jsv",
}
CONFIG_FILES = {"htaccess", "user.ini", "config"}   # .htaccess, .user.ini, web.config


def audit(h: Handler) -> list[Gap]:
    gaps: list[Gap] = []

    if h.client_side_only:
        gaps.append(Gap("client-side validation only",
                        "the request is attacker-generated; the browser check is not in the path",
                        "validate server-side"))

    # --- extension handling -------------------------------------------
    if h.extension_mode == "none":
        gaps.append(Gap("no extension check", "any suffix is accepted",
                        "allowlist the extensions the feature needs"))
    elif h.extension_mode == "denylist":
        missed = sorted(EXECUTABLE_SUFFIXES - {e.lower() for e in h.extension_list})
        gaps.append(Gap("extension denylist",
                        f"{len(missed)} executable suffixes not listed, e.g. {', '.join(missed[:6])}",
                        "use an allowlist instead - a denylist is open-ended"))
    else:
        allowed_bad = {e.lower() for e in h.extension_list} & (EXECUTABLE_SUFFIXES | CONFIG_FILES)
        if allowed_bad:
            gaps.append(Gap("allowlist includes a dangerous suffix",
                            f"{sorted(allowed_bad)} is on the allowlist",
                            "remove it; allow only inert media types"))

    if h.extension_mode != "none":
        if h.extension_match == "any":
            gaps.append(Gap("extension matched anywhere in the name",
                            "'shell.php.jpg' satisfies a check that scans the whole filename",
                            "parse only the final suffix, and configure the server to do the same"))
        elif h.extension_match == "first":
            gaps.append(Gap("extension taken from the first dot",
                            "'image.jpg.php' passes a check that stops at the first suffix",
                            "take the suffix after the LAST dot"))
        if h.case_sensitive:
            gaps.append(Gap("case-sensitive extension check",
                            "'.pHP' bypasses it while the handler match stays case-insensitive",
                            "normalise case before comparing"))
        if h.platform == "windows":
            gaps.append(Gap("Windows filename normalisation",
                            "trailing dot/space are stripped after validation ('shell.php.'); "
                            "also ADS ('shell.php::$DATA') and 8.3 short names",
                            "generate the stored filename; never derive it from input"))

    # --- content inspection -------------------------------------------
    if h.checks_content_type:
        gaps.append(Gap("Content-Type is trusted",
                        "the multipart Content-Type is a client claim, editable in a proxy",
                        "ignore it; it is not evidence of anything"))
    if h.checks_magic_bytes and not h.reencodes_images:
        gaps.append(Gap("magic bytes only",
                        "a header check inspects the first bytes; a file can satisfy it and still "
                        "be valid script, since interpreters pass through non-tag content",
                        "re-encode from decoded pixel data, and store outside the webroot"))
    if h.reencodes_images and h.preserves_metadata:
        gaps.append(Gap("re-encode preserves metadata",
                        "payloads in EXIF/comment fields survive the re-encode",
                        "strip all metadata on re-encode"))

    # --- storage: the decisive layer -----------------------------------
    if h.stores_under_webroot and not h.execution_disabled_in_dir:
        gaps.append(Gap("stored under the web root with execution enabled",
                        "this is what turns a file into code; every check above is only a delay",
                        "store outside the document root and serve through a handler, or disable "
                        "execution for the directory"))
    if h.preserves_filename:
        gaps.append(Gap("original filename preserved",
                        "carries traversal ('../../x.php') and every extension trick into storage",
                        "generate a random identifier and keep the original name as metadata only"))
    if h.stores_under_webroot and h.extension_mode == "allowlist" and \
            any(e.lower() in CONFIG_FILES for e in h.extension_list):
        gaps.append(Gap("server configuration file uploadable",
                        ".htaccess / .user.ini / web.config change how sibling files are handled",
                        "never accept configuration filenames; set AllowOverride None"))
    if not h.serves_as_attachment:
        gaps.append(Gap("content served inline",
                        "SVG and HTML render on the application origin - stored XSS even without RCE",
                        "serve with Content-Disposition: attachment and a fixed Content-Type, "
                        "ideally from a separate origin"))
    if h.validate_then_delete:
        gaps.append(Gap("validate-then-delete race",
                        "the file is reachable between the write and the delete",
                        "write to a quarantine path and promote only after validation"))
    return gaps


def verdict(gaps: list[Gap]) -> str:
    names = {g.name for g in gaps}
    if "stored under the web root with execution enabled" in names:
        return "execution reachable if any extension gap exists"
    if any("XSS" in g.detail for g in gaps):
        return "execution closed; stored XSS still possible"
    return "no gap found in the modelled layers"


if __name__ == "__main__":
    scenarios = {
        "naive handler": Handler(client_side_only=True, extension_mode="none"),
        "denylist under webroot": Handler(extension_mode="denylist", extension_list=["php"],
                                          checks_content_type=True),
        "magic bytes, name kept": Handler(checks_magic_bytes=True),
        "windows allowlist": Handler(platform="windows"),
        "hardened": Handler(extension_mode="allowlist", extension_list=["jpg", "png"],
                            checks_magic_bytes=True, reencodes_images=True,
                            preserves_metadata=False, stores_under_webroot=False,
                            preserves_filename=False, execution_disabled_in_dir=True,
                            serves_as_attachment=True),
    }
    for name, handler in scenarios.items():
        gaps = audit(handler)
        print(f"\n== {name} == ({len(gaps)} gaps)")
        for gap in gaps:
            print(gap)
        print(f"  => {verdict(gaps)}")

    # A denylist is open-ended by construction.
    gaps = audit(Handler(extension_mode="denylist", extension_list=["php"]))
    denylist = next(g for g in gaps if g.name == "extension denylist")
    assert "executable suffixes not listed" in denylist.detail
    assert "allowlist" in denylist.closed_by
    # Blocking 'php' alone leaves the whole PHP family reachable.
    assert EXECUTABLE_SUFFIXES - {"php"} >= {"phtml", "php5", "phar"}

    # Trusting Content-Type is always a gap.
    assert any(g.name == "Content-Type is trusted"
               for g in audit(Handler(checks_content_type=True)))

    # Magic bytes alone do not establish that a file is not also script.
    assert any(g.name == "magic bytes only" for g in audit(Handler(checks_magic_bytes=True)))
    # ...but combined with a re-encode that strips metadata, that gap closes.
    assert not any(g.name == "magic bytes only"
                   for g in audit(Handler(checks_magic_bytes=True, reencodes_images=True)))
    # A re-encode that keeps metadata reopens it.
    assert any(g.name == "re-encode preserves metadata"
               for g in audit(Handler(reencodes_images=True, preserves_metadata=True)))

    # Storage is the decisive layer: even a perfect allowlist leaves this gap.
    perfect_checks = Handler(extension_mode="allowlist", extension_list=["jpg"],
                             checks_magic_bytes=True, reencodes_images=True,
                             preserves_filename=False)
    assert any(g.name == "stored under the web root with execution enabled"
               for g in audit(perfect_checks)), \
        "byte-level validation does not answer the execution question"

    # The hardened handler has no gaps in any modelled layer.
    assert audit(scenarios["hardened"]) == [], [str(g) for g in audit(scenarios["hardened"])]

    print("\nself-test ok")
```

## Variants & pitfalls

- **Find the stored path first.** An upload you cannot fetch is not yet a finding.
- **Change one thing per request.** Otherwise you cannot tell which layer rejected you.
- **A denylist is open-ended.** Enumerate alternate suffixes before concluding the extension check holds.
- **`Content-Type` proves nothing.** Do not treat matching it as progress.
- **Polyglots pass header checks by construction** - the two parsers care about different bytes.
- **Re-encoding usually wins** unless metadata is preserved.
- **`.htaccess` needs `AllowOverride`**, which modern configurations often disable. Check before assuming.
- **Execution depends on the server's handler mapping**, not on the extension in isolation. A `.php` file in
  a directory with the PHP handler removed is inert.
- **SVG and HTML are the fallback** when code execution is closed, provided content is served inline.
- **Windows normalisation happens after validation** - trailing dots and spaces are the classic case.
- **Uploads on a CDN or object store** usually cannot execute at all; the risk shifts to stored XSS and
  content-type confusion.

### Defence / what closes this

Store uploads outside the document root and serve them through an application handler that sets the
`Content-Type` and `Content-Disposition: attachment` explicitly - that removes execution and inline rendering
in one decision, regardless of what the file contains. Generate the stored filename yourself (a UUID) and
keep the user's name as display metadata only, which closes traversal and every extension trick at once.
Allowlist extensions and MIME types rather than denylisting, comparing case-insensitively against the suffix
after the final dot. Verify the type by parsing, not by header bytes, and re-encode images from decoded pixel
data with metadata stripped. Never accept `.htaccess`, `.user.ini` or `web.config`, and set
`AllowOverride None`. Disable script handlers for the upload directory as defence in depth. Write to a
quarantine location and promote only after validation, rather than deleting on failure. Serve user content
from a separate origin so that a stored-XSS payload lands outside the application's origin. Cap file size and
count, and scan asynchronously rather than in the request path.

## Tools

- Burp Repeater - the natural place to vary one field of a multipart request at a time.
- `curl -F` - scriptable equivalent for quick checks.
- `exiftool` - inspect and strip metadata; confirms whether a re-encode preserved fields.
- `file` - what a magic-byte check sees, from the command line.

## References

- OWASP, unrestricted file upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP Testing Guide, testing upload of unexpected file types: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types
- PortSwigger, file upload vulnerabilities: https://portswigger.net/web-security/file-upload
- PayloadsAllTheThings, upload insecure files: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- Apache, `AllowOverride` directive: https://httpd.apache.org/docs/current/mod/core.html#allowoverride
- PHP manual, handling file uploads: https://www.php.net/manual/en/features.file-upload.php
