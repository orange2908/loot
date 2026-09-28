---
title: "php://filter - Source Disclosure and iconv Filter Chains"
category: web
subcategory: lfi
type: technique
tags: [lfi, php-filter, php-wrapper, base64-encode, convert-base64-decode, iconv, filter-chain, stream-filter, source-disclosure, zlib-deflate, encoding, allow-url-fopen, include, file-get-contents, synacktiv, oracle]
difficulty: hard
summary: "php://filter transforms a stream on the way in; base64 reads source without executing it, and an iconv chain turns a pure read into controlled content."
when_to_use:
  - "You have file inclusion and want the PHP source rather than its output"
  - "`allow_url_include` is off, so php://input and data:// are unavailable"
  - "The sink reads a path but you control no file on disk"
  - "You need to understand why a long chain of iconv conversions produces chosen bytes"
related: [lfi-to-rce, lfi-path-traversal, upload-to-rce]
tools: [burp, curl, php]
---

## TL;DR

`php://filter` applies transformations to a stream as it is opened. Two consequences. First,
`convert.base64-encode` lets you read a PHP file as base64 instead of executing it, which is the standard
source-disclosure primitive. Second - and much less obvious - chaining `iconv` conversions lets you *prepend*
chosen bytes to whatever the stream contains, which converts a read-only file primitive into one that
produces content you choose. That second property is what makes a pure file read escalate when every other
route is closed.

## Recognise it

- An inclusion or file-read sink where the path is user-controlled.
- `php://filter/convert.base64-encode/resource=index.php` returns a base64 blob instead of rendered output.
- `allow_url_include=Off`, so `php://input` and `data://` return
  `URL file-access is disabled in the server configuration`.
- A forced `.php` suffix on the parameter - which does not block this, because the wrapper name is not a path.
- Extremely long URLs in a writeup or a challenge's request log - a filter chain is thousands of characters.

## Theory

### Stream filters

PHP streams support filters that transform data in transit. The `php://filter` wrapper expresses that in a
URI:

```
php://filter/<read filters>/resource=<the real stream>
php://filter/read=convert.base64-encode/resource=index.php
php://filter/convert.base64-encode|convert.base64-encode/resource=index.php
```

Filters are applied left to right, separated by `|`. The `resource=` part must come last and names the
underlying stream. The available filter families:

| Family | Examples | Notes |
|--------|----------|-------|
| `convert.base64-*` | `convert.base64-encode`, `convert.base64-decode` | the decode half is unusually tolerant |
| `convert.iconv.*` | `convert.iconv.UTF-8.UTF-16LE` | character-set conversion, the chain primitive |
| `string.*` | `string.toupper`, `string.rot13` | simple transforms |
| `zlib.*` | `zlib.deflate`, `zlib.inflate` | compression; useful to shrink a long output |

### Why base64 for source disclosure

`include('config.php')` executes the file, so you see its *output* - typically nothing, since a config file
is all assignments. You want the bytes.

`convert.base64-encode` makes the stream's contents base64 before PHP parses them. Base64 output contains no
`<?php`, so there is nothing for the interpreter to execute; the encoded text is emitted as literal output
and you decode it yourself. The filter is doing the work of neutralising the PHP tags, which is why this
works on an `include` sink and not just a read sink.

For a large file, `php://filter/zlib.deflate/convert.base64-encode/resource=big.php` compresses first, which
matters when the response is size-limited.

### The iconv chain: turning a read into a write

This is the part worth understanding properly, because the payload looks like line noise and the mechanism is
genuinely elegant. It is due to Charles Fol / Synacktiv.

The goal: make the stream produce bytes **you choose**, when you control only the filter list and not the
file. Three properties combine.

**Property 1: `convert.base64-decode` ignores characters outside the base64 alphabet.** Feed it a mixture of
valid base64 and arbitrary junk, and the junk is skipped rather than raising an error. So the decoder acts as
a filter that *selects* the base64-alphabet characters out of a stream and decodes them.

**Property 2: `iconv` conversions emit predictable bytes for a given input.** Converting between character
sets with different widths and representations transforms each byte in a defined way. `UTF-8` to `UTF-16LE`
interleaves null bytes; conversions to and from the various ISO-2022, UCS and EBCDIC-family encodings produce
shifts, escape sequences and substitutions. Crucially, some conversions *introduce* bytes that were not in
the input - escape sequences, byte-order marks, padding.

**Property 3: the two compose.** If a conversion introduces a byte that happens to be in the base64 alphabet,
and you then base64-decode, that introduced byte contributes to the decoded output. By picking a conversion
whose introduced bytes are known, you control part of the result.

The construction is then iterative, and the direction is the surprising bit - **the chain builds the prefix
backwards, one character at a time**:

1. Start with the file's own content as the stream.
2. Apply a conversion that prepends a known byte.
3. Base64-encode and decode around it so that the prepended byte survives and the rest is re-normalised.
4. Repeat. Each round adds one more chosen character to the front of the stream.

After enough rounds the stream begins with a string you chose, followed by the original file's content as
trailing garbage. If the sink is `include`, a leading `<?php ...` is parsed and executed, and the trailing
garbage is either after a `?>`-free script or simply irrelevant.

Two practical consequences fall out of the construction:

- **Chains are long.** Each character costs several conversions, so a short prefix is already a URL of
  thousands of characters. Servers with a URL-length limit will reject it, and a POST parameter or a header
  may be needed instead.
- **The file being read barely matters.** You are generating content, not reading it - so the chain works
  against any readable file, which is why `/etc/passwd` or even a non-existent-but-readable resource is a
  common base.

### Why this matters

It is the answer to "`allow_url_include` is off, logs are not readable, there is no upload, and `open_basedir`
is set". Under those conditions every route in `lfi-to-rce` is closed, and a filter chain still works, because
it needs only `allow_url_fopen` (on by default) and a sink that opens a path.

## Attack

1. Confirm the wrapper is available: `php://filter/convert.base64-encode/resource=<known file>` returning
   base64 is the test.
2. **Read the source first.** Before anything clever, dump the including file, the config, and anything the
   application references. The source usually shortens the rest of the challenge dramatically.
3. Determine the sink. Reading gets you source; only `include`/`require` executes generated content.
4. If execution is needed and the simple routes are closed, build a chain. Keep the generated prefix as short
   as possible, because length is the binding constraint.
5. Deliver it in a request component without a tight length limit if the URL is rejected.

## Code

A demonstration of the two encoding mechanics the technique rests on: base64-decode's tolerance of
non-alphabet characters, and how conversion between encodings introduces bytes that a subsequent decode
picks up. It simulates the primitives in Python so the mechanism is visible and testable; it does not
generate a deployable chain.

```python
#!/usr/bin/env python3
"""The encoding mechanics behind php://filter chains.

Demonstrates, offline:
  1. Why base64 defeats "include executes what it reads".
  2. That base64 decoding ignores characters outside the alphabet - the property
     that lets injected bytes survive alongside junk.
  3. That encoding conversions introduce bytes not present in the input, and
     that a following base64-decode picks those bytes up. That composition is
     the filter-chain primitive.

Simulation, not a chain generator: Python's codecs are not PHP's iconv, and the
exact byte sequences differ. The transferable part is the mechanism.
"""
from __future__ import annotations

import base64
import binascii

B64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def php_base64_decode(data: bytes) -> bytes:
    """Model convert.base64-decode: skip anything outside the alphabet.

    PHP's decoder does not error on junk; it filters the stream down to base64
    characters and decodes those. That tolerance is property 1.
    """
    kept = bytes(c for c in data if chr(c) in B64_ALPHABET and chr(c) != "=")
    kept = kept[:len(kept) - len(kept) % 4]   # a trailing partial group is dropped
    return base64.b64decode(kept)


def looks_like_php(data: bytes) -> bool:
    return b"<?php" in data or b"<?=" in data


def introduced_bytes(text: str, src: str, dst: str) -> bytes:
    """Bytes present after a conversion that were not in the input.

    Stands in for the iconv step: conversions add escape sequences, byte-order
    marks and padding. Those additions are what a chain steers.
    """
    try:
        converted = text.encode(src).decode(src).encode(dst)
    except (UnicodeError, LookupError):
        return b""
    original = set(text.encode(src, errors="ignore"))
    return bytes(b for b in converted if b not in original)


if __name__ == "__main__":
    source = b"<?php $db_pass = 'hunter2'; ?>"

    print("== 1. base64 neutralises the PHP tags ==")
    encoded = base64.b64encode(source)
    print(f"  source  {source!r}")
    print(f"  encoded {encoded!r}")
    assert looks_like_php(source), "the raw file would be parsed and executed"
    assert not looks_like_php(encoded), "the encoded stream contains no PHP tag to execute"
    assert base64.b64decode(encoded) == source, "and it round-trips, so you get the bytes"
    print("  -> include() emits the encoded text instead of executing the file")

    print("\n== 2. the decoder ignores non-alphabet characters ==")
    payload = base64.b64encode(b"CHOSEN")
    # Interleave junk of the kind a conversion step leaves behind: escape
    # sequences, control bytes and a BOM, none of them in the base64 alphabet.
    noisy = b"\x1b$*" + payload[:4] + b"\x00\x0e!!" + payload[4:] + b"\xff\xfe"
    decoded = php_base64_decode(noisy)
    print(f"  clean   {payload!r} -> {php_base64_decode(payload)!r}")
    print(f"  noisy   {noisy!r}\n          -> {decoded!r}")
    assert decoded == b"CHOSEN", "junk skipped, the base64 characters still decode"

    # A strict decoder refuses the same input. PHP's tolerance is the point.
    strict_rejected = False
    try:
        base64.b64decode(noisy, validate=True)
    except binascii.Error:
        strict_rejected = True
    assert strict_rejected, "a validating decoder should reject non-alphabet bytes"
    print("  a strict decoder rejects it; PHP's does not - that tolerance is property 1")

    # Junk that DOES fall in the alphabet is not skipped: it shifts the
    # decoding. A real chain has to account for every introduced byte, which is
    # a large part of why chains are long and platform-sensitive.
    shifted = php_base64_decode(b"B" + payload)
    assert shifted != b"CHOSEN", "one stray alphabet byte changes the whole decode"
    print(f"  one stray alphabet byte -> {shifted!r} (alignment matters)")

    print("\n== 3. conversions introduce bytes that were not in the input ==")
    found_any = False
    for src, dst in [("utf-8", "utf-16"), ("utf-8", "utf-32"), ("utf-8", "utf-16-be")]:
        extra = introduced_bytes("AA", src, dst)
        usable = bytes(b for b in extra if chr(b) in B64_ALPHABET)
        print(f"  {src:>8} -> {dst:<10} introduced {extra!r}")
        if extra:
            found_any = True
    assert found_any, "at least one conversion must add bytes absent from the input"
    print("  -> a chain picks conversions whose introduced bytes are known in advance")

    print("\n== 4. composing them: introduced bytes survive a following decode ==")
    # A conversion leaves both junk and alphabet characters; the decode selects
    # the alphabet ones. Compose the two and chosen bytes reach the output while
    # the original content contributes trailing garbage.
    chosen = base64.b64encode(b"<?php ")
    original = base64.b64encode(b"unrelated file content")
    stream = b"\xfe\xff" + chosen + b"\x1b(*" + original
    result = php_base64_decode(stream)
    print(f"  stream  {stream!r}")
    print(f"  decoded {result!r}")
    assert result.startswith(b"<?php "), "the chosen prefix leads the decoded stream"
    print("  -> the chain builds this prefix one character at a time, backwards")

    print("\n== 5. why the target file is almost irrelevant ==")
    for content in (b"root:x:0:0:root:/root:/bin/bash\n", b"", b"\x89PNG\r\n\x1a\n"):
        stream = chosen + base64.b64encode(content)
        assert php_base64_decode(stream).startswith(b"<?php "), \
            "the generated prefix does not depend on what the file contains"
    print("  the prefix is generated, not read - any readable resource works as a base")

    print("\nself-test ok")
```

## Variants & pitfalls

- **`resource=` must be last.** Filters come first, separated by `|`; getting the order wrong produces a
  generic failure that looks like the wrapper being disabled.
- **`read=` is optional** but explicit (`php://filter/read=convert.base64-encode/...`); both forms work.
- **A forced suffix is not fatal.** `resource=config` with `.php` appended still resolves, because the suffix
  lands on the resource name.
- **Base64 output can be truncated** by a response-length limit. `zlib.deflate` first, or read in slices with
  the `string.*` filters, or fetch the file in parts.
- **`allow_url_fopen=Off` disables the wrapper entirely.** That is the one setting that closes this.
- **`open_basedir` still applies** to the underlying resource, so the chain does not escape it.
- **Chains are enormous.** Expect a URL-length rejection and be ready to move the parameter into a POST body.
- **Python is not PHP.** The demonstration above shows the mechanism; the exact conversions that produce
  usable bytes differ between `iconv` implementations and even between glibc versions, which is why a chain
  generated for one host can fail on another.
- **Read source before generating content.** The source frequently makes the generation step unnecessary.
- **Filter names are case-sensitive** and an unknown filter fails the whole open.

### Defence / what closes this

Do not pass user input to a function that opens a path. Map input through a hard-coded allowlist to a fixed
filename - that closes this along with every other inclusion route, because the wrapper name never reaches
the stream API. If dynamic paths are unavoidable, reject any value containing `://` before use, since every
wrapper is reached through a scheme, and then `realpath()`-confine the result. Set `allow_url_fopen=Off` when
the application does not need remote streams; it is the setting that disables `php://filter` outright. Keep
`open_basedir` confined so that even a successful read is limited to the application directory. Keep secrets
out of PHP files that user input could name - use environment variables or a secret store, so source
disclosure yields less. And disable `display_errors` so that path structure is not handed over.

## Tools

- `curl` plus `base64 -d` - decode the response in one pipeline.
- Burp Repeater - for driving long payloads and moving them between URL and body.
- A local PHP container - the only reliable way to check which `iconv` conversions behave as expected, since
  this varies by platform.
- `php -r` - test filter strings directly against a local file.

## References

- PHP manual, `php://` wrappers: https://www.php.net/manual/en/wrappers.php.php
- PHP manual, available filters: https://www.php.net/manual/en/filters.php
- PHP manual, `convert.*` filters: https://www.php.net/manual/en/filters.convert.php
- Synacktiv, "PHP filter chains: file read from error-based oracle": https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle
- Synacktiv, php_filter_chain_generator: https://github.com/synacktiv/php_filter_chain_generator
- PayloadsAllTheThings, file inclusion: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- OWASP Testing Guide, testing for local file inclusion: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
