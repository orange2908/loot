---
title: "LFI - Escalating File Read to Code Execution"
category: web
subcategory: lfi
type: technique
tags: [lfi, local-file-inclusion, rce, log-poisoning, proc-self-environ, proc-self-fd, session-file, php-wrapper, php-input, data-wrapper, phar, zip-wrapper, allow-url-include, allow-url-fopen, open-basedir, disable-functions, include, require, file-get-contents]
difficulty: medium
summary: "Every LFI-to-RCE route is the same shape: get attacker bytes into a file the server will include, then include it - the routes differ only in which file."
when_to_use:
  - "You can include an arbitrary local path and want to know whether execution is reachable"
  - "You need to decide which escalation route the target's configuration actually permits"
  - "A documented technique fails and you need to know which precondition is missing"
  - "You are assessing how much an include-based file read is worth on a hardened host"
related: [lfi-path-traversal, lfi-php-filter-chain, upload-to-rce, deser-php-phar]
tools: [burp, curl, ffuf]
---

## TL;DR

File *inclusion* differs from file *reading* in one respect that decides everything: `include` and `require`
execute what they read. So escalation is a two-part problem - **write attacker-controlled bytes into some
file on the host**, then **include that file**. Every named technique on this page is one answer to the first
part. Which answers exist is decided entirely by the target's PHP configuration, so establishing the
configuration is the actual work.

## Recognise it

- A parameter that names a file: `?page=about`, `?lang=en`, `?template=default`, `?file=report`.
- Including `/etc/passwd` (or `C:\Windows\win.ini`) returns its content.
- The error `failed to open stream: No such file or directory in /var/www/html/index.php on line 12`
  discloses the including file, the line, and confirms the sink is `include`/`require` rather than
  `file_get_contents`.
- An appended extension in the error (`.../pages/abouts.php`) tells you a suffix is being concatenated.
- Content that *executes* rather than displaying - including a known PHP file returns its rendered output,
  not its source. That distinguishes inclusion from reading, and only inclusion escalates directly.

## Theory

### The sink decides what is possible

| Sink | Reads | Executes | Escalation |
|------|-------|----------|-----------|
| `include` / `require` (and `_once`) | yes | **yes** | direct, if you can control bytes in any readable file |
| `file_get_contents`, `readfile`, `fopen` | yes | no | read-only; pivot to secrets or to `phar://` |
| `file_exists`, `is_file`, `filesize`, `md5_file` | metadata | no | oracle only - but see `phar://` below |

Most of this page needs the first row. Establishing which row you are in is the first diagnostic, and the
test is simple: include a file you know contains PHP. Source means reading; rendered output means inclusion.

### The configuration that gates everything

Four PHP settings decide which routes exist. Read them from `phpinfo()` if it is reachable, or infer them
from behaviour:

| Setting | Effect |
|---------|--------|
| `allow_url_fopen` | may remote URLs be opened at all (default **On**) |
| `allow_url_include` | may remote URLs be *included* (default **Off** since 5.2) |
| `open_basedir` | confines file access to a directory tree |
| `disable_functions` | removes command-execution functions from the language |

`allow_url_include` being off by default is why remote file inclusion is largely historical and why the
techniques below are all about *local* files. `open_basedir` is the setting that most often kills an
otherwise-working route, because logs and `/proc` sit outside the web root.

### Route 1: log poisoning

**Mechanism.** A web server writes request data into its access log verbatim. Request headers are
attacker-controlled and are logged as-is. Put PHP source into a logged header, then include the log file; the
interpreter parses the whole file, ignores the lines that are not PHP, and executes your tags.

**Preconditions.** The log path must be known, readable by the PHP process, and the sink must be `include`.
All three fail more often than not: on Debian-family systems `/var/log/apache2/access.log` is mode 640 owned
`root:adm`, and `www-data` is not in `adm`. That single fact is why this technique works in CTFs far more
often than in the wild.

**Why the User-Agent specifically.** It is logged in the default combined format, it is trivially
controllable, and it is not validated. The request line also works but is subject to URL-encoding by the
client. Referer works equally well.

**Variants.** Any log that contains attacker-controlled bytes: mail logs (an address field), SSH `auth.log`
(a username in a failed login), FTP logs, and application-level logs. The mechanism is identical - the
question is only which log the PHP user can read.

### Route 2: /proc/self/environ

**Mechanism.** `/proc/self/environ` is the environment of the *reading* process. Under CGI or FastCGI, the
request's headers are passed to the interpreter as environment variables (`HTTP_USER_AGENT`), so including
this pseudo-file includes attacker-controlled bytes.

**Preconditions.** `procfs` mounted and readable, and a SAPI that puts request data in the environment. That
second condition is the one that has aged: under `mod_php` the environment belongs to the Apache process, and
under php-fpm the variables reach PHP over the FastCGI protocol rather than through the process environment.
So this is largely a CGI-era technique, and finding it live tells you something about the stack.

**Relatives.** `/proc/self/cmdline` (the command line), `/proc/self/fd/N` (open file descriptors - which can
include the access log or an uploaded temp file, letting you reach a file whose path you do not know), and
`/proc/self/root` (a symlink to `/`, useful for escaping a naive prefix check).

### Route 3: session files

**Mechanism.** PHP serialises `$_SESSION` into a file named `sess_<session_id>` under `session.save_path`
(commonly `/tmp` or `/var/lib/php/sessions`). If any user-controlled value is stored in the session - a
username, a language preference, a "last search" - those bytes land in that file. You know the filename
because you hold the session cookie.

**Preconditions.** Sessions in use, the save path readable, and *something* attacker-influenced written into
the session. The third is the real constraint, and it is worth checking what the app actually stores before
assuming.

This route is attractive because the path is predictable from your own cookie and needs no log access.

### Route 4: the PHP wrappers

Stream wrappers make the "get bytes into a file" step unnecessary, because the wrapper *is* the source:

- **`php://input`** - the raw request body. `include('php://input')` with PHP in the body executes it.
  Requires `allow_url_include=On`, which is off by default. This is the cleanest route when available and
  absent otherwise.
- **`data://text/plain,<?php ...`** - the URI carries the content. Also requires `allow_url_include`.
- **`expect://`** - executes a command directly. Requires the `expect` extension, which is rarely installed.
- **`php://filter`** - read-only transformation of a stream. It does not execute, and it is how you read
  source as base64. The filter *chain* technique turns it into content generation - see
  `lfi-php-filter-chain`, which is the modern answer when `allow_url_include` is off.
- **`zip://archive.zip#inner.php`** - include a file inside an uploaded archive. Needs an upload primitive
  and a known path.

### Route 5: phar://

**Mechanism.** A `.phar` archive carries a serialised metadata blob. Until PHP 8, **any** file operation on a
`phar://` URL deserialised that metadata - including operations that merely check the file, like
`file_exists` or `is_file`. So a read-only or even metadata-only sink became an object-injection sink,
provided a usable gadget chain exists in the loaded code.

**Preconditions.** PHP < 8.0 for the automatic behaviour (8.0+ requires opt-in), a way to place the archive on
disk (any upload, even one that renames the file - the extension does not matter), and a gadget chain. See
`deser-php-phar` for the deserialisation half.

This is the route that matters when the sink does *not* execute, which is why it is worth knowing even though
it is the most involved.

### Route 6: the upload temp-file race

**Mechanism.** PHP writes every multipart upload to a temporary file before the script runs, and deletes it
when the script ends. During that window the file exists, with attacker-controlled content, at a path like
`/tmp/phpXXXXXX`. Including it executes it.

**Preconditions.** The six random characters must be guessed or leaked, and the inclusion must happen while
the file exists. In practice this needs either a path disclosure (an error message, or `/proc/self/fd/`) or a
very large number of attempts. It is a real technique and a slow one.

## Attack

1. **Confirm inclusion, not reading.** Include a known PHP file and see whether you get source or output.
2. **Establish the configuration.** Look for `phpinfo()`; otherwise probe: does `php://filter` work
   (`allow_url_fopen` on)? Does `data://` work (`allow_url_include` on)? Does `/proc/self/environ` read
   (procfs + SAPI)?
3. **Deal with a forced suffix.** If the app appends `.php`, `php://filter` still works because the wrapper
   name is not a path. Older PHP allowed null-byte truncation; see `lfi-path-traversal`.
4. **Pick the route that the configuration permits.** Do not start with log poisoning on a host where the log
   is mode 640.
5. **Verify the write before the include.** Confirm your bytes actually reached the file (read the log back
   through the same LFI) before debugging the execution step.
6. **If nothing executes**, fall back to reading: config files with database credentials, `.env`, source via
   `php://filter`, and the application's own secrets.

## Code

A preconditions evaluator. Given the configuration facts, it reports which routes are open, which are closed
and precisely what closes them - which is the triage this page exists to support.

```python
#!/usr/bin/env python3
"""Decide which LFI-to-RCE routes a PHP configuration permits.

Encodes the precondition table: sink type, the four php.ini settings, log
readability, SAPI, and PHP version. Reports each route with the reason.

Offline; pure decision logic.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Target:
    sink: str = "include"                 # "include" | "read" | "metadata"
    php_version: tuple[int, int] = (8, 2)
    allow_url_fopen: bool = True
    allow_url_include: bool = False       # default Off since PHP 5.2
    open_basedir: str = ""                # non-empty confines file access
    disable_functions: list[str] = field(default_factory=list)
    log_readable: bool = False            # www-data usually is NOT in group adm
    procfs_readable: bool = True
    sapi: str = "fpm"                     # "cgi" | "fpm" | "apache2handler"
    session_stores_user_input: bool = False
    session_path_readable: bool = True
    can_upload: bool = False
    has_gadget_chain: bool = False
    expect_extension: bool = False


@dataclass
class Route:
    name: str
    open_: bool
    reason: str

    def __str__(self) -> str:
        return f"  [{'OPEN  ' if self.open_ else 'closed'}] {self.name:<26} {self.reason}"


def evaluate(t: Target) -> list[Route]:
    routes: list[Route] = []
    executes = t.sink == "include"
    basedir = bool(t.open_basedir)

    def needs_execution(name: str) -> Route | None:
        if not executes:
            return Route(name, False, f"sink is {t.sink!r}, which does not execute what it reads")
        return None

    # --- log poisoning -------------------------------------------------
    blocked = needs_execution("log poisoning")
    if blocked:
        routes.append(blocked)
    elif not t.log_readable:
        routes.append(Route("log poisoning", False,
                            "log not readable by the PHP user (mode 640 root:adm is the usual reason)"))
    elif basedir:
        routes.append(Route("log poisoning", False, f"open_basedir={t.open_basedir!r} excludes /var/log"))
    else:
        routes.append(Route("log poisoning", True, "write PHP into a logged header, then include the log"))

    # --- /proc/self/environ --------------------------------------------
    blocked = needs_execution("/proc/self/environ")
    if blocked:
        routes.append(blocked)
    elif not t.procfs_readable:
        routes.append(Route("/proc/self/environ", False, "procfs not readable"))
    elif basedir:
        routes.append(Route("/proc/self/environ", False, "open_basedir excludes /proc"))
    elif t.sapi != "cgi":
        routes.append(Route("/proc/self/environ", False,
                            f"SAPI is {t.sapi!r}: request headers do not reach the process environment"))
    else:
        routes.append(Route("/proc/self/environ", True, "CGI puts request headers in the environment"))

    # --- session files -------------------------------------------------
    blocked = needs_execution("session file")
    if blocked:
        routes.append(blocked)
    elif not t.session_stores_user_input:
        routes.append(Route("session file", False, "nothing attacker-controlled is written into the session"))
    elif not t.session_path_readable:
        routes.append(Route("session file", False, "session.save_path not readable"))
    else:
        routes.append(Route("session file", True,
                            "session file name is derived from your own cookie - predictable path"))

    # --- wrappers ------------------------------------------------------
    blocked = needs_execution("php://input")
    if blocked:
        routes.append(blocked)
    elif not t.allow_url_include:
        routes.append(Route("php://input", False, "allow_url_include=Off (the default since 5.2)"))
    else:
        routes.append(Route("php://input", True, "request body is included directly"))

    blocked = needs_execution("data:// wrapper")
    if blocked:
        routes.append(blocked)
    elif not t.allow_url_include:
        routes.append(Route("data:// wrapper", False, "allow_url_include=Off"))
    else:
        routes.append(Route("data:// wrapper", True, "content carried in the URI"))

    routes.append(Route("expect:// wrapper", executes and t.expect_extension,
                        "expect extension present" if t.expect_extension
                        else "expect extension not installed (rarely is)"))

    # php://filter reads without executing - available far more often.
    if not t.allow_url_fopen:
        routes.append(Route("php://filter (read)", False, "allow_url_fopen=Off"))
    else:
        routes.append(Route("php://filter (read)", True,
                            "read source as base64; see lfi-php-filter-chain for content generation"))

    # --- phar:// -------------------------------------------------------
    if t.php_version >= (8, 0):
        routes.append(Route("phar:// deserialisation", False,
                            "PHP 8.0+ does not deserialise phar metadata implicitly"))
    elif not t.can_upload:
        routes.append(Route("phar:// deserialisation", False, "no way to place an archive on disk"))
    elif not t.has_gadget_chain:
        routes.append(Route("phar:// deserialisation", False, "no known gadget chain in the loaded code"))
    else:
        routes.append(Route("phar:// deserialisation", True,
                            "any file op on a phar:// URL deserialises metadata - works on read-only sinks"))

    # --- upload temp race ----------------------------------------------
    blocked = needs_execution("upload temp-file race")
    if blocked:
        routes.append(blocked)
    else:
        routes.append(Route("upload temp-file race", True,
                            "needs the /tmp/phpXXXXXX name leaked or brute-forced; slow but real"))
    return routes


def summarise(routes: list[Route]) -> str:
    open_routes = [r.name for r in routes if r.open_]
    if not open_routes:
        return "no execution route: pivot to reading secrets and source"
    return "open: " + ", ".join(open_routes)


if __name__ == "__main__":
    scenarios = {
        "modern hardened (fpm, PHP 8.2)": Target(),
        "CTF-shaped (readable logs)": Target(log_readable=True),
        "legacy CGI": Target(sapi="cgi", php_version=(5, 6), allow_url_include=True, log_readable=True),
        "read-only sink": Target(sink="read", log_readable=True),
        "metadata sink + phar": Target(sink="metadata", php_version=(7, 4),
                                       can_upload=True, has_gadget_chain=True),
        "open_basedir confined": Target(open_basedir="/var/www/html", log_readable=True),
    }
    for name, target in scenarios.items():
        routes = evaluate(target)
        print(f"\n{name}")
        for route in routes:
            print(route)
        print(f"  => {summarise(routes)}")

    # A default modern install offers no execution route at all - only reads.
    modern = evaluate(Target())
    assert not any(r.open_ for r in modern if "filter" not in r.name and "race" not in r.name), \
        "default config closes the named execution routes"
    assert any(r.name == "php://filter (read)" and r.open_ for r in modern)

    # allow_url_include being off is what closes the wrapper routes.
    assert any(r.name == "php://input" and not r.open_ and "allow_url_include" in r.reason
               for r in modern)

    # Log readability, not the technique, is what decides log poisoning.
    assert any(r.name == "log poisoning" and r.open_ for r in evaluate(Target(log_readable=True)))
    assert any(r.name == "log poisoning" and not r.open_ and "640" in r.reason for r in modern)

    # open_basedir kills the routes that live outside the web root.
    confined = evaluate(Target(open_basedir="/var/www/html", log_readable=True))
    assert any(r.name == "log poisoning" and not r.open_ and "open_basedir" in r.reason
               for r in confined)

    # A read-only sink closes every execution route except phar.
    readonly = evaluate(Target(sink="read", log_readable=True))
    assert all("does not execute" in r.reason
               for r in readonly if r.name in {"log poisoning", "php://input", "session file"})

    # phar reaches a metadata-only sink, which is the point of it.
    metadata = evaluate(Target(sink="metadata", php_version=(7, 4),
                               can_upload=True, has_gadget_chain=True))
    assert any(r.name == "phar:// deserialisation" and r.open_ for r in metadata)
    # ...but not on PHP 8.
    assert any(r.name == "phar:// deserialisation" and not r.open_ and "8.0+" in r.reason
               for r in evaluate(Target(php_version=(8, 1), can_upload=True, has_gadget_chain=True)))

    print("\nself-test ok")
```

## Variants & pitfalls

- **Reading is not including.** Confirm which you have before spending time on execution routes.
- **Log permissions kill log poisoning** far more often than any other factor. Check before theorising.
- **`open_basedir` excludes `/proc` and `/var/log`** and therefore closes the two most-cited routes at once.
- **A forced `.php` suffix** does not block `php://filter`, because the wrapper is not a filesystem path.
- **Null-byte truncation was fixed in PHP 5.3.4.** Do not plan around it unless the target is ancient.
- **`/proc/self/environ` is a CGI-era technique.** Under fpm or mod_php it will not contain your headers.
- **`/proc/self/fd/N` reaches files whose paths you do not know**, including the access log and upload temp
  files - worth trying when a path is unknown rather than unreadable.
- **Verify the write step independently.** Read the poisoned file back through the LFI before debugging the
  include.
- **Inclusion can be a one-shot.** Some payloads corrupt the target file, so plan the payload before sending.
- **When execution is unreachable, reading is still valuable**: `.env`, `config.php`, database credentials,
  framework secrets, and source that reveals a better bug.

### Defence / what closes this

Do not build a path from user input. Map the input to a value from a hard-coded allowlist
(`$pages = ['about' => 'about.php']; include $pages[$_GET['page']] ?? 'home.php';`) - that closes the whole
class, including the traversal variants, without relying on filtering. If a dynamic path is truly
unavoidable, resolve with `realpath()` and verify the result is inside an expected directory, rejecting
anything else; never sanitise by stripping. Set `allow_url_include=Off` and `allow_url_fopen=Off` unless a
feature needs them, and keep `open_basedir` confined to the application directory so logs and `/proc` are out
of reach. Run PHP as a user that cannot read the web server's logs. Store sessions outside any includable
path. Keep uploads on a separate, non-executable filesystem location. Run PHP 8.0+, where `phar://`
deserialisation is no longer implicit. Finally, disable `display_errors` in production - the include path in
an error message is what makes most of this navigable.

## Tools

- Burp Repeater - for setting a header and then requesting the log in two adjacent requests.
- `curl -H 'User-Agent: ...'` - the same thing from a shell.
- `ffuf` - enumerating candidate log and session paths against a known-good/known-bad response length.
- LFI wordlists in SecLists (`Discovery/Web-Content/LFI/`) - candidate paths per platform.

## References

- OWASP Testing Guide, testing for local file inclusion: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- PortSwigger, file path traversal: https://portswigger.net/web-security/file-path-traversal
- PHP manual, `include`: https://www.php.net/manual/en/function.include.php
- PHP manual, supported protocols and wrappers: https://www.php.net/manual/en/wrappers.php
- PHP manual, `phar` stream wrapper: https://www.php.net/manual/en/phar.using.stream.php
- PHP manual, runtime configuration (`allow_url_include`, `open_basedir`): https://www.php.net/manual/en/filesystem.configuration.php
- PayloadsAllTheThings, file inclusion: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- SecLists: https://github.com/danielmiessler/SecLists
