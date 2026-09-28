---
title: "Command Injection - Shell Context and Argument Injection"
category: web
subcategory: cmdi
type: technique
tags: [command-injection, os-command-injection, argument-injection, shell-metacharacters, shell-true, subprocess, system, popen, exec, shell-exec, passthru, proc-open, blind-injection, out-of-band, ifs, brace-expansion, wildcard, execve, burp]
difficulty: medium
summary: "Two different bugs: data escaping into shell syntax, and data becoming a flag to the program - the second needs no metacharacters at all."
when_to_use:
  - "Input reaches a command line: ping, nslookup, convert, tar, git, curl, pdf tools"
  - "You need to work out which quoting context your input lands in"
  - "The application escapes metacharacters and you need to know what that does and does not close"
  - "There is no output, so detection has to be timing- or callback-based"
related: [ssrf-fundamentals, upload-image-processing, sqli-waf-bypass, lfi-to-rce]
tools: [burp, curl, interactsh]
---

## TL;DR

There are two distinct vulnerabilities that both get called "command injection". **Shell injection**: your
data reaches a shell, and shell metacharacters escape the intended command. **Argument injection**: your data
stays a single argument, but the program interprets it as an option - which needs no metacharacters and
survives every quoting fix. Knowing which one you have determines both the approach and the correct fix.

## Recognise it

- A feature that obviously wraps a tool: ping, traceroute, whois, nslookup, DNS lookup, "convert to PDF",
  "download this URL", archive extraction, git operations, image conversion.
- Output that looks like a program's stdout - `PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data`.
- Error text naming a binary: `sh: 1: convert: not found`, `/bin/sh: syntax error near unexpected token`.
- A response-time difference when you append a delay, with no visible output change.
- In source: `system()`, `exec()`, `shell_exec()`, `passthru()`, backticks, `proc_open()` in PHP;
  `os.system`, `subprocess` with `shell=True`, `os.popen` in Python; `child_process.exec` in Node;
  `Runtime.exec` with a single string in Java.

## Theory

### The fork in the road

```
subprocess.run(f"ping -c 1 {host}", shell=True)   # a SHELL parses this string
subprocess.run(["ping", "-c", "1", host])          # execve; no shell exists
```

In the first, the string is handed to `/bin/sh`, which tokenises it - so shell syntax in `host` is syntax.
In the second, the argument vector goes straight to `execve` and `host` is exactly one argument no matter
what bytes it contains. **There is no metacharacter that escapes the second form**, because there is no
parser to escape from.

That is why "escape the metacharacters" is a worse fix than "do not use a shell": escaping is a blacklist
over a large grammar, while the list form removes the grammar. And note what the list form does *not* fix -
argument injection, below, where the problem is that the program itself interprets the argument.

### Shell context decides the exit

If a shell is involved, what you need depends on the quoting your data lands inside. Same reasoning as
`xss-contexts`: identify the state, then the exits.

| Where your data lands | What terminates it | Why |
|---------------------|-------------------|-----|
| Unquoted argument | `; & \| \n` and friends | you are already in command position after a separator |
| Inside `"double quotes"` | `$(...)` or backticks | command substitution is evaluated inside double quotes |
| Inside `'single quotes'` | a `'` first | nothing is special inside single quotes, so you must close them |
| As a filename after a flag | nothing - see argument injection | no shell parsing is involved |

The separators worth knowing and why they differ:

- `;` - run the next command unconditionally.
- `&&` / `||` - conditional on the previous exit status. Useful when you want your command to run only if
  the intended one failed, or vice versa, which can matter for keeping the page rendering normally.
- `|` - pipe; the second command runs regardless and receives the first's output.
- `&` - background the first command; the response often returns sooner.
- Newline (`%0a` in a URL) - a command separator that many filters forget because it is not punctuation.
- `$(cmd)` and `` `cmd` `` - substitution, which works *inside* double quotes where separators do not.

The single-quote case is the one people get wrong. Inside `'...'` the shell treats everything literally - no
substitution, no separators - so the only way out is a literal `'`. If the application escapes quotes
correctly but nothing else, a single-quoted context is genuinely closed.

### Argument injection: the program is the gadget

Suppose the application is careful and uses the list form:

```
subprocess.run(["tar", "czf", "out.tgz", user_input])
```

No shell. No metacharacters possible. And still a problem, because `tar` interprets arguments beginning with
`-` as options, and some options run programs or read and write arbitrary paths. The same is true across the
toolbox: `curl` can write to a file chosen by an option; `ffmpeg` takes an input path as an option value;
`git` has options that name a program to run; `wget` can be told to post the contents of a local file; `find`
has an option that executes a command per result; `zip` has one that names a filter program.

The mechanism to internalise: **any argument you control that can begin with `-` is a potential option**, and
the set of reachable behaviours is the set of options that program supports. You are not escaping a parser;
you are using the program's documented interface in a way the caller did not intend.

Two defences, and the difference matters:

- `--` ends option parsing, so everything after it is positional. This is the correct fix and it is one token.
- Prefixing a relative path with `./` makes it not start with `-`. Narrower, but effective for filenames.

Neither is achieved by escaping metacharacters, which is why argument injection survives the usual
remediation.

### Blind detection

Most real cases show no command output. Three detection channels, in order of reliability:

1. **Out-of-band.** Make the server contact a host you control - DNS or HTTP. This is the most reliable
   because it is unambiguous and it works even when the command's output is discarded and its exit status is
   ignored. DNS is the better first probe: it often escapes egress filtering that blocks HTTP, and a
   resolution is logged even when the connection is blocked.
2. **Timing.** A deliberate delay changes response time. Works everywhere, but noisy - network variance and
   application load produce false positives, so repeat and compare distributions rather than single samples.
3. **File-based.** Write to a path the application serves, then fetch it. Requires a writable, served
   directory, so it is situational.

Reliability practice: always confirm with a *negative* control. A payload that should not trigger, sent the
same way, tells you whether the signal is real.

### Filter evasion as a diagnostic

When a filter blocks specific characters or words, the space of shell-equivalent expressions is large -
`${IFS}` in place of a space, brace expansion, quote insertion inside a word, variable substitution,
wildcards matching a path, encoding and decoding through a helper. Each of these works for the same reason as
in `sqli-waf-bypass`: **the filter's model of the input and the shell's grammar disagree**.

The practical upshot for a defender is the useful part: because that space is effectively unbounded, a
character or keyword filter cannot be the control. The only sound answers are not invoking a shell, and
allowlisting the input against a narrow pattern. Treat a working evasion as evidence that the design is
wrong, not as a tuning problem for the filter.

## Attack

1. **Determine whether a shell is involved at all.** If the feature never changes behaviour on separators but
   does on a leading `-`, you are looking at argument injection.
2. **Establish an oracle before payloads.** Timing or out-of-band, with a negative control.
3. **Identify the quoting context** by testing one exit character at a time - a separator, then `$(`, then a
   quote. One per request.
4. **For argument injection**, enumerate the invoked program's options and look for ones that read, write, or
   execute. The manual page is the payload list.
5. **Keep the original command valid** where possible, so the page still renders and the response stays
   comparable to baseline.
6. **Confirm twice.** Command execution findings are frequently mis-called from timing noise.

## Code

A demonstration of the structural difference between shell and argument-vector invocation, and of what
escaping does and does not cover. It executes only harmless, portable commands (`echo`, `true`) and asserts
on their output.

```python
#!/usr/bin/env python3
"""Shell string vs argument vector: what each does with hostile-looking input.

Runs only harmless commands (echo/true) and asserts on their output, to show:
  1. With shell=True, metacharacters in data are parsed as syntax.
  2. With a list argv, the same bytes are one inert argument - no parser exists.
  3. shlex.quote makes the shell form safe from separators...
  4. ...but neither quoting nor the list form stops argument injection, which
     needs the '--' terminator instead.

Portable to macOS and Linux; creates its own fixture; no network.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile

MARKER = "INJECTED"


def via_shell(user: str) -> str:
    """The vulnerable pattern: interpolate into a string handed to /bin/sh."""
    return subprocess.run(f"echo start-{user}-end", shell=True,
                          capture_output=True, text=True).stdout.strip()


def via_shell_quoted(user: str) -> str:
    """The same shell invocation, with the value quoted for the shell."""
    return subprocess.run(f"echo start-{shlex.quote(user)}-end", shell=True,
                          capture_output=True, text=True).stdout.strip()


def via_argv(user: str) -> str:
    """The safe pattern: an argument vector, executed without a shell."""
    return subprocess.run(["echo", f"start-{user}-end"],
                          capture_output=True, text=True).stdout.strip()


def search(user: str, path: str, *, terminate_options: bool) -> tuple[int, str]:
    """Model argument injection: a user value in a positional argument slot.

    `grep <pattern> <file>` with no shell anywhere. A pattern of '-v' is read
    as grep's invert-match option instead of as data, which shifts every later
    argument along. '--' ends option parsing and restores it to data.

    grep is a deliberately harmless stand-in; the reachable options of tools
    like tar, curl or find are considerably more consequential.
    """
    argv = ["grep"]
    if terminate_options:
        argv.append("--")
    argv += [user, path]
    result = subprocess.run(argv, capture_output=True, text=True,
                            stdin=subprocess.DEVNULL)
    return result.returncode, result.stdout


if __name__ == "__main__":
    benign = "hello"
    hostile = f"x; echo {MARKER}"
    substitution = f'x$(echo {MARKER})'

    print("== 1. shell=True: data becomes syntax ==")
    for payload in (hostile, substitution):
        out = via_shell(payload)
        print(f"  {payload!r:<28} -> {out!r}")
    assert MARKER in via_shell(hostile), "the ';' separated a second command"
    assert MARKER in via_shell(substitution), "command substitution ran"
    # The separator split the output into two lines; the intended command's
    # output no longer stands alone.
    assert via_shell(hostile).splitlines()[0] == "start-x"

    print("\n== 2. argument vector: the same bytes are inert data ==")
    for payload in (hostile, substitution):
        out = via_argv(payload)
        print(f"  {payload!r:<28} -> {out!r}")
    assert via_argv(hostile) == f"start-{hostile}-end", "passed through literally"
    assert via_argv(substitution) == f"start-{substitution}-end", "no substitution happened"
    print("  -> no shell exists, so there is no grammar to escape from")

    print("\n== 3. shlex.quote closes the shell form against separators ==")
    for payload in (hostile, substitution, "it's", '"quoted"', "a\nb", "$HOME", "`id`"):
        out = via_shell_quoted(payload)
        expected = f"start-{payload}-end"
        status = "ok " if out == expected else "DIFF"
        print(f"  {status} {payload!r:<28} -> {out!r}")
    for payload in (hostile, substitution, "it's", '"quoted"', "$HOME", "`id`"):
        assert via_shell_quoted(payload) == f"start-{payload}-end", payload
    assert MARKER not in via_shell_quoted(hostile).replace("start-", "").replace("-end", "") \
        or via_shell_quoted(hostile) == f"start-{hostile}-end"
    print("  -> correct for THIS context; still a blacklist-shaped defence")

    print("\n== 4. argument injection: no shell, no metacharacters, still a bug ==")
    with tempfile.TemporaryDirectory() as tmp:
        haystack = os.path.join(tmp, "data.txt")
        with open(haystack, "w", encoding="utf-8") as handle:
            handle.write("alpha\n-v\nbeta\n")

        normal = search("alpha", haystack, terminate_options=False)
        as_flag = search("-v", haystack, terminate_options=False)
        terminated = search("-v", haystack, terminate_options=True)

        print(f"  pattern 'alpha'        -> rc={normal[0]} stdout={normal[1]!r}")
        print(f"  pattern '-v'  (no --)  -> rc={as_flag[0]} stdout={as_flag[1]!r}")
        print(f"  pattern '-v'  (with --) -> rc={terminated[0]} stdout={terminated[1]!r}")

        assert normal == (0, "alpha\n"), "ordinary data behaves as a pattern"
        assert as_flag[1] == "", \
            "the value was consumed as grep's -v option; the filename shifted into pattern position"
        assert terminated == (0, "-v\n"), \
            "'--' ends option parsing, so the same value is data again"
        print("  -> quoting and argv do NOT close this; '--' does")

        print("\n== 5. the two bugs are independent ==")
        # Safe against shell injection, still vulnerable to argument injection.
        assert via_argv("; echo x") == "start-; echo x-end"
        assert search("-v", haystack, terminate_options=False)[1] == ""
        # Safe against both.
        assert search("-v", haystack, terminate_options=True) == (0, "-v\n")
        print("  argv alone:   shell injection closed, argument injection open")
        print("  argv + '--':  both closed")

    print("\nself-test ok")
```

## Variants & pitfalls

- **Timing false positives are common.** Repeat, and use a negative control.
- **DNS often escapes egress filtering** that blocks HTTP, so try it first for out-of-band.
- **Single-quoted context needs a quote**, not a separator. Test the quote before concluding the input is
  filtered.
- **Newline is a separator.** `%0a` is easy to forget because it is not punctuation.
- **Windows is a different grammar** - `&`, `&&`, `|` work in `cmd.exe`; `;` does not. PowerShell is
  different again.
- **`escapeshellarg`/`escapeshellcmd` are not interchangeable.** The former quotes one argument correctly;
  the latter escapes a whole command string and is easy to misuse. Neither addresses argument injection.
- **Argument injection survives every quoting fix**, which is exactly why it is missed in review.
- **Blind does not mean unexploitable**, but it does mean you need a channel before you need a payload.
- **A filter that blocks spaces** tells you a filter exists; it does not tell you the sink is a shell.
- **Keep the command syntactically valid** so the application behaves normally and your baseline stays
  meaningful.

### Defence / what closes this

Do not invoke a shell. Use the argument-vector form of your language's process API - `subprocess.run([...])`
without `shell=True`, `execve`-family calls, Node's `execFile`/`spawn` rather than `exec`, Java's
`ProcessBuilder` with a list - so that no shell grammar exists for data to escape into. Then close argument
injection separately: pass `--` before user-controlled positional values, prefix user-supplied relative paths
with `./`, and reject values beginning with `-`. Better still, do not pass user input as an argument at all -
validate it against a strict allowlist pattern first (for a hostname, a hostname regex or a resolver call;
for a choice, an enum mapped to a fixed value). Prefer a library over a subprocess where one exists: a DNS
library instead of `nslookup`, an HTTP client instead of `curl`, an archive library instead of `tar`. If a
shell is genuinely unavoidable, quote with the platform's own facility (`shlex.quote`, `escapeshellarg`) and
treat it as a mitigation rather than the control. Run the process as an unprivileged user with a minimal
environment, in a container without egress, so a successful injection reaches as little as possible.

## Tools

- Burp Repeater / Collaborator - one exit character per request, with an out-of-band channel.
- `interactsh` - self-hosted DNS and HTTP interaction collector.
- `shlex.quote` / `escapeshellarg` - read their documentation for what they promise; it is narrower than
  people assume.
- The invoked program's manual page - for argument injection this is the primary reference.

## References

- OWASP, command injection: https://owasp.org/www-community/attacks/Command_Injection
- OWASP Testing Guide, testing for command injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
- OWASP OS Command Injection Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- PortSwigger, OS command injection: https://portswigger.net/web-security/os-command-injection
- Python docs, `subprocess` security considerations: https://docs.python.org/3/library/subprocess.html#security-considerations
- PHP manual, `escapeshellarg`: https://www.php.net/manual/en/function.escapeshellarg.php
- PayloadsAllTheThings, command injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- PayloadsAllTheThings, argument injection: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md
