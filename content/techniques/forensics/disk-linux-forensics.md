---
title: "Linux Filesystem Forensics - ext4, Journals, Deleted Files and Persistence"
category: forensics
subcategory: linux
type: technique
tags: [ext4, sleuthkit, fsstat, debugfs, dumpe2fs, extundelete, ext4magic, jls, fls, istat, icat, mactime, timeline, crtime, wtmp, btmp, bash-history, systemd, journalctl, dfir]
difficulty: medium
summary: "Mount-less ext4 analysis: superblock and inode anatomy, journal recovery of deleted files, MACB timelines, and every Linux login and persistence artifact worth grepping."
when_to_use:
  - "You were handed a .img / .dd / .raw disk image or a partition that reports ext2/ext3/ext4"
  - "A file was deleted and you need it back, or need to prove when it existed"
  - "You must build a timeline of what happened on a Linux box"
  - "The task is 'find the backdoor' / 'how did they persist' on a Linux system image"
tools: [sleuthkit, debugfs, dumpe2fs, extundelete, ext4magic, e2fsprogs, mactime, plaso]
related: [disk-image-triage, disk-file-carving, disk-hidden-data, memory-linux-and-carving]
---

## TL;DR

Do not mount the image. Find the partition offset with `mmls`, then drive it with Sleuth Kit
(`fsstat`/`fls`/`istat`/`icat`) and `debugfs`. Deleted ext4 files are usually gone from the inode
but still in the **journal** -- that is where `ext4magic` and `jls`/`jcat` earn their keep. Then
grep the boring artifacts: bash history, authorized_keys, cron, systemd units, ld.so.preload.

## Recognise it

- `file image.dd` -> `Linux rev 1.0 ext4 filesystem data` (or `DOS/MBR boot sector` for a disk),
  and `xxd -s 1080 -l 2 image.dd` prints `53ef` (little-endian `0xEF53`) for ext2/3/4.
- `mmls image.dd` shows a `Linux (0x83)` partition; note its **start sector** (usually 2048).
  `fsstat -o 2048 image.dd` then prints `File System Type: Ext4`.

## Artifact anatomy: ext4 on disk

- The **primary superblock is at byte offset 1024**, with magic `0xEF53` at **superblock + 56**
  (absolute byte 1080, on disk little-endian `53 ef`). Backups sit at block-group starts.
- The fs is split into **block groups** (group descriptor, block bitmap, inode bitmap, inode
  table each); `flex_bg` lets a group's metadata live in a neighbour. **Inodes** start at 1,
  with fixed meanings: 2 = `/`, 8 = the **journal**, 11 = `lost+found`.
- ext2/3 used **indirect blocks** (12 direct + up to 3 levels). ext4 uses **extents**: an
  `ext4_extent_header` with magic `0xF30A` at the start of `i_block[]`, then entries mapping
  logical -> physical block runs, so fragmentation is rare. The **journal (inode 8)** is a
  circular log; `data=ordered` (default) journals metadata only, `data=journal` journals
  contents too and makes full content recovery possible.
- **Why ext4 undelete is hard**: on unlink ext4 zeroes the extent tree in the inode and frees
  the blocks, where ext3 only marked indirect blocks free, so recovery means pulling an **older
  copy of that inode** out of the journal -- exactly what `ext4magic` does.

## Workflow: layout, inodes, deleted files

```sh
# partition table: take the "Start" sector of the Linux partition as the -o value below
mmls image.dd
# filesystem summary (block size, inode count, last mount point/time, UUID), then the
# superblock alone: features, mount count, journal inode, default mount options
fsstat -o 2048 image.dd; dumpe2fs -h image.dd
# recursive listing with full paths; -d restricts it to deleted entries (marked with *)
fls -rp -o 2048 image.dd; fls -rpd -o 2048 image.dd   # deleted only
# metadata for one inode (all four times + extent runs), then its content; debugfs has no -o,
# so carve the partition out first (2048 * 512 = 1048576)
istat -o 2048 image.dd 12; icat -o 2048 image.dd 12 > recovered.bin
dd if=image.dd of=part.img bs=512 skip=2048
# inode detail incl. crtime and inline_data; then a directory INCLUDING deleted entries,
# whose inodes debugfs prints in angle brackets
debugfs -R "stat <12>" part.img; debugfs -R "ls -d /tmp" part.img
# dump by inode number or path, then replay what the journal knows about one inode
debugfs -R "dump <12> /tmp/out" part.img; debugfs -R "logdump -i <12>" part.img
# journal blocks and what each describes; jcat prints one of them raw
jls -o 2048 image.dd; jcat -o 2048 image.dd 8 1234 > jblock.bin
# ext4magic: histogram of what the journal knows, then list, then recover under /
ext4magic part.img -f / -H; ext4magic part.img -f / -a $(date -d "2 hours ago" +%s) -l
ext4magic part.img -f / -r -d ./RECOVERDIR
# -m is magic-scan mode (carve from unallocated); -b/-a bracket a time window; a dirty
# journal must be dumped first and passed with -j (never run e2fsck on evidence)
ext4magic part.img -f / -m -d ./RECOVERDIR; debugfs -R "dump <8> journalcopy" part.img
ext4magic part.img -f / -b $(date -d yesterday +%s) -a $(date +%s) -j journalcopy -r -d ./OUT
# extundelete: excellent on ext3, partial on ext4; output lands in ./RECOVERED_FILES/
extundelete part.img --restore-all; extundelete part.img --restore-file root/.ssh/id_rsa
```

## Timestamps and timelines

ext4 inodes carry **atime** (last read), **mtime** (content changed), **ctime** (inode changed:
perms, owner, link count, rename) and **crtime** (birth, ext4-only). `ls -l` shows mtime; only
`debugfs`, `istat` and `statx` expose crtime.

```sh
# live box: all four times plus inode and link count. From an image, istat labels crtime
# "Created" and debugfs prints it with nanoseconds
stat /etc/passwd; istat -o 2048 image.dd 12; debugfs -R "stat <12>" part.img
# build a bodyfile (mactime format) for the whole fs, deleted entries included, then render it
fls -m / -r -o 2048 image.dd > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv; mactime -b bodyfile.txt 2024-01-01..2024-01-03
```

`relatime` (the default) updates atime only when it is older than mtime/ctime or older than 24h,
and `noatime` never does, so **never conclude "this file was never read."** `ctime` cannot be set
from userland -- `touch -d` rewinds atime/mtime but bumps ctime to now, so an old mtime beside a
ctime of this morning is the classic timestomp signature; `crtime > mtime` is stronger still,
since crtime needs raw inode writes to forge.

## Artifacts: logins, shells, keys

```sh
# successful auth, sudo, su, sshd - Debian/Ubuntu then RHEL; zgrep the rotated .gz copies too
grep -aE 'Accepted|sudo:|session opened|Failed password' var/log/auth.log
grep -aE 'Accepted|sudo:|USER_AUTH' var/log/secure; zgrep -a 'Accepted' var/log/auth.log.*.gz
# binary login databases: logins, failed logins, last login per uid, who was logged in
last -f var/log/wtmp; lastb -f var/log/btmp; utmpdump var/log/wtmp; utmpdump var/run/utmp
strings -a var/log/lastlog | head    # lastlog is a fixed-width array indexed by uid
# syslog, kern.log and the dmesg copy; then the systemd journal read straight from the image
grep -aiE 'usb|segfault|oom|iptables|denied' var/log/syslog var/log/kern.log var/log/dmesg
journalctl --file var/log/journal/*/system.journal -o verbose
journalctl --file var/log/journal/*/system.journal -u sshd.service --no-pager
# shell history for every user at once, with the file each hit came from
grep -r --include='.bash_history' --include='.zsh_history' -an . home/ root/
```

History pitfalls: `HISTFILE=/dev/null` and `unset HISTFILE` lose the session, `HISTSIZE=0`
disables in-memory history, `HISTCONTROL=ignorespace` drops any command typed with a leading
space. If `HISTTIMEFORMAT` was set, bash writes `#<epoch>` before each command; zsh extended
history writes `: <epoch>:<elapsed>;<command>`. Read in full, per user: `~/.bash_history`,
`~/.zsh_history`, `~/.python_history`; `~/.ssh/authorized_keys` (the #1 Linux persistence spot),
`~/.ssh/known_hosts` (hashed under `HashKnownHosts yes`, still crackable against a candidate
list), `~/.ssh/id_*`, `~/.ssh/config` (a `ProxyCommand` is code execution); `~/.viminfo` (recent
files, search history and register contents -- often an entire edited flag), `~/.lesshst`,
`~/.local/share/recently-used.xbel` (GTK recent files, XML with URIs); and `~/.bashrc`,
`~/.profile`, `~/.zshrc`, where persistence is a one-liner at the bottom.

## Artifacts: accounts and persistence

```sh
# uid 0 accounts other than root, then the hashes ($6 sha512crypt -m 1800, $y yescrypt -m 100),
# then root-equivalent groups and the sudo rules including NOPASSWD entries
awk -F: '$3==0 {print}' etc/passwd; cat etc/shadow
grep -E '^(sudo|wheel|adm|docker|lxd|admin):' etc/group; cat etc/sudoers etc/sudoers.d/*
# every cron location, per-user crontabs and at jobs
cat etc/crontab; ls -la etc/cron.d etc/cron.hourly etc/cron.daily etc/cron.weekly
grep -r . var/spool/cron/crontabs/; ls -la var/spool/cron/atjobs/
# systemd: admin units, vendor units, user units - what they execute, and the timers
grep -rH 'ExecStart' etc/systemd/system/ usr/lib/systemd/system/ home/*/.config/systemd/user/
grep -rl 'OnCalendar\|OnBootSec' etc/systemd/system/ usr/lib/systemd/system/
# legacy init persistence, then the classic userland rootkit (a preloaded .so hooking readdir)
cat etc/rc.local; ls -la etc/init.d/ etc/rc*.d/; cat etc/ld.so.preload etc/ld.so.conf.d/*
grep -r 'LD_PRELOAD' etc/environment etc/profile etc/profile.d/ home/*/.bashrc
# setuid/setgid binaries and file capabilities (cap_setuid=ep on a shell is instant root)
find . -perm -4000 -type f 2>/dev/null; find . -perm -2000 -type f 2>/dev/null; getcap -r . 2>/dev/null
# sshd and pam backdoors
grep -vE '^\s*#|^$' etc/ssh/sshd_config; grep -rn 'pam_exec\|pam_permit' etc/pam.d/
# what was installed and when, and which packaged files changed after install ("5" = md5 differs)
grep -E ' (install|upgrade) ' var/log/dpkg.log; cat var/log/apt/history.log; rpm -qa --last
rpm -Va | grep '^..5'; debsums -c 2>/dev/null
```

Live triage only (`/proc` is the source of truth on a running box):

```sh
# deleted-but-running binaries (the classic dropper signature), recovered straight from the fd
ls -l /proc/*/exe 2>/dev/null | grep deleted; cp /proc/1337/exe /tmp/recovered
# one process' argv, environment, cwd and fds; then sockets and modules vs /sys/module
tr '\0' ' ' < /proc/1337/cmdline; tr '\0' '\n' < /proc/1337/environ; ls -l /proc/1337/{cwd,fd}
cat /proc/net/tcp /proc/net/unix /proc/modules; ls /sys/module
```

## Code

```python
#!/usr/bin/env python3
"""Parse a Sleuth Kit `fls -m` bodyfile into a sorted MACB timeline.

Bodyfile = 11 pipe-delimited fields:
    MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
Rows sharing (time, inode) merge, so one event prints as "macb", "m.c." and so on.
Feed it:  fls -m / -r -o 2048 image.dd > bodyfile.txt
"""
import argparse
import collections
import datetime as dt
import re
import sys

FIELDS = ("atime", "mtime", "ctime", "crtime")
LETTER = {"atime": "a", "mtime": "m", "ctime": "c", "crtime": "b"}

def parse_line(line: str):
    """Return a dict for one bodyfile line, or None if it is unusable."""
    p = line.rstrip("\n").split("|")
    if len(p) < 11:
        return None
    times = {}
    for key, raw in zip(FIELDS, p[7:11]):
        try:
            times[key] = int(float(raw))
        except ValueError:
            times[key] = 0
    try:
        size = int(p[6])
    except ValueError:
        size = 0
    return {"name": p[1], "inode": p[2], "mode": p[3], "uid": p[4],
            "gid": p[5], "size": size, "times": times}

def to_epoch(spec: str) -> int:
    """Accept an epoch integer or "YYYY-MM-DD[ HH:MM:SS]", interpreted as UTC."""
    if spec.isdigit():
        return int(spec)
    fmt = "%Y-%m-%d %H:%M:%S" if " " in spec else "%Y-%m-%d"
    return int(dt.datetime.strptime(spec, fmt).replace(tzinfo=dt.timezone.utc).timestamp())

def build(rows, after=None, before=None, needle=None):
    """Collapse rows into {(epoch, inode, name): {letters}} plus the source row."""
    merged, meta = collections.defaultdict(set), {}
    for row in rows:
        if needle and not needle.search(row["name"]):
            continue
        for key, epoch in row["times"].items():
            if epoch <= 0 or (after and epoch < after) or (before and epoch > before):
                continue  # keep only timestamps inside the requested window
            ident = (epoch, row["inode"], row["name"])
            merged[ident].add(LETTER[key])
            meta[ident] = row
    return merged, meta

def macb(letters) -> str:
    return "".join(c if c in letters else "." for c in "macb")

def selftest() -> int:   # two sample rows, then check the merged MACB strings
    key = "/root/.ssh/authorized_keys"
    rows = [parse_line(s) for s in (
        f"0|{key}|12|r/rrw-------|0|0|742|1700000005|1700000005|1700000005|1699999000",
        "0|/tmp/x (deleted)|4021|r/rrw-r--r--|1000|1000|18|"
        "1700000100|1700000100|1700000100|1700000100")]
    assert all(rows)
    merged, meta = build(rows)
    assert macb(merged[(1700000005, "12", key)]) == "mac."
    assert macb(merged[(1699999000, "12", key)]) == "...b"
    assert macb(merged[(1700000100, "4021", "/tmp/x (deleted)")]) == "macb"
    assert meta[(1700000100, "4021", "/tmp/x (deleted)")]["size"] == 18
    print("selftest OK")
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bodyfile", nargs="?", default="bodyfile.txt")
    ap.add_argument("--after", type=to_epoch); ap.add_argument("--before", type=to_epoch)
    ap.add_argument("--grep", help="regex filter on the path")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    try:
        with open(args.bodyfile, errors="replace") as fh:
            rows = [r for r in map(parse_line, fh) if r]
    except FileNotFoundError:
        print(f"no such bodyfile: {args.bodyfile}", file=sys.stderr)
        return 1
    merged, meta = build(rows, args.after, args.before,
                         re.compile(args.grep) if args.grep else None)
    for ident in sorted(merged):
        row = meta[ident]
        when = dt.datetime.fromtimestamp(ident[0], dt.timezone.utc)
        print(f"{when:%Y-%m-%d %H:%M:%S}  {macb(merged[ident])}  {row['mode']:<12s} "
              f"{row['uid']:>5s}:{row['gid']:<5s} {row['size']:>10d}  {ident[1]:>9s}  {row['name']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Parse Linux wtmp / btmp / utmp binary records into login sessions.

struct utmp on 64-bit Linux is 384 bytes little-endian, 2 pad bytes after ut_type:
short ut_type; int32 ut_pid; char ut_line[32]; char ut_id[4]; char ut_user[32];
char ut_host[256]; short e_termination, e_exit; int32 ut_session, tv_sec, tv_usec;
int32 ut_addr_v6[4]; char pad[20].  Run: utmp_parse.py /var/log/wtmp --sessions
"""
import argparse
import datetime as dt
import ipaddress
import struct
import sys

RECORD = "<h2xi32s4s32s256shhiii4i20x"
SIZE = struct.calcsize(RECORD)
assert SIZE == 384, f"unexpected record size {SIZE}"
TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
         5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS"}

def cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")

def addr(words) -> str:
    """ut_addr_v6 holds an IPv4 in word 0 (rest zero), or a full IPv6."""
    if not any(words):
        return ""
    packed = b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)
    return str(ipaddress.IPv4Address(packed[:4]) if not any(words[1:])
               else ipaddress.IPv6Address(packed))

def records(blob: bytes):
    """Yield one dict per 384-byte record; a trailing partial record is ignored."""
    for off in range(0, len(blob) - SIZE + 1, SIZE):
        (ut, pid, line, uid_, user, host, _t, _e,
         _s, sec, usec, a0, a1, a2, a3) = struct.unpack_from(RECORD, blob, off)
        yield {"type": TYPES.get(ut, str(ut)), "type_id": ut, "pid": pid,
               "line": cstr(line), "id": cstr(uid_), "user": cstr(user),
               "host": cstr(host), "time": sec + usec / 1e6, "addr": addr((a0, a1, a2, a3))}

def stamp(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def sessions(recs):
    """Pair each USER_PROCESS with the DEAD_PROCESS that reuses its tty line."""
    open_on, out = {}, []
    for rec in recs:
        if rec["type_id"] == 7 and rec["user"]:
            open_on[rec["line"]] = rec
        elif rec["type_id"] == 8:
            start = open_on.pop(rec["line"], None)
            if start:
                out.append((start, rec["time"] - start["time"]))
        elif rec["type_id"] == 2:          # BOOT_TIME ends every open session
            out.extend((s, None) for s in open_on.values())
            open_on.clear()
    out.extend((s, None) for s in open_on.values())
    out.sort(key=lambda p: p[0]["time"])
    return out

def selftest() -> int:
    blob = struct.pack(RECORD, 7, 4242, b"pts/1", b"ts/1", b"ctfuser", b"10.13.37.5",
                       0, 0, 0, 1700000000, 0,
                       int.from_bytes(bytes([10, 13, 37, 5]), "little"), 0, 0, 0)
    assert len(blob) == SIZE
    recs = list(records(blob))
    assert len(recs) == 1 and recs[0]["user"] == "ctfuser" and len(sessions(recs)) == 1
    assert recs[0]["type"] == "USER_PROCESS" and recs[0]["line"] == "pts/1"
    assert recs[0]["addr"] == "10.13.37.5" and stamp(recs[0]["time"])[:10] == "2023-11-14"
    print("selftest OK")
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default="/var/log/wtmp")
    ap.add_argument("--sessions", action="store_true", help="pair logins with logouts")
    ap.add_argument("--user", help="only this username")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    try:
        with open(args.path, "rb") as fh:
            recs = [r for r in records(fh.read())
                    if not args.user or r["user"] == args.user]
    except FileNotFoundError:
        print(f"no such file: {args.path}", file=sys.stderr)
        return 1
    if args.sessions:
        for rec, dur in sessions(recs):
            length = "still logged in" if dur is None else f"{dur / 60:.1f} min"
            print(f"{stamp(rec['time'])}  {rec['user']:<16s} {rec['line']:<12s} "
                  f"{rec['host'] or rec['addr']:<40s} {length}")
        return 0
    for rec in recs:
        print(f"{stamp(rec['time'])}  {rec['type']:<13s} pid={rec['pid']:<7d} "
              f"{rec['user']:<16s} {rec['line']:<12s} {rec['host']:<40s} {rec['addr']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **`-o` is in sectors, not bytes.** `fsstat -o 2048` means byte 1048576; get it wrong and you
  get "Cannot determine file system type". `debugfs` has no `-o` at all.
- `debugfs -w` is writable: never pass `-w` to evidence, and never run `e2fsck` on it -- that
  replays and destroys exactly the journal entries you want.
- `extundelete` on ext4 usually recovers only file **names** (from directory blocks) and
  zero-length files, because the extents were zeroed. Names alone are still evidence.
- `fls` shows deleted names whose inode has since been reallocated, so the content you `icat`
  may belong to a newer file -- cross-check the size and crtime.
- `inline_data` stores small files inside the inode, so they never carve; read them out of
  `debugfs -R "stat"`. Sparse files behave similarly. LVM: `mmls` shows `Linux_LVM (0x8e)`, so
  run `losetup` + `vgchange -ay` or `kpartx -av` first, and start at `cryptsetup luksDump` for
  an encrypted one. Docker hides a second filesystem in `/var/lib/docker/overlay2/*/diff`.

## Tools

`sleuthkit` (`mmls`, `fsstat`, `fls`, `istat`, `icat`, `ifind`, `ffind`, `jls`, `jcat`,
`tsk_recover`, `blkls`, `mactime`), `e2fsprogs` (`debugfs`, `dumpe2fs`), `extundelete`,
`ext4magic`, `utmpdump`, `journalctl`, `plaso`, `autopsy`, `rkhunter`.

## References

- `man debugfs`, `man dumpe2fs`, `man fls`, `man mactime` document every flag used above, and
  the Sleuth Kit wiki defines the bodyfile (mactime) column order. `man 5 utmp` (glibc) defines
  the `struct utmp` layout the second parser implements.
