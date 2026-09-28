---
title: "Timeline Building - Bodyfiles, mactime and Super-Timelines"
category: forensics
subcategory: timeline
type: technique
tags: [timeline, super-timeline, plaso, log2timeline, psort, mactime, bodyfile, sleuthkit, fls, macb, timesketch, hayabusa, kape, timestomping, utc, dfir, incident-response]
difficulty: medium
summary: "Build a filesystem timeline with fls and mactime, a super-timeline with plaso, then merge everything into one sorted UTC CSV you can actually read."
when_to_use:
  - "The question is 'what happened, in what order' rather than 'find this one file'"
  - "You have a disk image plus logs plus a memory dump and need a single narrative"
  - "You have a known bad timestamp and want everything within a few minutes of it"
  - "You suspect timestomping and need to compare timestamp sources"
tools: [sleuthkit, fls, mactime, plaso, log2timeline, psort, pinfo, timesketch, hayabusa, mftecmd, bulk-extractor]
related: [disk-ntfs-mft, disk-windows-execution-artifacts, logs-analysis, disk-image-triage, disk-linux-forensics]
---

## TL;DR

`fls -r -m / image.dd > bodyfile` then `mactime -b bodyfile -d -z UTC` gives you the filesystem
timeline in two commands. `log2timeline.py` + `psort.py` gives you everything else. Then pivot:
take the one timestamp you trust and read 30 minutes either side.

## Concepts

**MACB** is the four timestamp roles, and they mean different things per filesystem:

| Letter | NTFS ($STANDARD_INFORMATION) | ext4 | HFS+/APFS |
| --- | --- | --- | --- |
| M | Last modified (content changed) | mtime | Content modified |
| A | Last accessed (often disabled) | atime | Last accessed |
| C | MFT entry modified (metadata) | ctime (inode changed) | Attribute modified |
| B | Born / created | crtime | Created |

**Reliability ranking**, most to least trustworthy in an intrusion:

1. Append-only or externally-shipped logs (a syslog server, cloud audit logs).
2. `$UsnJrnl`, `$LogFile`, journald with sealing, EVTX records with intact sequence numbers.
3. `$FILE_NAME` timestamps in the MFT (harder to stomp than `$SI`).
4. Registry key LastWrite times, prefetch run times, SRUM.
5. `$STANDARD_INFORMATION` timestamps -- trivially forgeable by user-mode code.
6. Anything the suspect process could rewrite freely (application logs, bash history).

**Always work in UTC.** Record the system's timezone
(`SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, `/etc/timezone`,
`/etc/localtime`) and convert once, at ingest.

## Sleuthkit: the filesystem timeline

```sh
# find the partition offset first
mmls image.dd
# bodyfile: -m prefixes the mount point, -r recurses, -p gives full paths
fls -r -m / -o 2048 image.dd > bodyfile
# include deleted entries explicitly (default fls already shows them, marked *)
fls -r -m / -o 2048 -p image.dd > bodyfile
# add unallocated inode metadata (files whose name is gone but whose inode survives)
ils -m -o 2048 image.dd >> bodyfile
# a mounted live directory instead of an image
mac-robber /mnt/evidence > bodyfile
# windows: MFTECmd can emit a bodyfile too
MFTECmd.exe -f '$MFT' --body . --bodyf mft.body --bdl C
```

Bodyfile format (pipe-delimited, 11 fields):

```
MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
0|/etc/passwd|131074|r/rrw-r--r--|0|0|2891|1705309924|1705309920|1705309920|1698000000
```

All four times are Unix epoch seconds. `0` or an empty field means "not recorded".

```sh
# render the timeline, UTC, one line per MACB event
mactime -b bodyfile -d -z UTC > timeline.csv
# human-readable (default) instead of comma-delimited
mactime -b bodyfile -z UTC > timeline.txt
# restrict to a date range (inclusive)
mactime -b bodyfile -d -z UTC 2024-01-15..2024-01-16 > window.csv
# from a date onwards
mactime -b bodyfile -d -z UTC 2024-01-15 > since.csv
# with a UID->name map so ownership is readable
mactime -b bodyfile -d -z UTC -p /mnt/img/etc/passwd -u /mnt/img/etc/group > timeline.csv
# yearly/monthly index files instead of one huge output
mactime -b bodyfile -z UTC -i day dayindex.txt -i hour hourindex.txt > timeline.txt
# a different timezone when you need the analyst's local view
mactime -b bodyfile -d -z America/New_York > local.csv
```

`mactime` CSV columns are:
`Date,Size,Type,Mode,UID,GID,Meta,File Name`, where `Type` is the MACB letters that fired at that
instant (e.g. `.a..`, `m...`, `macb`). An entry showing `macb` all at once is a freshly created
file; `m.c.` with an old `b` is a modification.

## Plaso: the super-timeline

```sh
# install
pip install plaso   # or use the docker image / distro package
# ingest a whole disk image, all partitions, all VSS stores
log2timeline.py --status_view window --storage-file case.plaso image.dd
log2timeline.py --partitions all --vss_stores all --storage-file case.plaso image.E01
# a directory of collected artefacts (KAPE output, a triage collection)
log2timeline.py --storage-file case.plaso ./kape_out/
# one file (an EVTX, a registry hive, a browser database)
log2timeline.py --storage-file evtx.plaso ./Security.evtx
# restrict the parsers - this is the single biggest speed win
log2timeline.py --parsers 'win7,!filestat' --storage-file case.plaso image.dd
log2timeline.py --parsers 'winevtx,winreg,prefetch,lnk,mft,usnjrnl' --storage-file case.plaso image.dd
log2timeline.py --parsers 'linux' --storage-file case.plaso linux.dd
# list every available parser and preset
log2timeline.py --parsers list
log2timeline.py --info
# hash every file as it goes (useful for IOC matching later)
log2timeline.py --hashers md5,sha256 --storage-file case.plaso image.dd
# set the source timezone when the image does not declare one
log2timeline.py --timezone UTC --storage-file case.plaso image.dd
# what is in the storage file?
pinfo.py case.plaso
pinfo.py --sections events case.plaso
# render: dynamic is the readable one, l2tcsv is the classic 17-column format
psort.py -o dynamic -w timeline.csv case.plaso
psort.py -o l2tcsv -w timeline_l2t.csv case.plaso
psort.py -o json_line -w timeline.jsonl case.plaso
psort.py -o tln -w timeline.tln case.plaso
# filter with the plaso filter expression language
psort.py -o dynamic -w window.csv case.plaso \
  "date > '2024-01-15 08:00:00' AND date < '2024-01-15 12:00:00'"
psort.py -o dynamic -w reg.csv case.plaso "parser == 'winreg'"
psort.py -o dynamic -w evt.csv case.plaso "parser contains 'winevtx' AND message contains '4688'"
psort.py -o dynamic -w user.csv case.plaso "username == 'alice'"
# a slice around a known-bad time (minutes either side)
psort.py --slice '2024-01-15T09:12:04' --slice_size 30 -o dynamic -w slice.csv case.plaso
# deduplicate near-identical events
psort.py --no_deduplicate -o dynamic -w all.csv case.plaso
# choose output columns
psort.py -o dynamic --fields datetime,timestamp_desc,source,source_long,message,parser,display_name \
  -w timeline.csv case.plaso
```

`timestamp_desc` tells you **which** timestamp produced the row: `Creation Time`,
`Content Modification Time`, `Metadata Modification Time`, `Last Access Time`,
`Last Time Executed`, `Last Written Time`, `Expiration Time`. This column is the whole point of a
super-timeline -- it distinguishes "the file was created" from "the registry key was written".

Timesketch is the usual viewer:

```sh
# import a plaso storage file
timesketch_importer --host http://localhost --sketch_id 1 case.plaso
# or a CSV with datetime, timestamp_desc and message columns
timesketch_importer --host http://localhost --sketch_id 1 timeline.csv
```

## Sources to merge into a super-timeline

| Source | What it dates | Extract with |
| --- | --- | --- |
| `$MFT` `$SI` and `$FN` | File create/modify/access/MFT-change | `MFTECmd -f $MFT --csv .`, `analyzeMFT.py` |
| `$UsnJrnl:$J` | Every file create/rename/delete, with reasons | `MFTECmd -f $J --csv .` |
| `$LogFile` | Transaction-level file operations | `LogFileParser.exe` |
| EVTX | Logons, process creation, services, PowerShell | `EvtxECmd -d . --csv .`, `hayabusa csv-timeline` |
| Prefetch | Last 8 execution times per binary | `PECmd.exe -d Prefetch --csv .` |
| Registry LastWrite | When a key was last modified | `RECmd.exe --bn Kroll.reg`, `RegRipper` |
| ShimCache / AmCache | Binaries the system saw | `AppCompatCacheParser`, `AmcacheParser` |
| SRUM | Per-app network and CPU usage per hour | `SrumECmd -f SRUDB.dat --csv .` |
| LNK / Jump Lists | File opens, with the target's own timestamps | `LECmd`, `JLECmd` |
| Recycle Bin `$I` | Deletion time and original path | `RBCmd`, `rifiuti-vista` |
| Shellbags | Folder browsing | `SBECmd -d . --csv .` |
| Browser history | Visits, downloads, form fills | `sqlite3` queries, plaso |
| `bash_history` | Commands, **only** if `HISTTIMEFORMAT` was set | `cat`, plus `stat` on the file |
| journald / syslog / auth.log | Services, logins, sudo | `journalctl -o short-iso`, plaso |
| `wtmp` / `btmp` | Login sessions | `last -f wtmp`, plaso |
| Docker `*-json.log` | Container stdout with RFC3339 timestamps | `jq -r '.time + " " + .log'` |
| Web access logs | Requests | `awk`, plaso |
| Memory | Process start times, network connections | `vol3 timeliner.Timeliner -r csv` |
| Cloud audit logs | API calls | `jq`, plaso |

```sh
# memory into the same timeline
vol3 -f mem.raw -r csv timeliner.Timeliner > mem_timeline.csv
# EVTX, already sorted and normalised
hayabusa csv-timeline -d ./evtx -o evtx_timeline.csv
# MFT into a csv with ISO timestamps
MFTECmd.exe -f '$MFT' --csv . --csvf mft.csv
# docker json logs
jq -r '[.time, .stream, (.log|rtrimstr("\n"))] | @csv' container-json.log > docker_timeline.csv
# journald as ISO
journalctl --file ./system.journal -o short-iso --no-pager > journal.txt
```

## Analysing the timeline

```sh
# pivot around a known event: 15 minutes either side
awk -F',' '$1 >= "2024-01-15T09:00:00" && $1 <= "2024-01-15T09:30:00"' super.csv
# what happened in the same second as the malware's creation
grep '2024-01-15 09:12:04' super.csv
# files created under a user profile during the intrusion window
grep -i 'Users\\alice' window.csv | grep -i 'Creation Time'
# executables written anywhere
grep -iE '\.(exe|dll|ps1|bat|vbs|scr|jar)' window.csv | grep -i 'Creation'
# load it into sqlite and ask real questions
sqlite3 -csv timeline.db ".import timeline.csv events" \
  "SELECT datetime, source, message FROM events WHERE message LIKE '%powershell%' LIMIT 50;"
# or use q / csvkit without a database
q -H -d, "SELECT datetime, message FROM ./timeline.csv WHERE message LIKE '%Temp%' LIMIT 40"
csvsql --query "SELECT * FROM timeline WHERE datetime > '2024-01-15'" timeline.csv
# count events per hour to find the burst
cut -c1-13 super.csv | sort | uniq -c | sort -rn | head -20
```

### Spotting timestomping in a timeline

- `$SI` created **after** `$SI` modified, or either **before** the OS install date.
- `$SI` timestamps whose sub-second component is exactly `.0000000` while neighbours are not.
- `$FN` and `$SI` disagreeing by more than a few milliseconds on a file that was never moved.
- An MFT record number far higher than its neighbours' but with a much older creation time
  (record numbers are allocated roughly in order).
- A file whose `$UsnJrnl` FILE_CREATE entry is hours after its claimed creation time.
- Sysmon Event ID 2 (`A process changed a file creation time`) firing at all.

### Spotting anti-forensics gaps

- A period with **zero** filesystem events on a machine that was clearly running.
- EVTX record identifiers that jump.
- `wtmp` smaller than `btmp`, or either truncated to zero.
- Prefetch files missing for binaries that ShimCache says ran.
- `1102`/`104` log-cleared events, or a `Security.evtx` whose earliest record is very recent.

### The CTF shortcut

Before you build anything elaborate:

```sh
# just grep the bodyfile for the flag-ish filename
grep -i 'flag\|secret\|password\|README' bodyfile
# and sort the whole filesystem by creation time, newest first
mactime -b bodyfile -d -z UTC | tail -50
# the most recently modified files under the user profiles
mactime -b bodyfile -d -z UTC | grep -i 'Users/' | tail -100
```

## Code

```python
#!/usr/bin/env python3
"""Parse a Sleuthkit bodyfile into a normalised ISO-8601 UTC MACB timeline.

    fls -r -m / -o 2048 image.dd > bodyfile
    python3 bodyfile_timeline.py bodyfile --since 2024-01-15 --until 2024-01-16
    python3 bodyfile_timeline.py bodyfile --csv timeline.csv
    python3 bodyfile_timeline.py --selftest
"""
from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime, timezone

FIELDS = ("md5", "name", "inode", "mode", "uid", "gid", "size",
          "atime", "mtime", "ctime", "crtime")
ROLES = (("atime", "a"), ("mtime", "m"), ("ctime", "c"), ("crtime", "b"))


def parse_line(line: str) -> dict[str, str] | None:
    parts = line.rstrip("\n").split("|")
    if len(parts) < 11:
        return None
    return dict(zip(FIELDS, parts[:11]))


def to_iso(epoch: str) -> str | None:
    try:
        value = int(float(epoch))
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def events(path: str) -> list[dict[str, str]]:
    """One row per distinct timestamp, with the MACB letters that fired at it."""
    out: list[dict[str, str]] = []
    handle = sys.stdin if path == "-" else open(path, "r", encoding="utf-8", errors="replace")
    try:
        for line in handle:
            if not line.strip() or line.startswith("#"):
                continue
            rec = parse_line(line)
            if rec is None:
                continue
            by_time: dict[str, list[str]] = {}
            for field, letter in ROLES:
                iso = to_iso(rec.get(field, ""))
                if iso:
                    by_time.setdefault(iso, []).append(letter)
            for iso, letters in by_time.items():
                macb = "".join(l if l in letters else "." for l in "macb")
                out.append({
                    "datetime": iso,
                    "macb": macb,
                    "size": rec.get("size", ""),
                    "mode": rec.get("mode", ""),
                    "uid": rec.get("uid", ""),
                    "gid": rec.get("gid", ""),
                    "inode": rec.get("inode", ""),
                    "path": rec.get("name", ""),
                    "source": "FILE",
                })
    finally:
        if handle is not sys.stdin:
            handle.close()
    out.sort(key=lambda r: (r["datetime"], r["path"]))
    return out


def selftest() -> int:
    import os
    import tempfile
    # crtime 1698000000 = 2023-10-22T18:40:00Z, the other three share 1705309920
    line = ("0|/tmp/evil.sh|131074|r/rrwxr-xr-x|0|0|2891|"
            "1705309924|1705309920|1705309920|1698000000\n")
    line2 = "0|/etc/hosts|9|r/rrw-r--r--|0|0|180|0|1705309920|1705309920|1705309920\n"
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as fh:
        fh.write(line + line2)
    try:
        rows = events(path)
        assert len(rows) == 4, [r["datetime"] for r in rows]
        by_path = {}
        for r in rows:
            by_path.setdefault(r["path"], []).append(r)
        evil = sorted(by_path["/tmp/evil.sh"], key=lambda r: r["datetime"])
        assert evil[0]["macb"] == "...b", evil[0]
        assert evil[0]["datetime"].startswith("2023-10-22"), evil[0]
        assert evil[1]["macb"] == "m.c.", evil[1]
        assert evil[2]["macb"] == ".a..", evil[2]
        hosts = by_path["/etc/hosts"]
        assert len(hosts) == 1 and hosts[0]["macb"] == "m.cb", hosts
        assert to_iso("0") is None and to_iso("") is None and to_iso("abc") is None
        assert parse_line("too|few|fields") is None
    finally:
        os.unlink(path)
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bodyfile", nargs="?", help="fls -m output, or - for stdin")
    ap.add_argument("--since", help="ISO date/time lower bound, e.g. 2024-01-15")
    ap.add_argument("--until", help="ISO date/time upper bound")
    ap.add_argument("--grep", help="only paths containing this substring (case-insensitive)")
    ap.add_argument("--csv", help="write CSV here instead of printing a table")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not args.bodyfile:
        return selftest()

    try:
        rows = events(args.bodyfile)
    except FileNotFoundError:
        print(f"no such file: {args.bodyfile}", file=sys.stderr)
        return 1

    needle = args.grep.lower() if args.grep else None
    kept = []
    for row in rows:
        if args.since and row["datetime"] < args.since:
            continue
        if args.until and row["datetime"] > args.until:
            continue
        if needle and needle not in row["path"].lower():
            continue
        kept.append(row)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(kept[0].keys()) if kept else
                                    ["datetime", "macb", "size", "mode", "uid", "gid",
                                     "inode", "path", "source"])
            writer.writeheader()
            writer.writerows(kept)
        print(f"[+] {len(kept)} events -> {args.csv}", file=sys.stderr)
        return 0

    for row in kept:
        print(f"{row['datetime']:<26} {row['macb']}  {row['size']:>10}  "
              f"{row['mode']:<14} {row['uid']}:{row['gid']}  {row['path']}")
    print(f"\n[+] {len(kept)}/{len(rows)} events", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Merge heterogeneous CSV timelines into one sorted UTC super-timeline.

Auto-detects the timestamp column by trying a list of common formats against
every column of the first few rows, so plaso, mactime, MFTECmd, hayabusa and
hand-made CSVs can all be merged without per-file configuration.

    python3 merge_timelines.py mft.csv evtx.csv prefetch.csv -o super.csv
    python3 merge_timelines.py *.csv -o super.csv --since 2024-01-15T08:00:00Z
    python3 merge_timelines.py --selftest
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from datetime import datetime, timezone

TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M", "%Y-%m-%d",
    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
    "%a %b %d %Y %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z",
)
EPOCH_RE = re.compile(r"^\d{9,19}$")
TIME_COLUMN_HINTS = ("datetime", "date", "time", "timestamp", "created", "when",
                     "lastmodified", "firstrun", "lastrun", "systemtime")


def parse_timestamp(value: str) -> datetime | None:
    value = (value or "").strip().strip('"')
    if not value:
        return None
    if EPOCH_RE.match(value):
        number = int(value)
        for divisor in (1, 1_000, 1_000_000, 1_000_000_000):
            candidate = number / divisor
            if 946_684_800 <= candidate <= 4_102_444_800:      # 2000..2100
                return datetime.fromtimestamp(candidate, tz=timezone.utc)
        return None
    cleaned = value.replace("Z", "+0000")
    cleaned = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", cleaned)
    for fmt in TIME_FORMATS:
        try:
            parsed = datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None \
            else parsed.astimezone(timezone.utc)
    return None


def detect_time_column(header: list[str], rows: list[dict[str, str]]) -> str | None:
    scored: list[tuple[int, int, str]] = []
    for column in header:
        hits = sum(1 for row in rows if parse_timestamp(row.get(column, "")) is not None)
        if not hits:
            continue
        hint = 1 if any(h in column.lower().replace("_", "").replace(" ", "")
                        for h in TIME_COLUMN_HINTS) else 0
        scored.append((hint, hits, column))
    if not scored:
        return None
    scored.sort(key=lambda t: (-t[0], -t[1], header.index(t[2])))
    return scored[0][2]


def load(path: str, sample: int = 30) -> tuple[str | None, list[dict[str, str]]]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        try:
            dialect = csv.Sniffer().sniff(fh.read(8192), delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        fh.seek(0)
        reader = csv.DictReader(fh, dialect=dialect)
        rows = [r for r in reader]
    if not rows:
        return None, []
    header = [h for h in (rows[0].keys()) if h]
    return detect_time_column(header, rows[:sample]), rows


def summarise(row: dict[str, str], time_column: str, limit: int = 300) -> str:
    bits = []
    for key, value in row.items():
        if key == time_column or not key or value in (None, "", "-"):
            continue
        bits.append(f"{key}={value}")
    return " | ".join(bits)[:limit]


def selftest() -> int:
    import tempfile
    assert parse_timestamp("2024-01-15T09:12:04Z").year == 2024
    assert parse_timestamp("2024-01-15 09:12:04").hour == 9
    assert parse_timestamp("1705309924").year == 2024
    assert parse_timestamp("1705309924000").year == 2024          # milliseconds
    assert parse_timestamp("01/15/2024 09:12:04").month == 1
    assert parse_timestamp("not a time") is None
    assert parse_timestamp("") is None
    assert parse_timestamp("12") is None

    with tempfile.TemporaryDirectory() as tmp:
        a = os.path.join(tmp, "mft.csv")
        with open(a, "w", newline="", encoding="utf-8") as fh:
            fh.write("Created0x10,FileName,Size\n"
                     "2024-01-15 09:12:04,evil.exe,1024\n"
                     "2024-01-14 08:00:00,notes.txt,12\n")
        b = os.path.join(tmp, "evtx.csv")
        with open(b, "w", newline="", encoding="utf-8") as fh:
            fh.write("datetime,EventId,Message\n"
                     "2024-01-15T09:12:05Z,4688,cmd.exe /c whoami\n")
        c = os.path.join(tmp, "epoch.csv")
        with open(c, "w", newline="", encoding="utf-8") as fh:
            fh.write("ts,what\n1705309930,logon\n")

        merged = []
        for path in (a, b, c):
            column, rows = load(path)
            assert column is not None, path
            for row in rows:
                stamp = parse_timestamp(row.get(column, ""))
                if stamp:
                    merged.append((stamp, os.path.basename(path), summarise(row, column)))
        merged.sort(key=lambda t: t[0])
        assert len(merged) == 4, merged
        assert merged[0][1] == "mft.csv" and "notes.txt" in merged[0][2], merged[0]
        assert merged[-1][1] == "epoch.csv", merged[-1]
        order = [m[1] for m in merged]
        assert order == ["mft.csv", "mft.csv", "evtx.csv", "epoch.csv"], order
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs", nargs="*", help="CSV timelines to merge")
    ap.add_argument("-o", "--output", help="write the merged CSV here (default: stdout table)")
    ap.add_argument("--since", help="drop events before this ISO timestamp")
    ap.add_argument("--until", help="drop events after this ISO timestamp")
    ap.add_argument("--grep", help="only rows whose summary contains this substring")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or not args.inputs:
        return selftest()

    since = parse_timestamp(args.since) if args.since else None
    until = parse_timestamp(args.until) if args.until else None
    needle = args.grep.lower() if args.grep else None

    merged: list[tuple[datetime, str, str]] = []
    for path in args.inputs:
        try:
            column, rows = load(path)
        except (FileNotFoundError, OSError) as exc:
            print(f"[!] {path}: {exc}", file=sys.stderr)
            continue
        if column is None:
            print(f"[!] {path}: no parseable timestamp column found, skipping", file=sys.stderr)
            continue
        kept = 0
        for row in rows:
            stamp = parse_timestamp(row.get(column, ""))
            if stamp is None:
                continue
            if since and stamp < since:
                continue
            if until and stamp > until:
                continue
            text = summarise(row, column)
            if needle and needle not in text.lower():
                continue
            merged.append((stamp, os.path.basename(path), text))
            kept += 1
        print(f"[+] {path}: time column {column!r}, {kept}/{len(rows)} rows kept",
              file=sys.stderr)

    merged.sort(key=lambda t: t[0])
    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["datetime_utc", "source", "summary"])
            for stamp, source, text in merged:
                writer.writerow([stamp.isoformat().replace("+00:00", "Z"), source, text])
        print(f"[+] {len(merged)} events -> {args.output}", file=sys.stderr)
    else:
        for stamp, source, text in merged:
            print(f"{stamp.isoformat().replace('+00:00', 'Z'):<26} {source:<20} {text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **A super-timeline of a full disk is unreadable.** A typical Windows image produces millions of
  events. Always filter: a time window, a parser set, or a username. Use `--slice`.
- `log2timeline.py` takes **hours** on a real image. In a CTF, restrict `--parsers` to what the
  scenario needs, or skip plaso and use targeted parsers plus the merge script above.
- **Timezone mistakes destroy timelines.** `mactime -z` sets the *output* zone; plaso's
  `--timezone` sets the assumed *source* zone for naive timestamps. Get both right.
- `fls` bodyfiles use **`$STANDARD_INFORMATION`** on NTFS, which is the stompable set. For `$FN`
  you need `MFTECmd` or `analyzeMFT`.
- `mactime` collapses identical timestamps across files into one block; do not mistake that for
  a single event.
- A **`0` timestamp** in a bodyfile means "not recorded", not 1970-01-01. Filter it out or it
  will dominate the top of your sorted timeline.
- Deleted files in a bodyfile have `(deleted)` or `(realloc)` appended to the name and their
  inode may have been reused -- their timestamps may belong to a different file entirely.
- **Volume Shadow Copies** multiply everything. `--vss_stores all` is thorough and slow; it also
  gives you the pre-intrusion state of files, which is often exactly what you want.
- Plaso deduplicates by default, which can hide a genuinely repeated event. `--no_deduplicate`
  when precision matters.
- Merge on **UTC epoch**, render in whatever zone you like, but keep one canonical column.

## Tools

`fls`/`ils`/`mactime`/`mac-robber` (sleuthkit), `log2timeline.py`/`psort.py`/`pinfo.py` (plaso),
`timesketch`, `MFTECmd`/`PECmd`/`LECmd`/`EvtxECmd`/`AppCompatCacheParser` (Eric Zimmerman),
`Timeline Explorer`, `hayabusa`, `chainsaw`, `KAPE`, `bulk_extractor`, `q`/`csvkit`/`sqlite3`.

## References

- `mactime -h` documents the bodyfile field order and the `-z`/`-d`/`-i` flags.
- `log2timeline.py --info` prints every parser, parser preset, hasher and output module your
  plaso build supports.
