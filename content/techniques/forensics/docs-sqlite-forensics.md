---
title: "SQLite Forensics - Browser History, WAL, and Deleted Rows"
category: forensics
subcategory: sqlite
type: technique
tags: [sqlite, wal, journal, freeblock, deleted-rows, browser-history, places-sqlite, chromium-history, cookies, firefox, chrome, safari, webkit-time, prtime, undark, sqlite-recover, dfir, carving]
difficulty: medium
summary: "Read a SQLite artifact correctly (including its -wal), convert every browser timestamp, and recover rows that were deleted but not vacuumed."
when_to_use:
  - "You have a browser profile, a chat app database, or an Android/iOS backup"
  - "A row you need was deleted and a plain SELECT returns nothing"
  - "The database was carved from RAM or unallocated space and is partial"
  - "Timestamps come back as 13-digit or 17-digit integers"
tools: [sqlite3, undark, bring2lite, walitean, python3, strings, hexdump, binwalk]
related: [memory-credential-extraction, disk-file-carving, docs-email-forensics, timeline-building]
---

## TL;DR

Copy the `.db`, `.db-wal` and `.db-shm` **together** or you will read stale data. Run
`.recover` before `.dump`. Every browser uses a different epoch: Chromium counts microseconds
from 1601, Firefox microseconds from 1970, Safari seconds from 2001. Deleted rows survive in
freeblocks until a `VACUUM`.

## File format essentials

The first 100 bytes are the database header:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 16 | Magic `SQLite format 3\x00` |
| 16 | 2 | Page size, big-endian. A value of `1` means 65536. |
| 18 | 1 | File format write version (1 = legacy/rollback, 2 = WAL) |
| 19 | 1 | File format read version |
| 20 | 1 | Reserved bytes per page |
| 24 | 4 | File change counter |
| 28 | 4 | Database size in pages |
| 32 | 4 | First freelist trunk page |
| 36 | 4 | Number of freelist pages |
| 40 | 4 | Schema cookie |
| 56 | 4 | Text encoding (1 = UTF-8, 2 = UTF-16LE, 3 = UTF-16BE) |
| 92 | 4 | Version-valid-for number |
| 96 | 4 | SQLite version that last wrote it |

Page types (first byte of each page): `0x02` interior index b-tree, `0x05` interior table b-tree,
`0x0A` leaf index b-tree, `0x0D` leaf table b-tree. Row data lives in leaf table pages: a page
header, then a cell-pointer array, then free space, then the cells growing backwards from the end.

A cell is: payload-length varint, rowid varint, record header (header-length varint + one serial
type varint per column), then the column values. Serial types: 0 NULL, 1-6 integers of 1/2/3/4/6/8
bytes, 7 float, 8 the literal 0, 9 the literal 1, `N>=12 and even` a BLOB of `(N-12)/2` bytes,
`N>=13 and odd` TEXT of `(N-13)/2` bytes.

```sh
# header at a glance
xxd -l 100 places.sqlite
# page size and encoding without a parser
python3 -c "import struct;d=open('places.sqlite','rb').read(100);print('page',struct.unpack_from('>H',d,16)[0],'pages',struct.unpack_from('>I',d,28)[0],'enc',struct.unpack_from('>I',d,56)[0])"
# is it WAL mode?
sqlite3 places.sqlite 'PRAGMA journal_mode;'
```

## Journals and WAL

| File | Magic | Meaning |
| --- | --- | --- |
| `db-journal` | `\xd9\xd5\x05\xf9\x20\xa1\x63\xd7` | Rollback journal: the *old* page images |
| `db-wal` | `\x37\x7f\x06\x82` (big-endian) or `\x37\x7f\x06\x83` | Write-ahead log: the *new* page images not yet checkpointed |
| `db-shm` | n/a | Shared-memory index for the WAL, regenerable |

**The WAL usually holds the most recent -- and most interesting -- data.** If a challenge gives you
a `.db-wal`, that is not an accident.

```sh
# always copy all three together
cp Places.sqlite Places.sqlite-wal Places.sqlite-shm ./work/
# merge the WAL into the main database (destructive to the WAL - work on a copy)
sqlite3 places.sqlite 'PRAGMA wal_checkpoint(TRUNCATE);'
# read WITHOUT checkpointing, by opening read-only with immutable
sqlite3 'file:places.sqlite?immutable=1' '.tables'
# inspect the WAL frames directly
xxd -l 32 places.sqlite-wal
# walitean carves records out of a WAL file
python3 walitean.py places.sqlite-wal
# what happens if you open the db WITHOUT the wal: you see the last checkpointed state only
sqlite3 places_nowal.sqlite 'SELECT count(*) FROM moz_places;'
```

## Reading a database

```sh
# open read-only so you never modify evidence
sqlite3 'file:History?mode=ro' 
# useful dot commands
sqlite3 History '.tables'
sqlite3 History '.schema urls'
sqlite3 History '.fullschema'
sqlite3 History 'PRAGMA integrity_check;'
sqlite3 History 'PRAGMA page_count; PRAGMA page_size; PRAGMA freelist_count;'
sqlite3 -header -column History 'SELECT * FROM urls LIMIT 5;'
sqlite3 -header -csv History 'SELECT * FROM urls;' > urls.csv
sqlite3 History '.mode box' '.headers on' 'SELECT * FROM downloads LIMIT 5;'
# dump everything as SQL
sqlite3 History '.dump' > dump.sql
# .recover rebuilds as much as it can from a corrupt or partial file - ALWAYS try this
sqlite3 History '.recover' > recovered.sql
sqlite3 recovered.db < recovered.sql
# a carved/partial database often refuses .dump but accepts .recover
sqlite3 carved.db '.recover' 2>/dev/null | grep -i 'INSERT INTO' | head
```

## Deleted rows

When a row is deleted, SQLite marks the cell space as a **freeblock** inside the page and updates
the cell-pointer array. The bytes themselves stay until the page is reused or `VACUUM` runs.

```sh
# is there anything to recover? a large freelist means yes
sqlite3 db 'PRAGMA freelist_count;'
# sqlite's own recovery pass picks up orphaned pages
sqlite3 db '.recover' > rec.sql && grep -c 'INSERT' rec.sql
# undark walks the pages and prints recoverable records
undark -i db -f                       # freespace only
undark -i db --table urls
# bring2lite does a thorough page/freeblock/WAL/journal carve
python3 bring2lite.py -f db -o out/
# the low-tech version that solves most CTFs
strings -a -t d db | grep -i 'http'
strings -a -t d db-wal | grep -i 'secret'
# and the manual one (see the script below)
python3 sqlite_freespace.py db --min 8
```

## Browser artifacts

### Firefox (`places.sqlite`, PRTime = microseconds since 1970-01-01 UTC)

```sh
# history with timestamps
sqlite3 places.sqlite "
SELECT datetime(v.visit_date/1000000, 'unixepoch') AS when_utc,
       p.url, p.title, v.visit_type, p.visit_count
FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id
ORDER BY v.visit_date DESC LIMIT 50;"
# bookmarks
sqlite3 places.sqlite "
SELECT datetime(b.dateAdded/1000000,'unixepoch'), b.title, p.url
FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk ORDER BY b.dateAdded DESC;"
# downloads (modern Firefox stores them as annotations)
sqlite3 places.sqlite "
SELECT datetime(a.dateAdded/1000000,'unixepoch'), p.url, a.content
FROM moz_annos a JOIN moz_places p ON p.id=a.place_id
WHERE a.anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name LIKE '%download%');"
# cookies
sqlite3 cookies.sqlite "
SELECT host, name, value, datetime(expiry,'unixepoch'),
       datetime(lastAccessed/1000000,'unixepoch') FROM moz_cookies LIMIT 50;"
# saved form values
sqlite3 formhistory.sqlite "
SELECT fieldname, value, timesUsed, datetime(firstUsed/1000000,'unixepoch')
FROM moz_formhistory ORDER BY timesUsed DESC;"
# saved logins are in logins.json, encrypted with key4.db
python3 firefox_decrypt.py /path/to/profile
```

### Chromium / Chrome / Edge / Brave (`History`, WebKit time = microseconds since 1601-01-01)

```sh
# the conversion: value/1000000 - 11644473600 gives a unix epoch
sqlite3 History "
SELECT datetime(v.visit_time/1000000 - 11644473600,'unixepoch') AS when_utc,
       u.url, u.title, u.visit_count, v.visit_duration
FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time DESC LIMIT 50;"
# downloads, including the full target path and the referrer
sqlite3 History "
SELECT datetime(start_time/1000000 - 11644473600,'unixepoch'),
       target_path, tab_url, referrer, received_bytes, total_bytes, danger_type
FROM downloads ORDER BY start_time DESC;"
# search terms typed in the omnibox
sqlite3 History "SELECT term, url FROM keyword_search_terms LIMIT 50;"
# cookies (values are AES-GCM encrypted on modern builds; the metadata still helps)
sqlite3 Cookies "
SELECT host_key, name, path,
       datetime(creation_utc/1000000 - 11644473600,'unixepoch'),
       datetime(expires_utc/1000000 - 11644473600,'unixepoch')
FROM cookies LIMIT 50;"
# saved passwords (password_value is DPAPI/keyring encrypted)
sqlite3 'Login Data' "SELECT origin_url, username_value, length(password_value) FROM logins;"
# autofill
sqlite3 'Web Data' "SELECT name, value, date_created FROM autofill LIMIT 50;"
# favicons can prove a site was visited even after history is cleared
sqlite3 Favicons "SELECT page_url FROM icon_mapping LIMIT 50;"
# top sites
sqlite3 'Top Sites' "SELECT url, title FROM top_sites;"
```

### Safari (`History.db`, Mac absolute time = seconds since 2001-01-01)

```sh
# the conversion: value + 978307200 gives a unix epoch
sqlite3 History.db "
SELECT datetime(v.visit_time + 978307200,'unixepoch') AS when_utc, i.url, v.title
FROM history_visits v JOIN history_items i ON i.id = v.history_item
ORDER BY v.visit_time DESC LIMIT 50;"
# downloads live in a plist, not sqlite
plutil -p ~/Library/Safari/Downloads.plist
```

### Epoch cheat sheet

| Source | Unit | Epoch | SQL conversion |
| --- | --- | --- | --- |
| Unix | seconds | 1970-01-01 | `datetime(t,'unixepoch')` |
| Firefox PRTime | microseconds | 1970-01-01 | `datetime(t/1000000,'unixepoch')` |
| Chromium / WebKit | microseconds | 1601-01-01 | `datetime(t/1000000 - 11644473600,'unixepoch')` |
| Windows FILETIME | 100-ns | 1601-01-01 | `datetime(t/10000000 - 11644473600,'unixepoch')` |
| Mac absolute (Cocoa) | seconds | 2001-01-01 | `datetime(t + 978307200,'unixepoch')` |
| Mac absolute (ns) | nanoseconds | 2001-01-01 | `datetime(t/1000000000 + 978307200,'unixepoch')` |
| Java / JS | milliseconds | 1970-01-01 | `datetime(t/1000,'unixepoch')` |
| Android (most) | milliseconds | 1970-01-01 | `datetime(t/1000,'unixepoch')` |

### Other apps worth knowing

```sh
# android sms and contacts
sqlite3 mmssms.db "SELECT datetime(date/1000,'unixepoch'), address, body FROM sms ORDER BY date DESC LIMIT 50;"
sqlite3 contacts2.db "SELECT display_name, data1 FROM raw_contacts JOIN data ON data.raw_contact_id=raw_contacts._id LIMIT 50;"
# ios
sqlite3 sms.db "SELECT datetime(date/1000000000 + 978307200,'unixepoch'), text FROM message ORDER BY date DESC LIMIT 50;"
sqlite3 CallHistory.storedata "SELECT datetime(ZDATE + 978307200,'unixepoch'), ZADDRESS FROM ZCALLRECORD;"
# discord/slack/teams local caches are leveldb, not sqlite - use a leveldb dumper
# signal/telegram desktop are sqlcipher: you need the key from the keyring/config
sqlcipher signal.db "PRAGMA key = \"x'<64-hex-key>'\"; .tables"
```

## Code

```python
#!/usr/bin/env python3
"""Open a SQLite artifact read-only, print its schema, and run the right history
query when the schema matches a known browser.

    python3 sqlite_browser.py History
    python3 sqlite_browser.py places.sqlite --limit 100
    python3 sqlite_browser.py unknown.db --sql "SELECT * FROM sqlite_master"
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys

CHROMIUM_HISTORY = """
SELECT datetime(v.visit_time/1000000 - 11644473600, 'unixepoch') AS utc,
       u.url, substr(COALESCE(u.title,''),1,80) AS title, u.visit_count
FROM visits v JOIN urls u ON u.id = v.url
ORDER BY v.visit_time DESC LIMIT ?
"""
CHROMIUM_DOWNLOADS = """
SELECT datetime(start_time/1000000 - 11644473600, 'unixepoch') AS utc,
       target_path, tab_url, received_bytes
FROM downloads ORDER BY start_time DESC LIMIT ?
"""
FIREFOX_HISTORY = """
SELECT datetime(v.visit_date/1000000, 'unixepoch') AS utc,
       p.url, substr(COALESCE(p.title,''),1,80) AS title, p.visit_count
FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id
ORDER BY v.visit_date DESC LIMIT ?
"""
SAFARI_HISTORY = """
SELECT datetime(v.visit_time + 978307200, 'unixepoch') AS utc,
       i.url, substr(COALESCE(v.title,''),1,80) AS title, i.visit_count
FROM history_visits v JOIN history_items i ON i.id = v.history_item
ORDER BY v.visit_time DESC LIMIT ?
"""
COOKIES_CHROMIUM = """
SELECT host_key, name,
       datetime(creation_utc/1000000 - 11644473600, 'unixepoch') AS created,
       datetime(expires_utc/1000000 - 11644473600, 'unixepoch') AS expires
FROM cookies ORDER BY creation_utc DESC LIMIT ?
"""
COOKIES_FIREFOX = """
SELECT host, name, datetime(lastAccessed/1000000,'unixepoch') AS accessed,
       datetime(expiry,'unixepoch') AS expires
FROM moz_cookies ORDER BY lastAccessed DESC LIMIT ?
"""

PROFILES: list[tuple[str, set[str], list[tuple[str, str]]]] = [
    ("Chromium History", {"urls", "visits"},
     [("history", CHROMIUM_HISTORY), ("downloads", CHROMIUM_DOWNLOADS)]),
    ("Firefox places.sqlite", {"moz_places", "moz_historyvisits"},
     [("history", FIREFOX_HISTORY)]),
    ("Safari History.db", {"history_items", "history_visits"},
     [("history", SAFARI_HISTORY)]),
    ("Chromium Cookies", {"cookies"}, [("cookies", COOKIES_CHROMIUM)]),
    ("Firefox cookies.sqlite", {"moz_cookies"}, [("cookies", COOKIES_FIREFOX)]),
    ("Chromium Login Data", {"logins"},
     [("logins", "SELECT origin_url, username_value, length(password_value) "
                 "AS pw_len FROM logins LIMIT ?")]),
]


def open_ro(path: str) -> sqlite3.Connection:
    uri = f"file:{os.path.abspath(path)}?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    return con


def table_names(con: sqlite3.Connection) -> set[str]:
    return {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def show(con: sqlite3.Connection, label: str, sql: str, limit: int) -> None:
    try:
        rows = con.execute(sql, (limit,)).fetchall()
    except sqlite3.Error as exc:
        print(f"  [{label}] query failed: {exc}")
        return
    if not rows:
        print(f"  [{label}] no rows")
        return
    cols = rows[0].keys()
    print(f"\n-- {label} ({len(rows)} rows)")
    print("  " + " | ".join(cols))
    for r in rows:
        print("  " + " | ".join(str(r[c])[:90] for c in cols))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("db")
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--sql", help="run this SQL instead of the auto-detected queries")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"no such file: {args.db}", file=sys.stderr)
        return 1
    for side in ("-wal", "-journal"):
        if os.path.exists(args.db + side):
            print(f"[!] {os.path.basename(args.db)}{side} exists - it may hold newer data "
                  f"than the main file", file=sys.stderr)

    try:
        con = open_ro(args.db)
    except sqlite3.Error as exc:
        print(f"cannot open: {exc}\n"
              f"try:  sqlite3 {args.db} '.recover' > rec.sql", file=sys.stderr)
        return 1

    with con:
        tables = table_names(con)
        print(f"== {len(tables)} tables: {', '.join(sorted(tables)) or '(none)'}")
        try:
            page_count = con.execute("PRAGMA page_count").fetchone()[0]
            page_size = con.execute("PRAGMA page_size").fetchone()[0]
            freelist = con.execute("PRAGMA freelist_count").fetchone()[0]
            print(f"== {page_count} pages of {page_size} bytes, {freelist} on the freelist")
            if freelist:
                print("   free pages present -> deleted rows may be recoverable "
                      "(sqlite3 db '.recover', undark, bring2lite)")
        except sqlite3.Error:
            pass

        if args.sql:
            try:
                rows = con.execute(args.sql).fetchall()
            except sqlite3.Error as exc:
                print(f"query failed: {exc}", file=sys.stderr)
                return 1
            for r in rows:
                print(" | ".join(str(v)[:120] for v in tuple(r)))
            return 0

        matched = False
        for name, required, queries in PROFILES:
            if required <= tables:
                matched = True
                print(f"\n== recognised as {name}")
                for label, sql in queries:
                    show(con, label, sql, args.limit)
        if not matched:
            print("\n== unknown schema; dumping the first rows of every table")
            for t in sorted(tables):
                if t.startswith("sqlite_"):
                    continue
                show(con, t, f'SELECT * FROM "{t}" LIMIT ?', min(args.limit, 10))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Scan a SQLite file's pages for freeblocks and unallocated space and print the
printable strings found there - i.e. the remnants of deleted rows.

Pure stdlib, no sqlite3 involvement, so it works on carved and corrupt files.

    python3 sqlite_freespace.py History --min 8
    python3 sqlite_freespace.py places.sqlite --grep 'secret'
"""
from __future__ import annotations

import argparse
import re
import struct
import sys

HEADER_MAGIC = b"SQLite format 3\x00"
PAGE_TYPES = {0x02: "interior-index", 0x05: "interior-table",
              0x0A: "leaf-index", 0x0D: "leaf-table"}


def read_header(data: bytes) -> tuple[int, int]:
    if not data.startswith(HEADER_MAGIC):
        raise ValueError("not a SQLite database (bad magic)")
    page_size = struct.unpack_from(">H", data, 16)[0]
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size & (page_size - 1):
        raise ValueError(f"implausible page size {page_size}")
    reserved = data[20]
    return page_size, reserved


def page_regions(page: bytes, is_first: bool) -> list[tuple[int, int, str]]:
    """Return (offset_in_page, length, kind) for freeblocks and unallocated gap."""
    base = 100 if is_first else 0
    if len(page) <= base:
        return []
    ptype = page[base]
    if ptype not in PAGE_TYPES:
        return [(base, len(page) - base, "non-btree")]
    hdr_len = 12 if ptype in (0x02, 0x05) else 8
    try:
        first_free = struct.unpack_from(">H", page, base + 1)[0]
        ncells = struct.unpack_from(">H", page, base + 3)[0]
        content_start = struct.unpack_from(">H", page, base + 5)[0]
    except struct.error:
        return []
    content_start = 65536 if content_start == 0 else content_start

    regions: list[tuple[int, int, str]] = []
    # unallocated gap between the cell pointer array and the cell content area
    cell_array_end = base + hdr_len + ncells * 2
    if content_start > cell_array_end:
        regions.append((cell_array_end, content_start - cell_array_end, "unallocated"))

    # walk the freeblock chain
    off = first_free
    guard = 0
    while off and guard < 4096:
        guard += 1
        if off + 4 > len(page):
            break
        try:
            nxt, size = struct.unpack_from(">HH", page, off)
        except struct.error:
            break
        if size < 4 or off + size > len(page):
            break
        regions.append((off, size, "freeblock"))
        if nxt <= off:
            break
        off = nxt
    return regions


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("db")
    ap.add_argument("--min", type=int, default=6, help="minimum string length")
    ap.add_argument("--grep", help="only print strings matching this regex")
    ap.add_argument("--kinds", default="freeblock,unallocated,non-btree",
                    help="comma list of region kinds to scan")
    args = ap.parse_args()

    try:
        with open(args.db, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        print(f"no such file: {args.db}", file=sys.stderr)
        return 1

    try:
        page_size, reserved = read_header(data)
    except ValueError as exc:
        print(f"{exc}; scanning the whole file as one blob", file=sys.stderr)
        page_size, reserved = len(data) or 1, 0

    wanted = {k.strip() for k in args.kinds.split(",") if k.strip()}
    strpat = re.compile(rb"[\x20-\x7e]{%d,}" % args.min)
    needle = re.compile(args.grep.encode(), re.I) if args.grep else None

    npages = max(1, len(data) // page_size)
    total_free = 0
    printed = 0
    for pno in range(npages):
        start = pno * page_size
        page = data[start:start + page_size - reserved]
        if not page:
            continue
        for off, length, kind in page_regions(page, is_first=(pno == 0)):
            if kind not in wanted:
                continue
            total_free += length
            blob = page[off:off + length]
            for m in strpat.finditer(blob):
                text = m.group(0).decode("latin-1")
                if needle and not needle.search(m.group(0)):
                    continue
                abs_off = start + off + m.start()
                print(f"page {pno + 1:>6}  0x{abs_off:08x}  {kind:<12} {text}")
                printed += 1

    print(f"\n[+] {npages} pages of {page_size} bytes, {total_free} bytes of free space, "
          f"{printed} strings printed", file=sys.stderr)
    if printed == 0:
        print("    nothing in free space; try `sqlite3 db '.recover'`, the -wal file, "
              "or undark/bring2lite", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **Forgetting the `-wal`** is the single most common mistake. A database whose `moz_places` looks
  empty may have every row sitting in the WAL.
- `VACUUM` (and Chromium's periodic history expiry) permanently destroys free-space remnants. A
  freelist count of zero means there is probably nothing to recover.
- A **carved** database is usually truncated. `sqlite3 db '.dump'` fails; `'.recover'` still works
  and salvages whole pages.
- Chromium stores cookie values **AES-GCM encrypted** with a key from the OS keyring/DPAPI. The
  metadata (host, name, timestamps) is still plaintext and often enough.
- `sqlite3` will silently **create** an empty database if you typo the filename. Check the file
  size afterwards.
- Opening with `mode=ro` still allows SQLite to write the `-shm`/`-wal`; use `immutable=1` on
  read-only media.
- Timestamps of `0` or `86400000000` are placeholders, not real times.
- Android/iOS backups store databases inside an encrypted container; decrypt first
  (`iphone_backup_decrypt`, `abe.jar` for Android backups).
- `PRAGMA integrity_check` on a partially carved file may hang; add `PRAGMA quick_check` instead.

## Tools

`sqlite3` (with `.recover`), `undark`, `bring2lite`, `walitean`, `sqlitebrowser`,
`SQLite Forensic Explorer`/`FQLite`, `python3` (`sqlite3`, `struct`), `strings`, `binwalk`,
`firefox_decrypt`, `sqlcipher`.

## References

- The SQLite file format is fully documented in the official "Database File Format" page shipped
  with the SQLite source tree.
- `sqlite3 -help` and `.help` inside the shell list every dot command including `.recover`.
