---
title: "Social Media Forensics and Archive Recovery"
category: osint
subcategory: social
type: technique
tags: [osint, socmint, snowflake, discord-id, twitter-id, timestamp, deleted-content, wayback, archive-today, rss, cdn-url, timezone, post-id, metadata, recovery]
difficulty: medium
summary: "Post IDs encode creation time, archives hold deleted content, and posting patterns leak timezone - all without touching the account."
when_to_use:
  - "You need the exact time a post, account or message was created"
  - "The content you need was deleted or edited"
  - "You must prove two accounts belong to the same person from behaviour alone"
  - "A challenge references a post that no longer exists"
tools: [python3, wayback, archive.today, exiftool, curl, jq]
related: [osint-methodology, osint-people-pivoting, osint-infrastructure, osint-documents-and-code, osint-tools-cheatsheet]
---

## TL;DR

Two mechanical facts do most of the work: **IDs encode timestamps** (Twitter/X and Discord
snowflakes both embed milliseconds since a platform epoch), and **archives keep what was
deleted** (Wayback, archive.today, RSS remnants, search-engine snippets). Everything else is
correlation: posting hours, language, image CDN paths and follower overlap.

## Recognise it

- The challenge gives a numeric ID, a status URL, or a message link.
- A profile says "this post was deleted" or the account was renamed.
- You need a date and the visible timestamp is relative ("3 years ago").
- Two handles that might be the same person, with no explicit link between them.

## Snowflake IDs

A snowflake packs a timestamp, a machine/worker id and a sequence number into 64 bits. The
timestamp is the top 42 bits, measured in milliseconds since a platform-specific epoch.

| Platform | Epoch | Extraction |
| --- | --- | --- |
| Discord | 2015-01-01T00:00:00Z (1420070400000 ms) | `(id >> 22) + 1420070400000` |
| Twitter/X (post-2010 ids) | 2010-11-04T01:42:54.657Z (1288834974657 ms) | `(id >> 22) + 1288834974657` |
| Instagram (media ids) | 2011-01-01 (1314220021721 ms in the common shard scheme) | varies by shard scheme |

Discord is exact and reliable. Twitter/X snowflakes apply to IDs issued after the snowflake
migration; very old status IDs are sequential, not snowflakes, and cannot be decoded this way.

```bash
# Discord: id -> UTC timestamp
python3 -c "import datetime;i=int(input());print(datetime.datetime.fromtimestamp(((i>>22)+1420070400000)/1000, datetime.UTC))"
```

A Discord message link is `https://discord.com/channels/<guild>/<channel>/<message>` - all
three components are snowflakes, so you get the guild's creation time, the channel's, and the
message's from one URL.

## Archive recovery

```bash
# every snapshot of one URL
curl -s 'https://web.archive.org/cdx/search/cdx?url=example.com/page&output=json&fl=timestamp,statuscode,digest'

# the closest snapshot to a date
curl -s 'https://archive.org/wayback/available?url=example.com/page&timestamp=20210601' | jq .

# a specific snapshot, with `id_` to get the ORIGINAL bytes (no archive toolbar/rewriting)
curl -s 'https://web.archive.org/web/20210601000000id_/https://example.com/page'

# all archived URLs under a host, deduplicated
curl -s 'https://web.archive.org/cdx/search/cdx?url=example.com*&fl=original&collapse=urlkey'

# archive.today mirrors pages the Internet Archive misses (it saves on request and
# renders JavaScript); search it by URL in a browser
```

Other places deleted content survives:

- **RSS/Atom feeds** that were cached by a reader or a proxy.
- **Search-engine snippets** - the text under a result often survives the page.
- **Quote posts, screenshots and replies** by other accounts, which are not deleted when the
  original is.
- **Platform data-export archives** that someone published.
- **Image CDNs**: the media file frequently stays reachable after the post is removed, because
  it is served from a separate, content-addressed host.
- **Link shorteners and preview cards** (an unfurled preview keeps the title and description).

## Timestamps beyond IDs

| Source | What it gives |
| --- | --- |
| HTTP `Last-Modified` / `ETag` | when a static asset changed |
| Wayback snapshot timestamp | an upper bound on when content existed |
| EXIF `DateTimeOriginal` + `OffsetTimeOriginal` | when a photo was taken, and in which UTC offset |
| `GPSDateStamp`/`GPSTimeStamp` | UTC time from the GPS receiver, independent of the clock |
| Certificate `notBefore` | when a domain's certificate was issued |
| Domain `Creation Date` | when the persona's infrastructure was set up |
| Git commit `author date` vs `committer date` | the original write vs the rebase |
| File system mtime in an archive/zip | when a file was last written (local time, no zone) |

Cross-check at least two. A conflict is itself a finding: it usually means a rebase, a
re-upload, or a deliberately planted decoy.

## Behavioural correlation

- **Posting-hour histogram** -> the quiet 6-8 hours is their night -> UTC offset.
- **Day-of-week pattern** -> weekday vs weekend activity, and which days count as the weekend
  (Friday/Saturday in much of the Middle East).
- **Burstiness** -> automated posting has an unnaturally regular interval.
- **Language, spelling and emoji choice** -> locale and keyboard.
- **Client string**, when the platform shows it -> device and OS.
- **Follower/following overlap** between two accounts.

## Code

```python
#!/usr/bin/env python3
"""Social forensics helpers: snowflake decoding, archive URL construction,
posting-pattern analysis.

  python3 social.py discord 175928847299117063
  python3 social.py twitter 1541815603606036480
  python3 social.py archive https://example.com/page 20210601
  python3 social.py --selftest
"""
from __future__ import annotations

import datetime as dt
import re
import sys
import urllib.parse
from collections import Counter

DISCORD_EPOCH_MS = 1_420_070_400_000      # 2015-01-01T00:00:00Z
TWITTER_EPOCH_MS = 1_288_834_974_657      # 2010-11-04T01:42:54.657Z
SNOWFLAKE_TIMESTAMP_SHIFT = 22


def snowflake_to_datetime(snowflake: int, epoch_ms: int) -> dt.datetime:
    """Decode the timestamp out of a 64-bit snowflake id."""
    ms = (snowflake >> SNOWFLAKE_TIMESTAMP_SHIFT) + epoch_ms
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc)


def datetime_to_snowflake(when: dt.datetime, epoch_ms: int) -> int:
    """The smallest snowflake issued at or after `when` (useful for range queries)."""
    ms = int(when.timestamp() * 1000) - epoch_ms
    return ms << SNOWFLAKE_TIMESTAMP_SHIFT


def discord_id_info(snowflake: int) -> dict:
    """Discord snowflakes also carry the worker/process ids and a per-ms sequence."""
    return {
        "created_utc": snowflake_to_datetime(snowflake, DISCORD_EPOCH_MS),
        "worker_id": (snowflake & 0x3E0000) >> 17,
        "process_id": (snowflake & 0x1F000) >> 12,
        "increment": snowflake & 0xFFF,
    }


def twitter_id_info(snowflake: int) -> dict:
    """Only valid for ids issued after Twitter moved to snowflakes (roughly id > 2.9e10)."""
    if snowflake < 29_700_859_247:
        return {"created_utc": None,
                "note": "pre-snowflake sequential id; the timestamp is not embedded"}
    return {"created_utc": snowflake_to_datetime(snowflake, TWITTER_EPOCH_MS),
            "note": "snowflake id"}


def parse_discord_link(url: str) -> dict | None:
    """Pull guild/channel/message snowflakes out of a discord message link."""
    m = re.search(r"discord(?:app)?\.com/channels/(\d+|@me)/(\d+)/(\d+)", url)
    if not m:
        return None
    guild, channel, message = m.group(1), int(m.group(2)), int(m.group(3))
    out = {
        "guild": guild,
        "channel_id": channel,
        "message_id": message,
        "channel_created": snowflake_to_datetime(channel, DISCORD_EPOCH_MS),
        "message_created": snowflake_to_datetime(message, DISCORD_EPOCH_MS),
    }
    if guild != "@me":
        out["guild_created"] = snowflake_to_datetime(int(guild), DISCORD_EPOCH_MS)
    return out


# --------------------------------------------------------------------------- #
# archives
# --------------------------------------------------------------------------- #
def wayback_snapshot_url(url: str, timestamp: str = "", raw: bool = True) -> str:
    """`id_` returns the original bytes with no archive rewriting - always use it for analysis."""
    ts = (timestamp or "2") + ("id_" if raw else "")
    return f"https://web.archive.org/web/{ts}/{url}"


def wayback_availability_url(url: str, timestamp: str = "") -> str:
    q = {"url": url}
    if timestamp:
        q["timestamp"] = timestamp
    return "https://archive.org/wayback/available?" + urllib.parse.urlencode(q)


def wayback_cdx_url(url: str, fields: str = "timestamp,original,statuscode,digest",
                    collapse: str | None = "digest", limit: int = 1000) -> str:
    q = {"url": url, "output": "json", "fl": fields, "limit": str(limit)}
    if collapse:
        q["collapse"] = collapse
    return "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(q)


def archive_today_url(url: str) -> str:
    return "https://archive.ph/newest/" + url


def parse_wayback_timestamp(ts: str) -> dt.datetime:
    """Wayback timestamps are YYYYMMDDhhmmss in UTC."""
    return dt.datetime.strptime(ts[:14].ljust(14, "0"), "%Y%m%d%H%M%S").replace(
        tzinfo=dt.timezone.utc)


def snapshots_that_changed(rows: list[dict]) -> list[dict]:
    """Keep only snapshots whose content digest differs from the previous one."""
    out = []
    last = None
    for row in sorted(rows, key=lambda r: r.get("timestamp", "")):
        digest = row.get("digest")
        if digest != last:
            out.append(row)
            last = digest
    return out


# --------------------------------------------------------------------------- #
# behavioural analysis
# --------------------------------------------------------------------------- #
def posting_histogram(times: list[dt.datetime]) -> dict[int, int]:
    counts = Counter(t.astimezone(dt.timezone.utc).hour for t in times)
    return {h: counts.get(h, 0) for h in range(24)}


def infer_utc_offset(times: list[dt.datetime]) -> tuple[int, str]:
    """The centre of the longest quiet stretch is assumed to be 03:00 local."""
    hist = posting_histogram(times)
    total = sum(hist.values())
    if total == 0:
        return 0, "no data"
    threshold = total / 24 * 0.4
    quiet = [h for h in range(24) if hist[h] <= threshold]
    if not quiet or len(quiet) == 24:
        return 0, "activity is uniform; no usable night gap"
    best_start, best_len = 0, 0
    for start in quiet:
        length = 0
        while (start + length) % 24 in quiet and length < 24:
            length += 1
        if length > best_len:
            best_start, best_len = start, length
    centre = (best_start + best_len / 2 - 0.5) % 24
    offset = int(round((3 - centre) % 24))
    if offset > 12:
        offset -= 24
    return offset, f"quiet {best_start:02d}:00 UTC for {best_len} h -> UTC{offset:+d}"


def burstiness(times: list[dt.datetime]) -> tuple[float, str]:
    """Coefficient of variation of the gaps between posts; ~0 means a scheduler."""
    if len(times) < 3:
        return 0.0, "not enough data"
    ts = sorted(t.timestamp() for t in times)
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    mean = sum(gaps) / len(gaps)
    if mean == 0:
        return 0.0, "all posts at the same instant"
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    cv = (var ** 0.5) / mean
    if cv < 0.2:
        note = "very regular -> automated/scheduled"
    elif cv < 0.8:
        note = "semi-regular"
    else:
        note = "bursty -> human"
    return cv, note


def weekday_profile(times: list[dt.datetime]) -> dict[str, int]:
    names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    counts = Counter(t.astimezone(dt.timezone.utc).weekday() for t in times)
    return {names[i]: counts.get(i, 0) for i in range(7)}


def main(argv: list[str]) -> int:
    if not argv or argv[0] == "--selftest":
        _selftest()
        return 0
    cmd = argv[0]
    if cmd == "discord":
        for k, v in discord_id_info(int(argv[1])).items():
            print(f"{k:<16} {v}")
    elif cmd == "twitter":
        for k, v in twitter_id_info(int(argv[1])).items():
            print(f"{k:<16} {v}")
    elif cmd == "link":
        info = parse_discord_link(argv[1])
        if not info:
            print("[-] not a discord message link")
            return 1
        for k, v in info.items():
            print(f"{k:<16} {v}")
    elif cmd == "archive":
        url = argv[1]
        ts = argv[2] if len(argv) > 2 else ""
        print(wayback_snapshot_url(url, ts))
        print(wayback_availability_url(url, ts))
        print(wayback_cdx_url(url))
        print(archive_today_url(url))
    else:
        print(__doc__)
        return 1
    return 0


def _selftest() -> None:
    # Discord: the epoch itself must decode to the epoch
    assert snowflake_to_datetime(0, DISCORD_EPOCH_MS) == dt.datetime(
        2015, 1, 1, tzinfo=dt.timezone.utc)
    # one second after the epoch
    one_sec = 1000 << SNOWFLAKE_TIMESTAMP_SHIFT
    assert snowflake_to_datetime(one_sec, DISCORD_EPOCH_MS) == dt.datetime(
        2015, 1, 1, 0, 0, 1, tzinfo=dt.timezone.utc)

    # round trip through datetime_to_snowflake
    when = dt.datetime(2026, 3, 2, 14, 30, 0, tzinfo=dt.timezone.utc)
    sf = datetime_to_snowflake(when, DISCORD_EPOCH_MS)
    assert snowflake_to_datetime(sf, DISCORD_EPOCH_MS) == when, snowflake_to_datetime(
        sf, DISCORD_EPOCH_MS)

    # the worker/process/increment fields
    info = discord_id_info(sf | (3 << 17) | (1 << 12) | 7)
    assert info["worker_id"] == 3 and info["process_id"] == 1 and info["increment"] == 7, info
    assert info["created_utc"] == when

    # Twitter epoch and the pre-snowflake guard
    assert snowflake_to_datetime(0, TWITTER_EPOCH_MS) == dt.datetime(
        2010, 11, 4, 1, 42, 54, 657000, tzinfo=dt.timezone.utc)
    t_when = dt.datetime(2022, 6, 28, 12, 0, 0, tzinfo=dt.timezone.utc)
    t_sf = datetime_to_snowflake(t_when, TWITTER_EPOCH_MS)
    got = twitter_id_info(t_sf)
    assert got["created_utc"] == t_when, got
    assert twitter_id_info(12345)["created_utc"] is None

    # discord link parsing
    link = ("https://discord.com/channels/"
            f"{datetime_to_snowflake(dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc), DISCORD_EPOCH_MS)}"
            f"/{sf}/{sf}")
    parsed = parse_discord_link(link)
    assert parsed is not None
    assert parsed["message_created"] == when
    assert parsed["guild_created"] == dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    assert parse_discord_link("https://example.com/not/a/link") is None
    dm = parse_discord_link(f"https://discord.com/channels/@me/{sf}/{sf}")
    assert dm is not None and dm["guild"] == "@me" and "guild_created" not in dm

    # archive URLs
    u = wayback_snapshot_url("https://example.com/p", "20210601")
    assert u == "https://web.archive.org/web/20210601id_/https://example.com/p", u
    assert wayback_snapshot_url("https://example.com/p", "20210601", raw=False).endswith(
        "/20210601/https://example.com/p")
    assert "timestamp=20210601" in wayback_availability_url("https://example.com/p", "20210601")
    assert "collapse=digest" in wayback_cdx_url("https://example.com/p")
    assert archive_today_url("https://example.com/p").startswith("https://archive.ph/newest/")
    assert parse_wayback_timestamp("20210601000000") == dt.datetime(
        2021, 6, 1, tzinfo=dt.timezone.utc)
    assert parse_wayback_timestamp("20210601") == dt.datetime(
        2021, 6, 1, tzinfo=dt.timezone.utc)

    # change detection over snapshots
    rows = [{"timestamp": "20210101", "digest": "A"},
            {"timestamp": "20210201", "digest": "A"},
            {"timestamp": "20210301", "digest": "B"},
            {"timestamp": "20210401", "digest": "B"},
            {"timestamp": "20210501", "digest": "C"}]
    changed = snapshots_that_changed(rows)
    assert [r["timestamp"] for r in changed] == ["20210101", "20210301", "20210501"], changed

    # behavioural analysis
    base = dt.datetime(2026, 1, 5, tzinfo=dt.timezone.utc)
    times = [base + dt.timedelta(days=d, hours=h)
             for d in range(14) for h in range(9, 23)]
    off, why = infer_utc_offset(times)
    assert -2 <= off <= 2, (off, why)
    hist = posting_histogram(times)
    assert hist[3] == 0 and hist[12] == 14, hist
    wd = weekday_profile(times)
    assert sum(wd.values()) == len(times) and set(wd) == {
        "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

    regular = [base + dt.timedelta(hours=i) for i in range(50)]
    cv_reg, note_reg = burstiness(regular)
    assert cv_reg < 0.2 and "automated" in note_reg, (cv_reg, note_reg)
    human = [base + dt.timedelta(minutes=m) for m in (0, 3, 5, 400, 402, 1000, 1001, 5000)]
    cv_hum, note_hum = burstiness(human)
    assert cv_hum > 0.8 and "human" in note_hum, (cv_hum, note_hum)
    assert burstiness([base])[1] == "not enough data"

    print(f"selftest ok: discord/twitter snowflakes, link parsing, archive URLs, "
          f"{len(changed)} distinct snapshots, UTC{off:+d} inferred, burstiness "
          f"{cv_reg:.2f} vs {cv_hum:.2f}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

## Variants and pitfalls

- **Old Twitter/X IDs are not snowflakes.** Anything below roughly 2.97e10 predates the
  migration; the guard in the code above catches that.
- **Snowflake timestamps are creation time, not edit time.** An edited post keeps its original
  ID.
- **`id_` in a Wayback URL is essential** when you want the original bytes; without it the
  archive injects its toolbar and rewrites links, which breaks hash comparisons and any
  embedded payload.
- **The archive's copy may itself be incomplete** - images and scripts are archived separately
  and often missing. Check the CDX listing for the asset URLs directly.
- **Archive coverage is thin for recent and for JavaScript-heavy pages.** archive.today renders
  pages before saving, so it sometimes has content the Internet Archive does not.
- **`collapse=digest` hides unchanged snapshots** - exactly what you want when hunting for the
  moment a page changed.
- **Timezone inference fails for shift workers, night owls and schedulers.** Treat it as a hint
  with a confidence, not a fact.
- **Deleted media often outlives the post** on the CDN, but those URLs are frequently signed
  and expire; grab them immediately.
- **Never log in to view private content**, and never create an account to interact. If the
  content requires authentication, it is not the intended path.
- **Screenshots are not evidence of time.** Anyone can set a device clock; prefer IDs, archive
  timestamps and certificate dates.

## Tools

The Wayback Machine and its CDX API, archive.today, `curl` + `jq`, `exiftool` for media
timestamps, `whois`/RDAP for account-infrastructure dates, and the script above for snowflakes
and pattern analysis.

## References

- Wayback Machine CDX Server API:
  https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md
- Wayback availability API: https://archive.org/help/wayback_api.php
- Discord developer documentation, "Snowflakes" (epoch 1420070400000 and the bit layout):
  https://discord.com/developers/docs/reference
- Twitter's original Snowflake announcement and the 1288834974657 ms epoch it defines.
