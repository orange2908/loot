---
title: "Script - evtxkit: EVTX to JSONL and a Noise-Filtered DFIR Timeline (Linux)"
category: sherlocks
subcategory: evtx
type: script
tags: [evtx, jsonl, timeline, pyevtx-rs, evtx-parser, python, 4688, 4624, 4104, 7045, 4662, 4769, dfir, sherlock, windows-event-logs, super-timeline, linux]
summary: "One Python script: dump every .evtx to JSONL, then print a merged, noise-filtered UTC timeline of process, logon, Kerberos, DCSync, service and PowerShell events across all logs of a host."
tools: [evtx, jq]
related: [windows-evtx-hunting, ad-attack-detection-event-ids, sherlock-triage, htb-sasync]
---

## TL;DR

```sh
uv venv .venv && uv pip install -p .venv evtx
# 1. dump each host's logs (winevt/Logs or System32/Logs, depending on the triage pack)
.venv/bin/python evtxkit.py dump HOST/C/Windows/System32/winevt/Logs out/HOST
# 2. read the story
.venv/bin/python evtxkit.py timeline out/HOST --since 2026-03-09T19:25 --until 2026-03-09T19:45
# 3. what event IDs exist
.venv/bin/python evtxkit.py ids out/HOST/Security.jsonl
# add --all to disable the noise filter
```

The JSONL output keeps the raw evtx JSON plus `_ts` (UTC), so it is jq-friendly. See `cheatsheets:sherlocks:windows-evtx-hunting`.

On SaSync this one command printed the whole SqlSvr chain (xp_cmdshell, certutil, nc, SigmaPotato, reg save, net use, dir C:\Users). On DC2 it printed the password spray, the S4U logon with its LogonGuid, the psexec service, mimikatz, DCSync 4662 and Get-ADTrust.

## Code

```python
#!/usr/bin/env python3
"""evtxkit - dump Windows EVTX to JSONL and build a DFIR timeline, on Linux.

Requires: pip install evtx   (Rust-backed pyevtx-rs)

Usage:
  evtxkit.py dump     <logs_dir> <out_dir>          # every *.evtx -> <out_dir>/<name>.jsonl
  evtxkit.py timeline <jsonl_dir> [--since ISO] [--until ISO] [--all]
                                                    # merged, noise-filtered TSV of key events
  evtxkit.py ids      <file.jsonl>                  # event-id census
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

try:
    import evtx  # type: ignore
except ImportError:  # dump needs it, timeline does not
    evtx = None

# Security / System / Application / PowerShell events worth seeing in a DFIR timeline.
KEY_EVENTS = {
    "Security": {4624, 4625, 4648, 4662, 4688, 4697, 4698, 4720, 4728, 4732,
                 4738, 4768, 4769, 4771, 4776, 1102},
    "System": {7045, 104},
    "Application": {18456, 18453, 18454, 15457, 33205},
    "Microsoft-Windows-PowerShell%4Operational": {4104},
    "Microsoft-Windows-Sysmon%4Operational": {1, 3, 8, 10, 11, 13, 22},
}

NOISE = re.compile(
    r"ngen\.exe|msiexec|EdgeUpdate|msedge|VMware|MsMpEng|MpCmdRun|dsregcmd|"
    r"conhost\.exe 0xffffffff|cmdletization|Set-StrictMode|backgroundTask|"
    r"\t(SYSTEM|DWM-\d+|UMFD-\d+|ANONYMOUS LOGON|LOCAL SERVICE|NETWORK SERVICE)\t|"
    r"\\(ANONYMOUS LOGON|SYSTEM)\t|\\[\w.-]+\$\t",  # machine accounts and anonymous logons
    re.I,
)


def event_id(rec: dict) -> int:
    eid = rec["Event"]["System"]["EventID"]
    if isinstance(eid, dict):
        eid = eid.get("#text")
    return int(eid)


def dump(logs_dir: str, out_dir: str) -> None:
    if evtx is None:
        sys.exit("pip install evtx")
    os.makedirs(out_dir, exist_ok=True)
    for f in sorted(glob.glob(os.path.join(logs_dir, "*.evtx"))):
        rows = []
        try:
            for r in evtx.PyEvtxParser(f).records_json():
                d = json.loads(r["data"])
                d["_ts"] = r["timestamp"]
                rows.append(json.dumps(d))
        except Exception as exc:  # corrupt chunk: keep what parsed
            print(f"[!] {os.path.basename(f)}: {exc}", file=sys.stderr)
        if rows:
            name = os.path.basename(f)[:-5] + ".jsonl"
            with open(os.path.join(out_dir, name), "w") as fh:
                fh.write("\n".join(rows) + "\n")
            print(f"{len(rows):7d}  {name}")


def summarize(log: str, eid: int, ed) -> str:
    """One readable line per event."""
    if not isinstance(ed, dict):
        return json.dumps(ed)[:300]
    g = lambda k: str(ed.get(k, "") or "")  # noqa: E731
    if eid == 4688:
        return f"{g('SubjectUserName')}\t{g('ParentProcessName')} -> {g('CommandLine') or g('NewProcessName')}"
    if eid in (4624, 4625):
        extra = g("TransmittedServices").strip()
        return (f"{g('TargetDomainName')}\\{g('TargetUserName')}\tip={g('IpAddress')} type={g('LogonType')} "
                f"{g('AuthenticationPackageName')} guid={g('LogonGuid')} status={g('Status')}"
                + (f" s4u={' '.join(extra.split())}" if extra and extra != "-" else ""))
    if eid in (4768, 4769, 4771):
        return f"{g('TargetUserName')}\tsvc={g('ServiceName')} ip={g('IpAddress')} enc={g('TicketEncryptionType')} status={g('Status')}"
    if eid == 4648:
        return f"{g('SubjectUserName')} as {g('TargetDomainName')}\\{g('TargetUserName')}\tserver={g('TargetServerName')} proc={g('ProcessName')}"
    if eid == 4776:
        return f"{g('TargetUserName')}\tws={g('Workstation')} status={g('Status')}"
    if eid == 4662:
        return f"{g('SubjectUserName')}\t{' '.join(g('Properties').split())}"
    if eid == 4104:
        return " | ".join(g("ScriptBlockText").splitlines())[:400]
    if eid == 7045:
        return f"{g('ServiceName')}\t{g('ImagePath')} as {g('AccountName')}"
    if eid == 1:
        return f"{g('User')}\t{g('ParentImage')} -> {g('CommandLine')}"
    data = ed.get("Data", ed)
    if isinstance(data, dict) and "#text" in data:
        data = data["#text"]
    return " ".join(data) if isinstance(data, list) else json.dumps(data)[:300]


def timeline(jdir: str, since: str | None, until: str | None, keep_all: bool) -> list[str]:
    out = []
    for log, ids in KEY_EVENTS.items():
        path = os.path.join(jdir, log + ".jsonl")
        if not os.path.exists(path):
            continue
        short = log.replace("Microsoft-Windows-", "").replace("%4Operational", "")
        with open(path) as fh:
            for line in fh:
                rec = json.loads(line)
                ts = rec["_ts"].replace(" UTC", "")
                if since and ts < since or until and ts > until:
                    continue
                eid = event_id(rec)
                if eid not in ids:
                    continue
                row = f"{ts[:19].replace('T', ' ')}\t{short}\t{eid}\t{summarize(log, eid, rec['Event'].get('EventData'))}"
                if keep_all or not NOISE.search(row):
                    out.append(row)
    out.sort()
    return out


def ids(path: str) -> None:
    counts: dict[int, int] = {}
    with open(path) as fh:
        for line in fh:
            e = event_id(json.loads(line))
            counts[e] = counts.get(e, 0) + 1
    for e, c in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"{c:7d}  {e}")


def _selftest() -> None:
    rec = {"Event": {"System": {"EventID": {"#text": 7045}},
                     "EventData": {"ServiceName": "vpHM", "ImagePath": "%systemroot%\\FyPDJNvh.exe",
                                   "AccountName": "LocalSystem"}}}
    assert event_id(rec) == 7045
    assert "FyPDJNvh.exe" in summarize("System", 7045, rec["Event"]["EventData"])
    assert NOISE.search("x\tSYSTEM\ty") and NOISE.search("4624\tDOM\\DC2$\tip=") and not NOISE.search("certutil -urlcache")
    print("selftest ok")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("dump"); p.add_argument("logs_dir"); p.add_argument("out_dir")
    p = sub.add_parser("timeline"); p.add_argument("jsonl_dir")
    p.add_argument("--since"); p.add_argument("--until"); p.add_argument("--all", action="store_true")
    p = sub.add_parser("ids"); p.add_argument("file")
    sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "dump":
        dump(a.logs_dir, a.out_dir)
    elif a.cmd == "timeline":
        print("\n".join(timeline(a.jsonl_dir, a.since, a.until, a.all)))
    elif a.cmd == "ids":
        ids(a.file)
    else:
        _selftest()
```

## Extending

- Add event IDs to `KEY_EVENTS` (4698 scheduled task, 5140/5145 share access, Sysmon 3 network).
- Add a branch to `summarize()` for any event you care about. Unknown events fall back to the raw data.
- To merge several hosts, run `timeline` per host and `sort` the concatenated output.
