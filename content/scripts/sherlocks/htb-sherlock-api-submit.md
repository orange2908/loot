---
title: "Script - HTB Sherlock API Client: find, tasks, download, submit"
category: sherlocks
subcategory: htb-api
type: script
tags: [htb, hackthebox, sherlock, sherlocks, api, submit-answer, download, hacktheblue, rate-limit, too-many-attempts, python, stdlib, automation, htb-mcp]
summary: "Stdlib Python client for the HTB Sherlock v4 API: resolve by name, list tasks with masks, download the zip, submit single answers or a paced TSV of answers."
tools: [python3, curl, jq, 7z]
related: [htb-mcp-sherlocks, sherlock-triage]
---

## Verified endpoints (labs.hackthebox.com/api/v4, Bearer app token)

| Action | Request |
|---|---|
| search | `GET sherlocks?keyword=NAME` (also `state`, `difficulty[]`, `category[]`, `todo=1`, `page`) |
| profile | `GET sherlocks/{id}` (includes `file_password`) and `GET sherlocks/{id}/play` |
| tasks | `GET sherlocks/{id}/tasks` -> `id, description, masked_flag, completed` |
| download | `GET sherlocks/{id}/download_link` -> `{url, expires_in:3600}`, then fetch the url |
| submit | `POST sherlocks/{id}/tasks/{task_id}/flag` body `{"flag":"..."}` |

Replies: `Task flag owned!` (correct), `Incorrect task flag!`, and `Too Many Attempts.` (rate limited: wait about 90s and pace about 15s per request). `GET sherlocks/{id}/info` returns 403, so do not use it.

## curl version

```sh
T=$(cat ~/.config/htb-mcp/token)
# submit one answer, JSON-encoding it so backslashes survive
body=$(python3 -c 'import json,sys;print(json.dumps({"flag":sys.argv[1]}))' 'C:\Temp\nc.exe')
curl -s -X POST -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "$body" https://labs.hackthebox.com/api/v4/sherlocks/1692/tasks/23787/flag | jq -r .message
# in bash loops always use: while IFS='|' read -r id ans; do ...; done   (without -r, \ is eaten)
```

## Code

```python
#!/usr/bin/env python3
"""htb_sherlock - Hack The Box Sherlock API client (stdlib only).

Token: $HTB_TOKEN, or the file in $HTB_TOKEN_FILE (default ~/.config/htb-mcp/token).
The token is never printed.

  htb_sherlock.py find SaSync                     # id, difficulty, progress
  htb_sherlock.py tasks 1692                      # task ids, masks, questions, solved state
  htb_sherlock.py download 1692 [out.zip]         # zip; password is always "hacktheblue"
  htb_sherlock.py submit 1692 23778 '192.168.186.135'
  htb_sherlock.py submit-file 1692 answers.tsv    # lines "task_id<TAB>answer", paced to avoid rate limits
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://labs.hackthebox.com/api/v4"
ZIP_PASSWORD = "hacktheblue"


def token() -> str:
    tok = os.environ.get("HTB_TOKEN")
    if not tok:
        path = os.path.expanduser(os.environ.get("HTB_TOKEN_FILE", "~/.config/htb-mcp/token"))
        with open(path) as fh:
            tok = fh.read().strip()
    return tok


def call(path: str, method: str = "GET", body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{API}/{path}", data=data, method=method, headers={
        "Authorization": f"Bearer {token()}", "Accept": "application/json",
        "Content-Type": "application/json", "User-Agent": "htb-sherlock-cli/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:
            return {"message": f"HTTP {e.code}"}


def find(name: str) -> list[dict]:
    res = call("sherlocks?" + urllib.parse.urlencode({"keyword": name}))
    return res.get("data", [])


def resolve(ident: str) -> int:
    if ident.isdigit():
        return int(ident)
    for s in find(ident):
        if s["name"].lower() == ident.lower():
            return s["id"]
    sys.exit(f"no sherlock named {ident!r}")


def tasks(sid: int) -> list[dict]:
    return call(f"sherlocks/{sid}/tasks").get("data", [])


def download(sid: int, out: str) -> str:
    url = call(f"sherlocks/{sid}/download_link")["url"]
    # the signed link redirects to the CDN; no auth header needed
    with urllib.request.urlopen(url, timeout=600) as r, open(out, "wb") as fh:
        while chunk := r.read(1 << 20):
            fh.write(chunk)
    return out


def submit(sid: int, task_id: int, answer: str) -> str:
    res = call(f"sherlocks/{sid}/tasks/{task_id}/flag", "POST", {"flag": answer})
    return res.get("message", json.dumps(res)[:200])


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        sys.exit(__doc__)
    cmd, args = argv[1], argv[2:]
    if cmd == "find":
        for s in find(args[0]):
            print(f"{s['id']}\t{s['name']}\t{s['difficulty']}\t{s['state']}\tprogress={s.get('progress')}")
    elif cmd == "tasks":
        for t in tasks(resolve(args[0])):
            mark = "x" if t["completed"] else " "
            print(f"[{mark}] {t['id']}\t{t['title']}\t{t['masked_flag']}\n      {t['description']}")
    elif cmd == "download":
        sid = resolve(args[0])
        out = download(sid, args[1] if len(args) > 1 else f"sherlock-{sid}.zip")
        print(f"{out}  (7z x -p{ZIP_PASSWORD} {out})")
    elif cmd == "submit":
        print(submit(resolve(args[0]), int(args[1]), args[2]))
    elif cmd == "submit-file":
        sid = resolve(args[0])
        with open(args[1]) as fh:
            for line in fh:
                if not line.strip() or line.startswith("#"):
                    continue
                tid, ans = line.rstrip("\n").split("\t", 1)
                msg = submit(sid, int(tid), ans)
                if "Too Many" in msg:  # back off once, then retry
                    time.sleep(90)
                    msg = submit(sid, int(tid), ans)
                print(f"{tid}\t{ans}\t=> {msg}")
                time.sleep(15)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
```

## answers.tsv example

```text
# task_id<TAB>answer
23778	192.168.186.135
23781	MSSQL
```
