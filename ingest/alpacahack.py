#!/usr/bin/env python3
"""Ingest the `Daily_AlpacaHack` writeup collection into CTF-Brain.

    python3 ingest/alpacahack.py tree
    python3 ingest/alpacahack.py fetch
    python3 ingest/alpacahack.py render
    python3 ingest/alpacahack.py all

Source: https://github.com/baumroll0928-spec/myRepository/tree/main/Daily_AlpacaHack

The collection is laid out as `Daily_AlpacaHack/mYYYYMM/dDD_<Challenge_Name>/README.md`
with the occasional sibling solver script, which is inlined under a `## Solver`
heading.  The directory names carry the date, so `m202605/d09_reused_n` is the
AlpacaHack Daily challenge "reused n" from 2026-05-09.  Multi-day entries such as
`d03-04_...` and bonus entries such as `b17-21_...` are handled too.

Everything goes through the authenticated `gh` CLI and is cached by immutable git
blob sha under `data/raw/github/blobs/`, so re-runs are free and a crash mid-run
loses nothing.  A file that fails is recorded and skipped; the run never aborts.
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    CONTENT, RAW, load_json, mine_tags, pick_subcategory,
    save_json, slugify, truncate, write_doc,
)
from ctftime import looks_like_bait  # noqa: E402  - reuse the scraper-bait filter
from github_writeups import (  # noqa: E402  - shared `gh` plumbing
    ascii_ratio, blob_path, build_summary, choose_category, find_difficulty, gh_blob,
    gh_json, pad_tags, prune_tags, rewrite_links,
)

REPO = "baumroll0928-spec/myRepository"
ROOT_DIR = "Daily_AlpacaHack"
CTF_NAME = "AlpacaHack Daily"

CACHE = RAW / "github"
TREE_JSON = CACHE / "alpacahack-tree.json"
INDEX_JSON = CACHE / "alpacahack-index.json"
REPORT_JSON = CACHE / "alpacahack-report.json"

MONTH_RE = re.compile(r"^m(\d{4})(\d{2})$")
# d09_reused_n | d03-04_Long_Flag | b17-21_Long_Flag_Printer_2026
DAY_RE = re.compile(r"^([db])(\d{2})(?:-(\d{2}))?[_-]\s*(.+)$", re.DOTALL)

SOLVER_SUFFIXES = (".py", ".sage", ".sh", ".rb", ".js", ".c", ".cpp", ".go")
LANG_BY_SUFFIX = {
    ".py": "python", ".sage": "python", ".sh": "bash", ".rb": "ruby",
    ".js": "javascript", ".c": "c", ".cpp": "cpp", ".go": "go",
}


def head_sha() -> str:
    head = gh_json(f"repos/{REPO}/commits/main")
    return (head or {}).get("sha") or "main"


# ------------------------------------------------------------------------ tree
def build_index() -> list[dict]:
    """Walk the repository tree and group each challenge directory."""
    sha = head_sha()
    tree = load_json(TREE_JSON)
    if not tree or tree.get("_sha") != sha:
        payload = gh_json(f"repos/{REPO}/git/trees/{sha}?recursive=1")
        if not payload:
            print("tree: fetch failed")
            return load_json(INDEX_JSON, []) or []
        tree = {"_sha": sha, **payload}
        save_json(TREE_JSON, tree)

    nodes = [n for n in tree.get("tree", [])
             if n.get("type") == "blob" and n.get("path", "").startswith(ROOT_DIR + "/")]

    challenges: dict[str, dict] = {}
    for node in nodes:
        parts = node["path"].split("/")
        if len(parts) != 4:                           # Daily_AlpacaHack/mYYYYMM/dDD_x/file
            continue
        _, month_dir, day_dir, filename = parts
        month = MONTH_RE.match(month_dir.strip())
        day = DAY_RE.match(day_dir.strip())
        if not month or not day:
            continue
        key = f"{month_dir}/{day_dir}"
        record = challenges.setdefault(key, {
            "repo": REPO,
            "sha": sha,
            "dir": f"{ROOT_DIR}/{month_dir}/{day_dir}",
            "year": int(month.group(1)),
            "month": int(month.group(2)),
            "day": int(day.group(2)),
            "day_end": int(day.group(3)) if day.group(3) else None,
            "bonus": day.group(1) == "b",
            "challenge": re.sub(r"[_]+", " ", day.group(4)).strip(),
            "readme": None,
            "solvers": [],
        })
        if filename.lower() == "readme.md":
            record["readme"] = {"path": node["path"], "blob": node["sha"],
                                "size": node.get("size", 0)}
        elif filename.lower().endswith(SOLVER_SUFFIXES):
            record["solvers"].append({"path": node["path"], "blob": node["sha"],
                                      "name": filename, "size": node.get("size", 0)})

    index = [c for c in challenges.values() if c["readme"]]
    index.sort(key=lambda c: (c["year"], c["month"], c["day"]))
    for record in index:
        record["solvers"].sort(key=lambda s: s["name"])
    save_json(INDEX_JSON, index)
    solvers = sum(len(c["solvers"]) for c in index)
    print(f"tree: {len(index)} challenges, {solvers} sibling solver files (head {sha[:8]})")
    return index


# ----------------------------------------------------------------------- fetch
def fetch(workers: int) -> int:
    index = load_json(INDEX_JSON, []) or []
    if not index:
        print("nothing indexed - run `tree` first")
        return 0
    jobs: list[tuple[str, str]] = []
    for record in index:
        for node in [record["readme"], *record["solvers"]]:
            if node and not blob_path(node["blob"]).exists():
                jobs.append((REPO, node["blob"]))
    print(f"fetch: {len(jobs)} blobs to pull")
    ok = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(gh_blob, repo, blob): blob for repo, blob in jobs}
        for future in as_completed(futures):
            try:
                if future.result():
                    ok += 1
            except Exception as exc:                  # noqa: BLE001
                print(f"    blob {futures[future][:8]}: {exc}")
    print(f"fetch: {ok}/{len(jobs)} new blobs stored")
    return ok


# ---------------------------------------------------------------------- render
def date_label(record: dict) -> str:
    end = record.get("day_end")
    span = f"{record['day']:02d}" + (f"-{end:02d}" if end else "")
    return f"{record['year']}-{record['month']:02d}-{span}"


def render() -> dict:
    index = load_json(INDEX_JSON, []) or []
    by_category: dict[str, int] = {}
    dropped: dict[str, int] = {}
    seen: set[Path] = set()
    written = 0

    for record in index:
        try:
            body = gh_blob(REPO, record["readme"]["blob"])
        except Exception as exc:                      # noqa: BLE001
            dropped["fetch-error"] = dropped.get("fetch-error", 0) + 1
            print(f"    {record['dir']}: {exc}")
            continue
        if not body:
            dropped["no-body"] = dropped.get("no-body", 0) + 1
            continue
        body = body.strip()

        # Scraped markdown is data, never instructions: bait is dropped, not followed.
        reason = looks_like_bait(body)
        if reason:
            dropped[reason.split(":")[0]] = dropped.get(reason.split(":")[0], 0) + 1
            print(f"    {record['dir']}: dropped ({reason})")
            continue

        challenge = record["challenge"]
        sha = record["sha"]
        permalink = (f"https://github.com/{REPO}/blob/{sha}/"
                     + quote(record["readme"]["path"], safe="/"))
        dir_link = f"https://github.com/{REPO}/tree/{sha}/" + quote(record["dir"], safe="/")

        document = rewrite_links(body, REPO, sha, record["dir"])

        # Inline any sibling solver script the author shipped next to the writeup.
        solver_blocks: list[str] = []
        for solver in record["solvers"]:
            try:
                code = gh_blob(REPO, solver["blob"])
            except Exception:                         # noqa: BLE001
                code = None
            if not code or not code.strip():
                continue
            lang = LANG_BY_SUFFIX.get(Path(solver["name"]).suffix.lower(), "")
            link = (f"https://github.com/{REPO}/blob/{sha}/"
                    + quote(solver["path"], safe="/"))
            solver_blocks.append(
                f"### `{solver['name']}`\n\n<{link}>\n\n```{lang}\n"
                + code.rstrip() + "\n```")
        if solver_blocks:
            document += "\n\n## Solver\n\n" + "\n\n".join(solver_blocks)

        tags = prune_tags(
            mine_tags(challenge, document[:16000], extra=["alpacahack"]), document)
        category = choose_category(tags, challenge, document[:10000])
        if category not in tags:
            tags.insert(0, category)
        subcategory = pick_subcategory(tags, category)
        tags = pad_tags(tags, category, subcategory, CTF_NAME, challenge,
                        record["year"], extra=("alpacahack", "daily"))

        summary = build_summary(document, challenge, CTF_NAME, category, tags)
        if ascii_ratio(summary) < 0.85:
            summary = build_summary("", challenge, CTF_NAME, category, tags)

        out_path = CONTENT / "writeups" / category / f"alpacahack-{slugify(challenge, 50)}.md"
        counter = 2
        while out_path in seen:
            out_path = out_path.with_name(
                f"alpacahack-{slugify(challenge, 46)}-{counter}.md")
            counter += 1
        seen.add(out_path)

        meta = [
            "## Source", "",
            f"- **CTF:** {CTF_NAME}"
            + (" (bonus challenge)" if record.get("bonus") else ""),
            f"- **Challenge:** {challenge}",
            f"- **Date:** {date_label(record)}",
            f"- **Repository:** [{REPO}](https://github.com/{REPO})",
            f"- **Directory:** <{dir_link}>",
            f"- **File:** <{permalink}>",
            "", "---", "",
        ]

        try:
            write_doc(
                out_path,
                {
                    "title": f"{challenge} - {CTF_NAME}",
                    "category": category,
                    "subcategory": subcategory,
                    "type": "writeup",
                    "tags": tags,
                    "difficulty": find_difficulty(document),
                    "summary": summary,
                    "source": {"name": REPO, "url": permalink},
                    "ctf": {"name": CTF_NAME, "year": record["year"],
                            "challenge": challenge},
                },
                "\n".join(meta) + truncate(document, 1200, permalink),
            )
        except Exception as exc:                      # noqa: BLE001
            dropped["write-error"] = dropped.get("write-error", 0) + 1
            print(f"    {record['dir']}: {exc}")
            continue

        written += 1
        by_category[category] = by_category.get(category, 0) + 1

    report = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": f"https://github.com/{REPO}/tree/main/{ROOT_DIR}",
        "indexed": len(index),
        "rendered": written,
        "with_solver": sum(1 for r in index if r["solvers"]),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "dropped": dict(sorted(dropped.items(), key=lambda kv: -kv[1])),
    }
    save_json(REPORT_JSON, report)
    print(f"render: {written} documents")
    for category, n in report["by_category"].items():
        print(f"    {category:<12} {n}")
    if dropped:
        print(f"  dropped: {dropped}")
    return report


# ------------------------------------------------------------------------ main
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["tree", "fetch", "render", "all"])
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    CACHE.mkdir(parents=True, exist_ok=True)
    if args.command in ("tree", "all"):
        build_index()
    if args.command in ("fetch", "all"):
        fetch(args.workers)
    if args.command in ("render", "all"):
        render()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
