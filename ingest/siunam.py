#!/usr/bin/env python3
"""Ingest siunam321's CTF writeups.

Blog:   https://siunam321.github.io/ctf/
Source: github.com/siunam321/siunam321.github.io  (a Jekyll / GitHub Pages site)

The writeups live at ``ctf/<CTF>/<Category>/<Challenge>/README.md`` in the repo
and render on the blog at ``https://siunam321.github.io/ctf/<CTF>/<Category>/<Challenge>/``.
This pipeline pulls the repo tree, fetches each challenge README, and normalises
it to the writeup format under ``content/writeups/<cat>/siunam-*.md``.

It deliberately reuses the ``github_writeups`` pipeline's path parsing, tag
mining, categorisation, link rewriting and bait filtering so the emitted
documents are shaped exactly like the rest of the corpus. Unlike that pipeline
it applies no per-repo / per-CTF cap: this is a single author's full writeup
collection, requested in full, not a breadth-balanced team-repo sweep.

Each document carries a ``source:`` link to the live blog page and an
``original_source:`` link to the exact file on GitHub.

Subcommands:  tree | fetch | render | all
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from urllib.parse import quote

# Reuse the GitHub-writeup machinery wholesale.
import github_writeups as gw
from ctftime import looks_like_bait
from common import (
    CONTENT,
    mine_tags,
    pick_subcategory,
    slugify,
    truncate,
    write_doc,
    load_json,
    save_json,
)

REPO = "siunam321/siunam321.github.io"
BRANCH = "main"
BLOG_BASE = "https://siunam321.github.io/"

CACHE = gw.RAW / "siunam" if hasattr(gw, "RAW") else CONTENT.parent / "data" / "raw" / "siunam"
CANDIDATES_JSON = CACHE / "candidates.json"
TREE_JSON = CACHE / "tree.json"
REPORT_JSON = CACHE / "report.json"


def _head_sha() -> str | None:
    head = gw.gh_json(f"repos/{REPO}/commits/{BRANCH}")
    if not head:
        return None
    return head.get("sha")


def blog_url(path: str) -> str:
    """Live blog permalink for a challenge README path."""
    dirpath = "/".join(path.split("/")[:-1])
    return BLOG_BASE + quote(dirpath, safe="/") + "/"


# --------------------------------------------------------------------- tree
def tree() -> list[dict]:
    CACHE.mkdir(parents=True, exist_ok=True)
    sha = _head_sha()
    if not sha:
        print(f"  {REPO}: could not resolve {BRANCH} - is `gh` authenticated?")
        return []

    tree_payload = load_json(TREE_JSON)
    if not tree_payload or tree_payload.get("sha") != sha:
        raw = gw.gh_json(f"repos/{REPO}/git/trees/{sha}?recursive=1")
        if not raw:
            print(f"  {REPO}: tree fetch failed")
            return []
        tree_payload = {"sha": sha, "tree": raw.get("tree", [])}
        save_json(TREE_JSON, tree_payload)

    nodes = tree_payload["tree"]
    # Only challenge-level READMEs: ctf/<CTF>/<Category>/<Challenge>/README.md
    # (depth >= 4). Shallower READMEs are CTF- or category-index pages.
    blobs = [
        n for n in nodes
        if n.get("type") == "blob"
        and n.get("path", "").startswith("ctf/")
        and n["path"].endswith("README.md")
        and n["path"].count("/") >= 4
    ]

    candidates: list[dict] = []
    seen_groups: set[str] = set()
    for node in blobs:
        info = gw.parse_path(node["path"], ("", None))
        if not info or not info.get("challenge"):
            continue
        if info["group"] in seen_groups:
            continue
        seen_groups.add(info["group"])
        candidates.append({
            "repo": REPO,
            "sha": sha,
            "path": node["path"],
            "blob": node["sha"],
            "size": node.get("size", 0),
            **info,
        })

    save_json(CANDIDATES_JSON, candidates)
    print(f"tree: {len(blobs)} challenge READMEs -> {len(candidates)} candidate writeups")
    return candidates


# -------------------------------------------------------------------- fetch
def fetch(limit: int) -> int:
    candidates = (load_json(CANDIDATES_JSON, []) or [])[:limit]
    if not candidates:
        print("nothing to fetch - run `tree` first")
        return 0
    ok = 0
    for i, c in enumerate(candidates, 1):
        body = gw.gh_blob(c["repo"], c["blob"])  # cached forever by blob sha
        if body:
            ok += 1
        if i % 100 == 0:
            print(f"  fetched {i}/{len(candidates)}")
    print(f"fetch: {ok}/{len(candidates)} blobs available (cached under {gw.BLOBS})")
    return ok


# ------------------------------------------------------------------- render
def render(limit: int) -> dict:
    candidates = (load_json(CANDIDATES_JSON, []) or [])[:limit]
    by_category: dict[str, int] = {}
    by_ctf: dict[str, int] = {}
    dropped: dict[str, int] = {}
    seen: set[Path] = set()
    written = 0

    for entry in candidates:
        body = gw.gh_blob(entry["repo"], entry["blob"])
        if not body:
            dropped["no-body"] = dropped.get("no-body", 0) + 1
            continue
        body = body.strip()

        # Scraped markdown is data, not instructions.
        reason = looks_like_bait(body)
        if reason:
            dropped[reason.split(":")[0]] = dropped.get(reason.split(":")[0], 0) + 1
            continue
        if gw.looks_like_index(body):
            dropped["link-index"] = dropped.get("link-index", 0) + 1
            continue

        repo, sha, path = entry["repo"], entry["sha"], entry["path"]
        challenge = entry.get("challenge") or ""
        ctf = entry.get("ctf") or ""
        year = entry.get("year")
        dirpath = "/".join(path.split("/")[:-1])

        tags = gw.prune_tags(
            mine_tags(challenge, ctf, body[:16000],
                      extra=[t for t in (entry.get("category_dir"),) if t]), body)
        category = gw.choose_category(tags, challenge, ctf, body[:10000],
                                      stated=entry.get("category_dir") or "")
        if category not in tags:
            tags.insert(0, category)
        subcategory = pick_subcategory(tags, category)
        tags = gw.pad_tags(tags, category, subcategory, ctf, challenge, year,
                           extra=["siunam321"])

        gh_permalink = f"https://github.com/{repo}/blob/{sha}/" + quote(path, safe="/")
        live_url = blog_url(path)
        summary = gw.build_summary(body, challenge, ctf, category, tags)

        ctf_label = f"{ctf} {year}".strip() if year else ctf
        title = f"{challenge} - {ctf_label}" if ctf_label else challenge

        ctf_slug = slugify(ctf, 34) or "ctf"
        challenge_slug = slugify(challenge, 44) or entry["blob"][:10]
        stem = "-".join(x for x in ("siunam", ctf_slug, challenge_slug) if x)
        out_path = CONTENT / "writeups" / category / f"{stem}.md"
        counter = 2
        while out_path in seen:
            out_path = CONTENT / "writeups" / category / f"{stem}-{counter}.md"
            counter += 1
        seen.add(out_path)

        meta = ["## Source", ""]
        if ctf:
            meta.append(f"- **CTF:** {ctf_label}")
        if challenge:
            meta.append(f"- **Challenge:** {challenge}")
        meta += [
            f"- **Author:** [siunam321](https://siunam321.github.io/)",
            f"- **Writeup:** <{live_url}>",
            f"- **Source file:** <{gh_permalink}>",
            "", "---", "",
        ]

        frontmatter = {
            "title": title,
            "category": category,
            "subcategory": subcategory,
            "type": "writeup",
            "tags": tags,
            "difficulty": gw.find_difficulty(body),
            "summary": summary,
            "source": {"name": "siunam321.github.io", "url": live_url},
            "original_source": {"name": repo, "url": gh_permalink},
            "ctf": {"name": ctf, "year": year, "challenge": challenge},
        }
        try:
            write_doc(out_path, frontmatter,
                      "\n".join(meta)
                      + truncate(gw.rewrite_links(body, repo, sha, dirpath), 1200, live_url))
        except Exception as exc:  # noqa: BLE001
            dropped["write-error"] = dropped.get("write-error", 0) + 1
            print(f"    {path}: {exc}")
            continue

        written += 1
        by_category[category] = by_category.get(category, 0) + 1
        by_ctf[ctf] = by_ctf.get(ctf, 0) + 1

    report = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "repo": REPO,
        "candidates": len(candidates),
        "rendered": written,
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "ctfs": len(by_ctf),
        "dropped": dict(sorted(dropped.items(), key=lambda kv: -kv[1])),
    }
    save_json(REPORT_JSON, report)

    print(f"render: {written} documents across {len(by_ctf)} CTF events")
    for category, n in report["by_category"].items():
        print(f"    {category:<12} {n}")
    if dropped:
        print("  dropped:", dict(report["dropped"]))
    return report


# ---------------------------------------------------------------------- cli
def main() -> int:
    ap = argparse.ArgumentParser(description="Ingest siunam321's CTF writeups.")
    ap.add_argument("cmd", choices=["tree", "fetch", "render", "all"])
    ap.add_argument("--limit", type=int, default=10_000)
    args = ap.parse_args()

    if args.cmd in ("tree", "all"):
        tree()
    if args.cmd in ("fetch", "all"):
        fetch(args.limit)
    if args.cmd in ("render", "all"):
        render(args.limit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
