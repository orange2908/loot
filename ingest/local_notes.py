#!/usr/bin/env python3
"""Import a local folder of personal CTF notes into the knowledge base.

    python3 ingest/local_notes.py import --src "/Users/macbook/Documents/loot/CTF"
    python3 ingest/local_notes.py import --src PATH --dry-run

Your own notes are the most valuable thing in here: they are the ones you go
looking for again.  They are imported with the tag `my-notes` so you can always
narrow to them (`ctfbrain search "rsa tag:my-notes"`), and the source folder is
never modified.

Notes are free-form (no frontmatter, Obsidian callouts, link dumps, bare code
blocks), so category, type and tags are inferred from the path and the content.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    CONTENT, categorise, first_sentence, mine_tags, pick_subcategory, save_json,
    slugify, truncate, write_doc,
)
from ctftime import looks_like_bait  # noqa: E402

PREFIX = "notes-"
SOURCE_NAME = "Personal notes"

# Top-level folder -> CTF-Brain category. Anything unmapped falls back to
# content-based classification.
DIR_CATEGORY = {
    "blockchain": "blockchain",
    "cryptography": "crypto", "crypto": "crypto",
    "forensics": "forensics",
    "hardware": "hardware",
    "jails": "misc",
    "malware": "rev",
    "mobile": "mobile",
    "reverse": "rev", "reversing": "rev", "re": "rev",
    "web": "web",
    "pwn": "pwn", "binary": "pwn", "binary exploitation": "pwn",
    "osint": "osint",
    "stego": "stego", "steganography": "stego",
    "cloud": "cloud",
    "misc": "misc", "random": "misc", "random notes": "misc",
    "network": "misc", "networking": "misc",
}

# Folders whose *child* directory carries the real category.
PASSTHROUGH_DIRS = {"htb challenges", "htb", "scripts", "writeups", "challenges",
                    "notes", "ctf"}

LINK_RE = re.compile(r"https?://")
FENCE_RE = re.compile(r"^[ \t]*```", re.MULTILINE)
CALLOUT_RE = re.compile(r"^>\s*\[!(\w+)\]\s*(.*)$", re.MULTILINE)
WIKILINK_RE = re.compile(r"\[\[([^\]|]+)(?:\|([^\]]+))?\]\]")


def classify_category(rel: Path, body: str) -> tuple[str, str]:
    """Return (category, subcategory) from the path first, content second."""
    parts = [p.lower() for p in rel.parts[:-1]]
    subcategory = ""

    for i, part in enumerate(parts):
        if part in PASSTHROUGH_DIRS:
            # e.g. "HTB Challenges/Reversing/x.md" or "scripts/pwn/x.md"
            if i + 1 < len(parts) and parts[i + 1] in DIR_CATEGORY:
                subcategory = slugify(rel.parts[i]) if rel.parts[i] else ""
                return DIR_CATEGORY[parts[i + 1]], subcategory
            continue
        if part in DIR_CATEGORY:
            deeper = parts[i + 1] if i + 1 < len(parts) else ""
            subcategory = slugify(deeper) if deeper else ""
            return DIR_CATEGORY[part], subcategory

    return categorise(rel.as_posix(), body[:8000]), subcategory


def classify_type(rel: Path, body: str) -> str:
    parts = [p.lower() for p in rel.parts]
    if "writeups" in parts or "htb challenges" in parts or "challenges" in parts:
        return "writeup"
    if "scripts" in parts or "templates" in parts:
        return "script"

    fences = len(FENCE_RE.findall(body))
    lines = [l for l in body.splitlines() if l.strip()]
    if not lines:
        return "reference"
    link_ratio = sum(1 for l in lines if LINK_RE.search(l)) / len(lines)
    if link_ratio > 0.35 and fences < 2:
        return "reference"          # a link dump, not a technique
    if fences >= 2:
        return "technique"
    return "reference"


def clean_body(body: str) -> str:
    """Normalise Obsidian-isms so the page renders correctly here."""
    # Obsidian callouts -> plain blockquote with a bold lead-in.
    body = CALLOUT_RE.sub(lambda m: f"> **{m.group(1).title()}** {m.group(2)}".rstrip(), body)
    # Wiki links -> plain text (the target lives in another note, not a URL).
    body = WIKILINK_RE.sub(lambda m: m.group(2) or m.group(1), body)
    return body.strip()


def nice_title(rel: Path) -> str:
    stem = rel.stem.strip()
    stem = re.sub(r"\s+", " ", stem)
    if stem.islower() or stem.isupper():
        stem = stem.title()
    parent = rel.parts[-2] if len(rel.parts) > 1 else ""
    if parent and parent.lower() not in PASSTHROUGH_DIRS and parent.lower() != stem.lower():
        return f"{stem} ({parent})"
    return stem


def run(src: Path, dry_run: bool = False) -> dict:
    if not src.exists():
        print(f"source folder not found: {src}")
        return {}

    files = sorted(p for p in src.rglob("*.md") if not p.name.startswith("."))
    counts: dict[str, int] = {}
    skipped: dict[str, int] = {}
    written = 0
    seen: set[Path] = set()

    for path in files:
        rel = path.relative_to(src)
        raw = path.read_text(encoding="utf-8", errors="replace")
        body = clean_body(raw)
        if len(body.strip()) < 40:
            skipped["empty"] = skipped.get("empty", 0) + 1
            continue
        reason = looks_like_bait(body)
        if reason.startswith("scraper-bait"):
            skipped["bait"] = skipped.get("bait", 0) + 1
            continue

        category, subcategory = classify_category(rel, body)
        doctype = classify_type(rel, body)
        title = nice_title(rel)

        tags = mine_tags(title, rel.as_posix(), body[:12000],
                         extra=["my-notes", "personal"])
        for extra in (category, slugify(rel.parts[0]) if len(rel.parts) > 1 else ""):
            if extra and extra not in tags:
                tags.append(extra)
        subcategory = subcategory or pick_subcategory(tags)

        summary = first_sentence(body) or f"Personal note: {title}."
        footer = (f"\n\n---\n\n*From your own notes: `{rel.as_posix()}`*\n")

        out = CONTENT / doctype_dir(doctype) / category / f"{PREFIX}{slugify(rel.as_posix(), 70)}.md"
        n = 2
        while out in seen:
            out = out.with_name(f"{out.stem}-{n}.md")
            n += 1
        seen.add(out)

        if not dry_run:
            write_doc(out, {
                "title": title,
                "category": category,
                "subcategory": subcategory,
                "type": doctype,
                "tags": tags[:20],
                "summary": summary,
                "source": {"name": SOURCE_NAME, "url": ""},
                "origin_path": rel.as_posix(),
            }, truncate(body, 1200) + footer)

        counts[category] = counts.get(category, 0) + 1
        written += 1

    report = {"source": str(src), "files_seen": len(files), "written": written,
              "by_category": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
              "skipped": skipped}
    if not dry_run:
        save_json(Path(CONTENT).parent / "data" / "raw" / "local-notes-report.json", report)

    print(f"{'would import' if dry_run else 'imported'} {written} of {len(files)} notes")
    for cat, n in report["by_category"].items():
        print(f"    {cat:<12} {n}")
    if skipped:
        print(f"  skipped: {skipped}")
    return report


def doctype_dir(doctype: str) -> str:
    return {"script": "scripts", "writeup": "writeups", "technique": "techniques",
            "cheatsheet": "cheatsheets", "reference": "reference",
            "playbook": "playbooks", "tool": "tools"}[doctype]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["import"])
    parser.add_argument("--src", required=True, help="folder of markdown notes")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    run(Path(args.src).expanduser(), dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
