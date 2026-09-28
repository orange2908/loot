#!/usr/bin/env python3
"""Generate docs/CATALOG.md from the live index.

A hand-written tour of 4,500 documents would be wrong within a week, so this
reads the index instead. Run `make catalog` after `make index`.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctfbrain.config import CATEGORIES, CATEGORY_META  # noqa: E402
from ctfbrain.search import Brain  # noqa: E402

OUT = ROOT / "docs" / "CATALOG.md"

# Types listed per category, in the order you would reach for them.
SHOWCASE_TYPES = ["playbook", "cheatsheet", "technique", "script", "tool"]
MAX_PER_TYPE = 14


def main() -> int:
    brain = Brain()
    stats = brain.stats()

    lines: list[str] = [
        "# Catalog",
        "",
        "What is actually in the knowledge base, generated from the index.",
        "Regenerate with `make catalog`.",
        "",
        f"**{stats['documents']:,} documents · {stats['total_lines']:,} lines · "
        f"{stats['code_blocks']:,} code blocks · {stats['unique_tags']:,} tags · "
        f"{stats['ctfs']:,} CTFs**",
        "",
        "## By type",
        "",
        "| Type | Count | What it is |",
        "|---|---:|---|",
    ]
    type_blurb = {
        "playbook": "decision trees for when you do not know where to start",
        "cheatsheet": "dense command and payload references",
        "technique": "one attack each, with a working exploit",
        "script": "complete, self-testing tools",
        "writeup": "solved challenges from real competitions",
        "tool": "install plus the invocations that matter",
        "reference": "tables, mirrored wikis and vendored libraries",
    }
    for kind, n in stats["by_type"].items():
        lines.append(f"| `{kind}` | {n:,} | {type_blurb.get(kind, '')} |")

    lines += ["", "## By category", "", "| Category | Docs | Covers |", "|---|---:|---|"]
    for cat in CATEGORIES:
        n = stats["by_category"].get(cat, 0)
        if not n:
            continue
        label, _, desc = CATEGORY_META[cat]
        lines.append(f"| [{label}](#{cat}) | {n:,} | {desc} |")

    # Start here
    lines += ["", "## Start here", "",
              "When you do not know what you are looking at, open a playbook:", ""]
    playbooks = brain.conn.execute(
        "SELECT slug, title, summary FROM docs WHERE type='playbook' ORDER BY title"
    ).fetchall()
    for row in playbooks:
        title = row["title"].replace("Playbook - ", "").replace("Playbook: ", "")
        lines.append(f"- **{title}** &nbsp; `ctfbrain show {row['slug']}`  ")
        if row["summary"]:
            lines.append(f"  {row['summary']}")
    lines.append("")

    # Per category
    for cat in CATEGORIES:
        if not stats["by_category"].get(cat):
            continue
        label, _, desc = CATEGORY_META[cat]
        lines += [f'<a id="{cat}"></a>', "", f"## {label}", "", f"*{desc}*", ""]

        counts = brain.conn.execute(
            "SELECT type, COUNT(*) n FROM docs WHERE category=? GROUP BY type ORDER BY n DESC",
            (cat,)).fetchall()
        lines.append("  ".join(f"`{r['type']}` {r['n']}" for r in counts))
        lines.append("")

        top_tags = brain.tags(category=cat, limit=22)
        if top_tags:
            lines.append("Common tags: " + " ".join(f"`{t['tag']}`" for t in top_tags))
            lines.append("")

        by_type: dict[str, list] = defaultdict(list)
        rows = brain.conn.execute(
            """SELECT slug, title, type, subcategory, difficulty FROM docs
               WHERE category=? AND type IN ('playbook','cheatsheet','technique','script','tool')
               ORDER BY subcategory, title""", (cat,)).fetchall()
        for row in rows:
            by_type[row["type"]].append(row)

        for kind in SHOWCASE_TYPES:
            items = by_type.get(kind, [])
            if not items:
                continue
            shown = items[:MAX_PER_TYPE]
            lines.append(f"**{kind}** ({len(items)})")
            lines.append("")
            for row in shown:
                extra = f" · {row['difficulty']}" if row["difficulty"] else ""
                lines.append(f"- {row['title']}{extra}  `{row['slug']}`")
            if len(items) > len(shown):
                rest = len(items) - len(shown)
                lines.append(f"- *...and {rest} more: "
                             f"`ctfbrain search \"\" -c {cat} -t {kind} -n 200`*")
            lines.append("")

        writeups = stats["by_category"].get(cat, 0) - sum(len(v) for v in by_type.values())
        if writeups > 0:
            lines.append(f"Plus {writeups:,} writeups and reference pages: "
                         f"`ctfbrain search \"\" -c {cat} -t writeup -n 200`")
            lines.append("")

    # Sources
    lines += ["## Where the content came from", "",
              "| Source | Documents |", "|---|---:|"]
    sources = brain.conn.execute(
        """SELECT source_name, COUNT(*) n FROM docs
           WHERE source_name != '' GROUP BY source_name ORDER BY n DESC LIMIT 25"""
    ).fetchall()
    for row in sources:
        lines.append(f"| {row['source_name']} | {row['n']:,} |")
    lines += ["",
              "Documents with no `source:` were written for this knowledge base directly.",
              "Provenance for mirrors and vendored code is in",
              "[vendor/PROVENANCE.md](../vendor/PROVENANCE.md) and",
              "[content/reference/ext-CORPORA-PROVENANCE.md](../content/reference/ext-CORPORA-PROVENANCE.md).",
              ""]

    OUT.write_text("\n".join(lines), encoding="utf-8")
    brain.close()
    print(f"wrote {OUT.relative_to(ROOT)} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
