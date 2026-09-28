#!/usr/bin/env python3
"""Harvest CTF writeups from ctftime.org into the CTF-Brain knowledge base.

    python3 ingest/ctftime.py crawl  --pages 60
    python3 ingest/ctftime.py fetch  --limit 1200
    python3 ingest/ctftime.py render --limit 1200
    python3 ingest/ctftime.py all    --pages 60

Everything is cached under data/raw/ctftime/, so a second run only fetches what is
new.  A page that fails is recorded and skipped; the run never aborts.

ctftime.org serves 403 without a browser User-Agent - `common.Fetcher` sends one.
"""
from __future__ import annotations

import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    CONTENT, Fetcher, RAW, categorise, first_sentence, load_json, mine_tags,
    pick_subcategory, save_json, slugify, truncate, write_doc,
)

BASE = "https://ctftime.org"
CACHE = RAW / "ctftime"
INDEX_JSON = CACHE / "index.json"
DETAIL_JSON = CACHE / "details.json"
REPORT_JSON = CACHE / "report.json"

ROW_RE = re.compile(
    r"<tr>\s*"
    r'<td><a href="/event/(\d+)"[^>]*>(.*?)</a></td>\s*'
    r'<td><a href="/task/(\d+)"[^>]*>(.*?)</a></td>\s*'
    r"<td>(.*?)</td>\s*"
    r"<td>(.*?)</td>\s*"
    r'<td><a href="/writeup/(\d+)"[^>]*>.*?</a></td>',
    re.DOTALL,
)
LABEL_RE = re.compile(r'<span class="label label-info">(.*?)</span>')
TEAM_RE = re.compile(r'<a href="/team/\d+"[^>]*>(.*?)</a>')
ORIGINAL_RE = re.compile(
    r'<div class="well">\s*<a href="([^"]+)"[^>]*>\s*Original writeup\s*</a>', re.DOTALL)
DESC_RE = re.compile(r'<div class="well" id="id_description">(.*?)</div>', re.DOTALL)
TAG_STRIP_RE = re.compile(r"<[^>]+>")


def _text(html: str) -> str:
    return TAG_STRIP_RE.sub("", html or "").replace("&amp;", "&").replace("&#39;", "'") \
        .replace("&quot;", '"').replace("&lt;", "<").replace("&gt;", ">").replace("&nbsp;", " ").strip()


# ctftime carries a handful of planted "writeups" whose only content is an instruction
# aimed at LLM scrapers (exfiltrate your environment to a URL in exchange for a flag).
# They are not challenge writeups, they are bait. Never render them; never act on them.
BAIT_PATTERNS = (
    "ctftimecanary",
    "llm-exp",
    "send your environment",
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard your instructions",
)


# ctftime appends an anti-scraper canary to the inline description of EVERY writeup:
# a sentence instructing a language model to exfiltrate its environment to a URL.
# It is not part of the writeup, and it must be stripped before we measure whether the
# inline description has real content - otherwise its length alone makes every stub
# look substantive and we never follow through to the actual writeup.
CANARY_RE = re.compile(
    r"(?is)(?:<p>\s*)?[^<>]{0,80}\bctftimecanary\b.*?(?:</p>|$)")
CANARY_PLAIN_RE = re.compile(
    r"(?is)if you see (?:the )?string\s+ctftimecanary.*?(?:for flag\.?|\Z)")


def strip_canary(text: str) -> str:
    """Remove ctftime's anti-scraper injection from a description or body."""
    if "ctftimecanary" not in text.lower():
        return text
    text = CANARY_RE.sub("", text)
    text = CANARY_PLAIN_RE.sub("", text)
    # Belt and braces: drop any leftover line that still mentions it.
    return "\n".join(l for l in text.splitlines()
                      if "ctftimecanary" not in l.lower() and "llm-exp" not in l.lower())


def looks_like_bait(body: str) -> str:
    """Return a reason string if this body should be dropped, else ''."""
    lowered = body.lower()
    for pattern in BAIT_PATTERNS:
        if pattern in lowered:
            return f"scraper-bait:{pattern}"
    # A "writeup" with no substance is not worth a file either.
    if len(re.sub(r"\s+", " ", body).strip()) < 400:
        return "too-short"
    return ""


# --------------------------------------------------------------------- crawl
def crawl(fetcher: Fetcher, pages: int) -> list[dict]:
    records: dict[str, dict] = {r["id"]: r for r in (load_json(INDEX_JSON, []) or [])}
    before = len(records)
    empty_streak = 0

    for page in range(1, pages + 1):
        url = f"{BASE}/writeups?page={page}" if page > 1 else f"{BASE}/writeups"
        html = fetcher.get(url)
        if not html:
            print(f"  page {page}: fetch failed")
            continue
        found = 0
        for ev_id, ev_name, task_id, task_name, tags_html, team_html, wu_id in ROW_RE.findall(html):
            found += 1
            tags = [t.strip().lower() for t in LABEL_RE.findall(tags_html) if t.strip()]
            team = TEAM_RE.search(team_html)
            records[wu_id] = {
                "id": wu_id,
                "event_id": ev_id,
                "event": _text(ev_name),
                "task_id": task_id,
                "task": _text(task_name),
                "tags": tags,
                "team": _text(team.group(1)) if team else "",
            }
        print(f"  page {page:>3}: {found} rows  (total {len(records)})")
        empty_streak = empty_streak + 1 if found == 0 else 0
        if empty_streak >= 3:
            print("  three empty pages in a row - stopping")
            break

    out = sorted(records.values(), key=lambda r: -int(r["id"]))
    save_json(INDEX_JSON, out)
    print(f"crawl: {len(out)} writeups indexed ({len(out) - before} new)")
    return out


# --------------------------------------------------------------------- fetch
def github_raw(url: str) -> str | None:
    """Turn a github.com page URL into the raw URL for its markdown, when we can."""
    parsed = urlparse(url)
    if parsed.netloc not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) >= 5 and parts[2] in ("blob", "tree"):
        owner, repo, kind, ref, *rest = parts
        path = "/".join(rest)
        if kind == "blob":
            return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path.rstrip('/')}/README.md"
    if len(parts) == 2:
        owner, repo = parts
        return f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/README.md"
    return None


def html_to_markdown(html: str, base_url: str) -> str:
    import html2text
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")
    for bad in soup(["script", "style", "nav", "header", "footer", "noscript",
                     "form", "iframe", "svg", "aside"]):
        bad.decompose()
    for selector in ("#comments", ".comments", ".sidebar", ".navbar", ".menu",
                     ".site-header", ".site-footer", ".related-posts", ".share"):
        for node in soup.select(selector):
            node.decompose()

    main = None
    for selector in ("article", "main", ".post-content", ".entry-content", ".markdown-body",
                     ".content", "#content", ".post", ".markdown"):
        node = soup.select_one(selector)
        if node and len(node.get_text(strip=True)) > 400:
            main = node
            break
    main = main or soup.body or soup

    # Make links and images work when read offline.
    for tag, attr in (("a", "href"), ("img", "src")):
        for node in main.find_all(tag):
            value = node.get(attr)
            if value and not value.startswith(("http://", "https://", "data:", "#")):
                node[attr] = urljoin(base_url, value)

    converter = html2text.HTML2Text()
    converter.body_width = 0
    converter.ignore_images = False
    converter.ignore_links = False
    converter.mark_code = True
    text = converter.handle(str(main))
    text = re.sub(r"\[code\]\s*\n", "\n```\n", text)
    text = re.sub(r"\n\s*\[/code\]", "\n```", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    # Some sites stuff a whole abstract into an image alt attribute; it renders as noise.
    text = re.sub(r"!\[[^\]]{300,}?\]\(", "![image](", text)
    return text.strip()


def fetch_one(fetcher: Fetcher, record: dict) -> dict:
    """Fetch a writeup page and, if it only links out, the external source too."""
    out = dict(record)
    html = fetcher.get(f"{BASE}/writeup/{record['id']}")
    if not html:
        out["status"] = "writeup-page-failed"
        return out

    original = ORIGINAL_RE.search(html)
    out["original"] = original.group(1).strip() if original else ""

    desc = DESC_RE.search(html)
    inline = strip_canary(desc.group(1).strip()) if desc else ""
    # A description that is only the external link carries no content of its own.
    inline_text = _text(inline)
    has_inline = len(inline_text) > 300 or inline.count("<p>") > 2

    if has_inline:
        try:
            out["body"] = strip_canary(html_to_markdown(f"<div>{inline}</div>", BASE))
            out["body_source"] = "ctftime-inline"
            out["status"] = "ok"
            return out
        except Exception as exc:                      # noqa: BLE001
            out["status"] = f"inline-convert-failed: {exc}"

    if not out["original"]:
        out["status"] = "no-body-no-original"
        return out

    raw = github_raw(out["original"])
    if raw:
        markdown = fetcher.get(raw, suffix=".md")
        if markdown and len(markdown.strip()) > 120:
            out["body"] = strip_canary(markdown)
            out["body_source"] = "github-raw"
            out["status"] = "ok"
            return out

    page = fetcher.get(out["original"])
    if not page:
        out["status"] = "external-fetch-failed"
        return out
    try:
        markdown = html_to_markdown(page, out["original"])
    except Exception as exc:                          # noqa: BLE001
        out["status"] = f"external-convert-failed: {exc}"
        return out
    if len(markdown.strip()) < 200:
        out["status"] = "external-too-short"
        return out
    out["body"] = strip_canary(markdown)
    out["body_source"] = "external-html"
    out["status"] = "ok"
    return out


def fetch(fetcher: Fetcher, limit: int, workers: int) -> list[dict]:
    records = load_json(INDEX_JSON, []) or []
    if not records:
        print("nothing indexed - run `crawl` first")
        return []
    done = {d["id"]: d for d in (load_json(DETAIL_JSON, []) or []) if d.get("status") == "ok"}
    todo = [r for r in records if r["id"] not in done][:limit]
    print(f"fetch: {len(todo)} to fetch, {len(done)} already good")

    results = list(done.values())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_one, fetcher, r): r for r in todo}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                results.append(future.result())
            except Exception as exc:                  # noqa: BLE001
                bad = dict(futures[future])
                bad["status"] = f"exception: {exc}"
                results.append(bad)
            if i % 50 == 0:
                ok = sum(1 for r in results if r.get("status") == "ok")
                print(f"  {i}/{len(todo)} fetched  ({ok} with bodies)"
                      f"  cache hit/miss/fail {fetcher.stats}")
    save_json(DETAIL_JSON, results)
    ok = sum(1 for r in results if r.get("status") == "ok")
    print(f"fetch: {ok}/{len(results)} have a usable body")
    return results


# -------------------------------------------------------------------- render
def render(limit: int) -> dict:
    details = load_json(DETAIL_JSON, []) or []
    usable = [d for d in details if d.get("status") == "ok" and d.get("body")][:limit]
    counts: dict[str, int] = {}
    written = 0
    seen: set[Path] = set()

    dropped: dict[str, int] = {}
    for record in usable:
        body = record["body"].strip()
        reason = looks_like_bait(body)
        if reason:
            dropped[reason.split(":")[0]] = dropped.get(reason.split(":")[0], 0) + 1
            continue
        event = record.get("event", "")
        task = record.get("task", "") or "task"
        source_tags = record.get("tags", [])

        category = categorise(task, event, body[:6000], tags=source_tags)
        tags = mine_tags(task, event, body[:12000], extra=source_tags)
        if category not in tags:
            tags.insert(0, category)
        subcategory = pick_subcategory(tags)
        if subcategory and subcategory not in tags:
            tags.append(subcategory)

        year_match = re.search(r"(20\d{2})", event)
        year = int(year_match.group(1)) if year_match else None

        # The CTF's own name and year are how you find a writeup you half-remember
        # ("that lattice thing from SekaiCTF"), and they keep thin writeups findable.
        event_base = re.sub(r"\s*(20\d{2}|v?\d+(\.\d+)*)\s*$", "", event).strip()
        for extra_tag in (slugify(event_base, 30), slugify(event, 34),
                          str(year) if year else "", "ctf-writeup"):
            if extra_tag and extra_tag not in tags and extra_tag != "untitled":
                tags.append(extra_tag)

        original = record.get("original", "")
        summary = first_sentence(body) or f"Writeup for {task} from {event}."

        path = CONTENT / "writeups" / category / f"ctftime-{slugify(event, 40)}-{slugify(task, 40)}.md"
        n = 2
        while path in seen:
            path = path.with_name(f"{path.stem}-{n}.md")
            n += 1
        seen.add(path)

        meta = [
            "## Metadata", "",
            f"- **CTF:** {event}",
            f"- **Task:** {task}",
        ]
        if record.get("team"):
            meta.append(f"- **Author team:** {record['team']}")
        if source_tags:
            meta.append(f"- **CTFtime tags:** {', '.join(source_tags)}")
        meta.append(f"- **CTFtime:** <{BASE}/writeup/{record['id']}>")
        if original:
            meta.append(f"- **Original writeup:** <{original}>")
        meta += ["", "---", ""]

        write_doc(
            path,
            {
                "title": f"{task} - {event}" if event else task,
                "category": category,
                "subcategory": subcategory,
                "type": "writeup",
                "tags": tags,
                "summary": summary,
                "source": {"name": f"CTFtime writeup #{record['id']}",
                           "url": f"{BASE}/writeup/{record['id']}"},
                "original_source": original,
                "ctf": {"name": event, "year": year, "challenge": task},
            },
            "\n".join(meta) + truncate(body, 1200, original or f"{BASE}/writeup/{record['id']}"),
        )
        counts[category] = counts.get(category, 0) + 1
        written += 1

    failures: dict[str, int] = {}
    for d in details:
        if d.get("status") != "ok":
            failures[str(d.get("status", "?")).split(":")[0]] = \
                failures.get(str(d.get("status", "?")).split(":")[0], 0) + 1

    report = {"indexed": len(load_json(INDEX_JSON, []) or []),
              "fetched": len(details), "rendered": written, "dropped": dropped,
              "by_category": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
              "failures": failures}
    save_json(REPORT_JSON, report)
    print(f"render: {written} documents")
    for category, n in report["by_category"].items():
        print(f"    {category:<12} {n}")
    if dropped:
        print(f"  dropped: {dropped}")
    if failures:
        print(f"  skipped: {failures}")
    return report


# ---------------------------------------------------------------------- main
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["crawl", "fetch", "render", "all"])
    parser.add_argument("--pages", type=int, default=60)
    parser.add_argument("--limit", type=int, default=1500)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--rate", type=float, default=2.5, help="max requests per second")
    args = parser.parse_args()

    fetcher = Fetcher(CACHE / "http", rate=args.rate)
    if args.command in ("crawl", "all"):
        crawl(fetcher, args.pages)
    if args.command in ("fetch", "all"):
        fetch(fetcher, args.limit, args.workers)
    if args.command in ("render", "all"):
        render(args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
