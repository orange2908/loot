"""`ctfbrain`: the terminal interface to the knowledge base."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import webbrowser
from pathlib import Path

from .config import CATEGORIES, CATEGORY_META, DOC_TYPES, INDEX_DB
from . import __version__

# ------------------------------------------------------------------ output
try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
    _console = Console()
    RICH = True
except ImportError:  # pragma: no cover - degraded but usable
    _console = None
    RICH = False

CAT_COLOR = {
    "crypto": "magenta", "web": "cyan", "pwn": "red", "rev": "yellow",
    "forensics": "green", "stego": "bright_magenta", "misc": "bright_black",
    "osint": "bright_cyan", "mobile": "bright_green", "hardware": "bright_yellow",
    "blockchain": "yellow", "cloud": "blue", "sherlocks": "bright_blue",
}


def out(*args, **kwargs) -> None:
    if RICH:
        _console.print(*args, **kwargs)
    else:
        print(*[a for a in args if isinstance(a, str)], **{})


def die(message: str, code: int = 1) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


def _brain():
    from .search import Brain
    try:
        return Brain()
    except FileNotFoundError as exc:
        die(f"{exc}")


# ------------------------------------------------------------------ commands
def cmd_index(args) -> int:
    from .index import build
    print(f"Indexing content -> {INDEX_DB}")
    summary = build(verbose=not args.quiet)
    print(f"\n  {summary['documents']} documents, "
          f"{summary['total_lines']:,} lines, "
          f"{summary['code_blocks']:,} code blocks, "
          f"{summary['unique_tags']:,} unique tags "
          f"in {summary['duration_s']}s")
    if summary["by_category"]:
        widest = max(len(c) for c in summary["by_category"])
        for cat, n in summary["by_category"].items():
            print(f"    {cat:<{widest}}  {n}")
    if summary["failed"] or summary["duplicates"]:
        print(f"\n  ! {summary['failed']} failed, {summary['duplicates']} duplicate slugs")
        for err in summary["errors"][:10]:
            print(f"    {err}")
    if summary["problems"]:
        print(f"\n  frontmatter warnings: {summary['problems']}"
              f"\n  (run `ctfbrain lint` for the details)")
    return 0


def _print_hits(hits, total: int, query: str, show_path: bool) -> None:
    if not hits:
        out(f"[yellow]No results for[/] [bold]{query}[/]" if RICH
            else f"No results for {query}")
        out("  try: fewer words, a tool name, or `ctfbrain tags` to see the vocabulary")
        return
    header = f"{total} match{'es' if total != 1 else ''} for {query!r}"
    if RICH:
        _console.print(f"[dim]{header}[/]\n")
    else:
        print(header + "\n")

    for i, hit in enumerate(hits, 1):
        color = CAT_COLOR.get(hit.category, "white")
        meta = f"{hit.category}/{hit.type}"
        if hit.difficulty:
            meta += f" · {hit.difficulty}"
        if hit.ctf_name:
            # The CTF name usually already carries its year; avoid "2022 2022".
            label = hit.ctf_name
            if hit.ctf_year and str(hit.ctf_year) not in hit.ctf_name:
                label = f"{hit.ctf_name} {hit.ctf_year}"
            meta += f" · {label}"
        if RICH:
            line = Text()
            line.append(f"{i:>2}. ", style="dim")
            line.append(hit.title, style=f"bold {color}")
            _console.print(line)
            _console.print(f"    [dim]{meta}[/]  [dim cyan]{hit.slug}[/]")
            if hit.summary:
                _console.print(f"    {hit.summary}")
            if hit.snippet and hit.snippet != hit.summary:
                snip = hit.snippet.replace("«", "[bold yellow]").replace("»", "[/bold yellow]")
                _console.print(f"    [dim]{snip}[/]")
            if hit.tags:
                _console.print(f"    [dim]#{'  #'.join(hit.tags[:10])}[/]")
            if show_path:
                _console.print(f"    [dim]{hit.path}[/]")
            _console.print()
        else:
            print(f"{i:>2}. {hit.title}\n    {meta}  {hit.slug}\n    {hit.summary}\n")


def cmd_search(args) -> int:
    brain = _brain()
    query = " ".join(args.query)
    hits, total = brain.search(
        query, category=args.category, doctype=args.type,
        tags=args.tag, difficulty=args.difficulty,
        limit=args.limit, synonyms=not args.no_synonyms)
    if args.json:
        print(json.dumps({"query": query, "total": total,
                          "results": [h.to_dict() for h in hits]}, indent=2))
        return 0
    _print_hits(hits, total, query, args.paths)
    if hits and not args.paths:
        out(f"[dim]open one with:[/] ctfbrain show {hits[0].slug}" if RICH
            else f"open one with: ctfbrain show {hits[0].slug}")
    return 0


def _resolve(brain, slug: str) -> dict:
    doc = brain.get(slug)
    if doc:
        return doc
    hits, _ = brain.search(slug, limit=1)
    if hits:
        return brain.get(hits[0].slug)
    die(f"no document matching {slug!r}")


def cmd_show(args) -> int:
    brain = _brain()
    doc = _resolve(brain, args.slug)
    if args.raw:
        print(Path(doc["path"]).read_text(encoding="utf-8"))
        return 0

    color = CAT_COLOR.get(doc["category"], "white")
    head = [f"{doc['category']}/{doc['type']}"]
    if doc.get("subcategory"):
        head.append(doc["subcategory"])
    if doc.get("difficulty"):
        head.append(doc["difficulty"])
    if doc.get("ctf_name"):
        head.append(doc["ctf_name"])

    if RICH:
        _console.print(Panel(
            Text(doc["title"], style=f"bold {color}"),
            subtitle=" · ".join(head), border_style=color, expand=True))
        if doc.get("summary"):
            _console.print(f"  {doc['summary']}\n")
        if doc.get("when_to_use"):
            _console.print("[bold]Use when[/]")
            for item in doc["when_to_use"]:
                _console.print(f"  • {item}")
            _console.print()
        if doc.get("tags"):
            _console.print(f"[dim]#{'  #'.join(doc['tags'])}[/]\n")
        if doc.get("source_url"):
            _console.print(f"[dim]source: {doc.get('source_name') or ''} "
                           f"{doc['source_url']}[/]\n")
        markdown = Markdown(doc["body"], code_theme="one-dark", hyperlinks=True)
        if args.no_pager or not sys.stdout.isatty():
            _console.print(markdown)
        else:
            with _console.pager(styles=True):
                _console.print(markdown)
    else:
        print(doc["title"]); print(" · ".join(head)); print()
        print(doc["body"])

    related = brain.related(doc["slug"], limit=6)
    if related and not args.no_pager:
        out("\n[bold]Related[/]" if RICH else "\nRelated")
        for rel in related:
            out(f"  [dim]{rel['category']}/{rel['type']}[/]  {rel['title']}  "
                f"[dim cyan]{rel['slug']}[/]" if RICH
                else f"  {rel['category']}/{rel['type']}  {rel['title']}  {rel['slug']}")
    return 0


def cmd_cat(args) -> int:
    brain = _brain()
    doc = _resolve(brain, args.slug)
    print(Path(doc["path"]).read_text(encoding="utf-8"))
    return 0


def cmd_code(args) -> int:
    """Print just the code blocks. The fastest path from a search hit to a working script."""
    import re
    brain = _brain()
    doc = _resolve(brain, args.slug)
    blocks = re.findall(r"^[ \t]*```([^\n`]*)\n(.*?)^[ \t]*```",
                        doc["body"], re.DOTALL | re.MULTILINE)
    if not blocks:
        die(f"{doc['slug']} has no code blocks")
    for i, (lang, src) in enumerate(blocks, 1):
        lang = (lang.strip() or "text").split()[0]
        if args.lang and lang != args.lang:
            continue
        if args.first and i != 1:
            break
        if RICH and not args.plain:
            _console.print(f"[dim]--- block {i} ({lang}) ---[/]")
            _console.print(Syntax(src, lang, theme="one-dark", line_numbers=False))
        else:
            print(f"# --- block {i} ({lang}) ---")
            print(src)
    return 0


def cmd_open(args) -> int:
    brain = _brain()
    doc = _resolve(brain, args.slug)
    if args.web:
        webbrowser.open(f"http://{args.host}:{args.port}/doc/{doc['slug']}")
        return 0
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL") or "open"
    subprocess.run([editor, doc["path"]], check=False)
    return 0


def cmd_related(args) -> int:
    brain = _brain()
    doc = _resolve(brain, args.slug)
    rows = brain.related(doc["slug"], limit=args.limit)
    if not rows:
        out("no related documents (this one has no tags)")
        return 0
    out(f"[bold]Related to[/] {doc['title']}\n" if RICH else f"Related to {doc['title']}\n")
    for rel in rows:
        out(f"  [dim]{rel['category']}/{rel['type']:<10}[/] {rel['title']}\n"
            f"      [dim cyan]{rel['slug']}[/]" if RICH
            else f"  {rel['category']}/{rel['type']} {rel['title']}  {rel['slug']}")
    return 0


def cmd_tags(args) -> int:
    brain = _brain()
    rows = brain.tags(category=args.category, limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2)); return 0
    if RICH:
        table = Table(box=None, pad_edge=False)
        table.add_column("tag", style="cyan"); table.add_column("docs", justify="right", style="dim")
        for row in rows:
            table.add_row(row["tag"], str(row["n"]))
        _console.print(table)
    else:
        for row in rows:
            print(f"{row['tag']:<40} {row['n']}")
    return 0


def cmd_stats(args) -> int:
    brain = _brain()
    data = brain.stats()
    if args.json:
        print(json.dumps(data, indent=2)); return 0
    if RICH:
        _console.print(Panel(
            f"[bold]{data['documents']:,}[/] documents   "
            f"[bold]{data['total_lines']:,}[/] lines   "
            f"[bold]{data['code_blocks']:,}[/] code blocks   "
            f"[bold]{data['unique_tags']:,}[/] tags   "
            f"[bold]{data['ctfs']:,}[/] CTFs",
            title="CTF-Brain", border_style="cyan"))
        table = Table(box=None)
        table.add_column("category"); table.add_column("docs", justify="right")
        table.add_column("description", style="dim")
        for cat, n in data["by_category"].items():
            label, _, desc = CATEGORY_META.get(cat, (cat, "", ""))
            table.add_row(f"[{CAT_COLOR.get(cat,'white')}]{label}[/]", str(n), desc)
        _console.print(table)
        _console.print()
        types = Table(box=None)
        types.add_column("type"); types.add_column("docs", justify="right")
        for kind, n in data["by_type"].items():
            types.add_row(kind, str(n))
        _console.print(types)
    else:
        print(json.dumps(data, indent=2))
    return 0


def cmd_lint(args) -> int:
    brain = _brain()
    rows = brain.problems()
    if not rows:
        out("[green]No frontmatter problems.[/]" if RICH else "No frontmatter problems.")
        return 0
    by_problem: dict[str, list[str]] = {}
    for row in rows:
        by_problem.setdefault(row["problem"].split(":")[0], []).append(row["slug"])
    print(f"{len(rows)} problems across {len({r['slug'] for r in rows})} documents\n")
    for problem, slugs in sorted(by_problem.items(), key=lambda kv: -len(kv[1])):
        print(f"  {problem}: {len(slugs)}")
        if args.verbose:
            for slug in slugs[:50]:
                print(f"      {slug}")
    return 1 if args.strict else 0


def cmd_random(args) -> int:
    brain = _brain()
    doc = brain.random(category=args.category, doctype=args.type)
    if not doc:
        die("nothing in the index matches")
    args.slug, args.raw, args.no_pager = doc["slug"], False, True
    return cmd_show(args)


def cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        die("uvicorn is not installed. Run: pip install -r requirements.txt")
    if not INDEX_DB.exists():
        print("No index yet, building one first.")
        from .index import build
        build()
    url = f"http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}"
    print(f"CTF-Brain serving on {url}")
    if args.open:
        webbrowser.open(url)
    uvicorn.run("ctfbrain.api:app", host=args.host, port=args.port,
                reload=args.reload, log_level="warning")
    return 0


def cmd_categories(args) -> int:
    for cat in CATEGORIES:
        label, _, desc = CATEGORY_META[cat]
        out(f"  [{CAT_COLOR.get(cat,'white')}]{cat:<11}[/] {label:<16} [dim]{desc}[/]"
            if RICH else f"  {cat:<11} {label:<16} {desc}")
    return 0


# ------------------------------------------------------------------ parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfbrain",
        description="Offline, searchable CTF knowledge base.",
        epilog=(
            "examples:\n"
            "  ctfbrain search gcd\n"
            "  ctfbrain search 'padding oracle' -c crypto\n"
            "  ctfbrain search rsa cat:crypto type:cheatsheet\n"
            "  ctfbrain show crypto:rsa-common-modulus\n"
            "  ctfbrain code techniques:crypto:rsa-wiener-small-d --first\n"
            "  ctfbrain serve --open\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"ctfbrain {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("index", help="(re)build the search index from content/")
    p.add_argument("-q", "--quiet", action="store_true")
    p.set_defaults(func=cmd_index)

    p = sub.add_parser("search", aliases=["s", "find"], help="search the knowledge base")
    p.add_argument("query", nargs="+")
    p.add_argument("-c", "--category", choices=CATEGORIES)
    p.add_argument("-t", "--type", choices=DOC_TYPES)
    p.add_argument("--tag", action="append", default=[])
    p.add_argument("-d", "--difficulty")
    p.add_argument("-n", "--limit", type=int, default=15)
    p.add_argument("--json", action="store_true")
    p.add_argument("--paths", action="store_true", help="show file paths")
    p.add_argument("--no-synonyms", action="store_true", help="exact terms only")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("show", aliases=["view"], help="render a document")
    p.add_argument("slug")
    p.add_argument("--raw", action="store_true", help="print the source markdown")
    p.add_argument("--no-pager", action="store_true")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("cat", help="print a document's raw markdown")
    p.add_argument("slug"); p.set_defaults(func=cmd_cat)

    p = sub.add_parser("code", help="print only the code blocks of a document")
    p.add_argument("slug")
    p.add_argument("--lang", help="only blocks in this language")
    p.add_argument("--first", action="store_true", help="only the first block")
    p.add_argument("--plain", action="store_true", help="no syntax colouring")
    p.set_defaults(func=cmd_code)

    p = sub.add_parser("open", help="open a document in $EDITOR (or the web UI)")
    p.add_argument("slug")
    p.add_argument("--web", action="store_true")
    p.add_argument("--host", default="localhost"); p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_open)

    p = sub.add_parser("related", help="documents sharing tags with this one")
    p.add_argument("slug"); p.add_argument("-n", "--limit", type=int, default=12)
    p.set_defaults(func=cmd_related)

    p = sub.add_parser("tags", help="list tags by frequency")
    p.add_argument("-c", "--category", choices=CATEGORIES)
    p.add_argument("-n", "--limit", type=int, default=100)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_tags)

    p = sub.add_parser("stats", help="corpus statistics")
    p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_stats)

    p = sub.add_parser("categories", help="list the categories")
    p.set_defaults(func=cmd_categories)

    p = sub.add_parser("lint", help="report frontmatter problems")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--strict", action="store_true", help="exit non-zero if any problems")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("random", help="show a random document")
    p.add_argument("-c", "--category", choices=CATEGORIES)
    p.add_argument("-t", "--type", choices=DOC_TYPES)
    p.set_defaults(func=cmd_random)

    p = sub.add_parser("serve", help="run the web UI")
    p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true"); p.add_argument("--open", action="store_true")
    p.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
