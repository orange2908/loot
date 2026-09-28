#!/usr/bin/env python3
"""Ingest challenge-author repositories: the challenge plus the author's own solution.

    python3 ingest/challenge_repos.py add --url https://github.com/owner/name
    python3 ingest/challenge_repos.py list
    python3 ingest/challenge_repos.py ingest --only arkark-my-ctf-challenges
    python3 ingest/challenge_repos.py all

Repositories live in `ingest/sources.json`, so adding one later is a single
command and a re-run. Everything goes through the authenticated `gh` CLI and is
cached by blob sha under data/raw/challenge-repos/, so re-runs are free.

These repos are written by the people who *set* the challenges, which makes the
solution in them authoritative rather than one competitor's guess. Bodies are
capped and every document links back to the exact commit it was read from.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    CONTENT, RAW, categorise, first_sentence, load_json, mine_tags,
    pick_subcategory, save_json, slugify, truncate, write_doc,
)
from ctftime import looks_like_bait  # noqa: E402

HERE = Path(__file__).resolve().parent
SOURCES = HERE / "sources.json"
CACHE = RAW / "challenge-repos"
PREFIX = "chal-"

CATEGORY_WORDS = {
    "crypto": "crypto", "cryptography": "crypto",
    "web": "web", "websec": "web",
    "pwn": "pwn", "pwnable": "pwn", "binary": "pwn", "bin": "pwn",
    "rev": "rev", "reversing": "rev", "reverse": "rev", "re": "rev",
    "forensics": "forensics", "for": "forensics", "network": "forensics",
    "stego": "stego", "steganography": "stego",
    "misc": "misc", "ppc": "misc", "jail": "misc", "sandbox": "misc",
    "osint": "osint",
    "mobile": "mobile", "android": "mobile", "ios": "mobile",
    "hardware": "hardware", "embedded": "hardware",
    "blockchain": "blockchain", "smartcontract": "blockchain", "solidity": "blockchain",
    "cloud": "cloud", "kubernetes": "cloud",
}

# A README in one of these directories belongs to the challenge above it.
SOLUTION_DIRS = {"solver", "solve", "solution", "solutions", "exploit", "exploits",
                 "writeup", "writeups", "sol"}
# Directories that are challenge scaffolding, never the challenge itself.
NOISE_DIRS = {".github", ".vscode", "node_modules", "dist", "files", "distfiles",
              "assets", "images", "img", "public", "static", "target", "build"}

CODE_SUFFIXES = {".py", ".sol", ".js", ".ts", ".rs", ".go", ".c", ".cpp", ".rb",
                 ".sh", ".java", ".sage", ".ml", ".hs", ".php"}
LANG = {".py": "python", ".sol": "solidity", ".js": "javascript", ".ts": "typescript",
        ".rs": "rust", ".go": "go", ".c": "c", ".cpp": "cpp", ".rb": "ruby",
        ".sh": "bash", ".java": "java", ".sage": "python", ".php": "php"}

MAX_SOLVER_FILES = 4
MAX_SOLVER_LINES = 220


def gh(*args: str) -> str:
    proc = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip()[:300])
    return proc.stdout


# ------------------------------------------------------------------- sources
def load_sources() -> list[dict]:
    return load_json(SOURCES, []) or []


def save_sources(rows: list[dict]) -> None:
    save_json(SOURCES, rows)


def add_source(url: str, note: str = "") -> dict:
    match = re.search(r"github\.com[/:]([^/]+)/([^/.\s]+)", url.strip())
    if not match:
        raise SystemExit(f"not a GitHub URL: {url}")
    repo = f"{match.group(1)}/{match.group(2)}"

    info = json.loads(gh("repo", "view", repo, "--json",
                         "nameWithOwner,description,stargazerCount,defaultBranchRef"))
    try:
        licence = json.loads(gh("api", f"repos/{repo}/license")).get(
            "license", {}).get("spdx_id") or "NOASSERTION"
    except RuntimeError:
        licence = "none stated"

    rows = load_sources()
    for row in rows:
        if row["repo"].lower() == repo.lower():
            print(f"already tracked: {repo}")
            return row

    row = {
        "repo": info["nameWithOwner"],
        "slug": slugify(info["nameWithOwner"].replace("/", "-"), 50),
        "branch": info["defaultBranchRef"]["name"],
        "description": (info.get("description") or "")[:200],
        "stars": info["stargazerCount"],
        "licence": licence,
        "note": note,
    }
    rows.append(row)
    save_sources(rows)
    print(f"added {row['repo']}  (stars {row['stars']}, licence {row['licence']})")
    return row


# ------------------------------------------------------------------- fetching
def repo_tree(row: dict) -> list[dict]:
    cache = CACHE / f"tree-{row['slug']}.json"
    cached = load_json(cache)
    if cached:
        return cached
    data = json.loads(gh("api", f"repos/{row['repo']}/git/trees/{row['branch']}?recursive=1"))
    tree = [t for t in data.get("tree", []) if t.get("type") == "blob"]
    save_json(cache, tree)
    return tree


def head_sha(row: dict) -> str:
    cache = CACHE / f"sha-{row['slug']}.json"
    cached = load_json(cache)
    if cached:
        return cached["sha"]
    sha = json.loads(gh("api", f"repos/{row['repo']}/commits/{row['branch']}"))["sha"]
    save_json(cache, {"sha": sha})
    return sha


def blob(row: dict, entry: dict) -> str | None:
    """Fetch a blob by its immutable sha, so the cache never goes stale."""
    sha = entry["sha"]
    path = CACHE / "blobs" / sha[:2] / sha
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(gh("api", f"repos/{row['repo']}/git/blobs/{sha}"))
    except RuntimeError:
        return None
    if data.get("encoding") != "base64":
        return None
    import base64
    try:
        text = base64.b64decode(data["content"]).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return text


# ------------------------------------------------------------------ analysis
def prefetch(row: dict, entries: list[dict], workers: int = 6) -> None:
    """Warm the blob cache in parallel.

    Each blob costs a `gh` subprocess, which dominated the run time; fetching a
    challenge's files together turns a serial stall into one round trip.
    """
    missing = [e for e in entries
               if not (CACHE / "blobs" / e["sha"][:2] / e["sha"]).exists()]
    if len(missing) < 2:
        return
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(lambda e: blob(row, e), missing))


def challenge_dirs(tree: list[dict]) -> dict[str, dict]:
    """Group READMEs into challenges, folding solver/ READMEs into their parent."""
    by_dir: dict[str, dict] = {}
    for entry in tree:
        path = Path(entry["path"])
        if path.name.lower() != "readme.md":
            continue
        parts = path.parts[:-1]
        if not parts:
            continue                                  # repo root README
        if any(p in NOISE_DIRS for p in parts):
            continue
        if parts[-1].lower() in SOLUTION_DIRS:
            owner = "/".join(parts[:-1])
            if not owner:
                continue
            by_dir.setdefault(owner, {"dir": owner, "readme": None, "extra": []})
            by_dir[owner]["extra"].append(entry)
        else:
            owner = "/".join(parts)
            by_dir.setdefault(owner, {"dir": owner, "readme": None, "extra": []})
            by_dir[owner]["readme"] = entry
    return {k: v for k, v in by_dir.items() if v["readme"] or v["extra"]}


def solver_files(tree: list[dict], challenge_dir: str) -> list[dict]:
    out = []
    prefix = challenge_dir + "/"
    for entry in tree:
        path = Path(entry["path"])
        if not entry["path"].startswith(prefix):
            continue
        rel = path.relative_to(challenge_dir)
        if not any(p.lower() in SOLUTION_DIRS for p in rel.parts[:-1]):
            continue
        if path.suffix.lower() not in CODE_SUFFIXES:
            continue
        if entry.get("size", 0) > 60_000:
            continue
        out.append(entry)
    out.sort(key=lambda e: (len(Path(e["path"]).parts), e["path"]))
    return out[:MAX_SOLVER_FILES]


# Words that must not be title-cased when a name arrives as "seccon ctf 2023 quals".
ACRONYMS = {"ctf", "rsa", "xss", "ssrf", "ssti", "xxe", "jwt", "sql", "sqli", "rce",
            "evm", "vm", "js", "css", "html", "http", "api", "cpu", "gpu", "io",
            "pwn", "re", "osint", "dns", "tls", "ssl", "aes", "ecc", "lfi", "csp",
            "uaf", "rop", "gcd", "php", "xml", "json", "utf", "ai", "ml", "iot"}


def prettify(name: str) -> str:
    """Make `seccon ctf 2023 quals` read as `SECCON CTF 2023 Quals`.

    Names that already carry their own capitalisation are left alone, so
    `whitespace.js` and `pp3` survive untouched.
    """
    if not name or name != name.lower():
        return name
    out = []
    for word in name.split():
        if word in ACRONYMS:
            out.append(word.upper())
        elif word.isdigit():
            out.append(word)
        else:
            out.append(word[:1].upper() + word[1:])
    return " ".join(out)


def parse_ctf(parts: tuple[str, ...]) -> tuple[str, int | None]:
    """Pull a CTF name and year out of a path segment like 202112_SECCON_CTF_2021."""
    for part in parts:
        if len(part) < 4:
            continue
        year = re.search(r"(20\d{2})", part)
        if not year:
            continue
        name = re.sub(r"^\d{6}[_-]?", "", part)        # strip a leading YYYYMM
        name = re.sub(r"[_-]+", " ", name).strip()
        if name:
            return prettify(name), int(year.group(1))
    for part in parts:
        cleaned = re.sub(r"[_-]+", " ", part).strip()
        if len(cleaned) > 3 and cleaned.lower() not in ("ctfs", "challenges", "src"):
            return prettify(cleaned), None
    return "", None


def path_category(parts: tuple[str, ...]) -> str:
    for part in parts:
        key = re.sub(r"[^a-z]", "", part.lower())
        if key in CATEGORY_WORDS:
            return CATEGORY_WORDS[key]
    return ""


# ------------------------------------------------------------------- render
def ingest_repo(row: dict) -> dict:
    tree = repo_tree(row)
    sha = head_sha(row)
    challenges = challenge_dirs(tree)

    # Warm every README in one parallel pass before rendering anything.
    readmes = [c["readme"] for c in challenges.values() if c["readme"]]
    readmes += [e for c in challenges.values() for e in c["extra"]]
    prefetch(row, readmes)

    counts: dict[str, int] = {}
    skipped: dict[str, int] = {}
    written = 0

    for cdir, info in sorted(challenges.items()):
        parts = tuple(Path(cdir).parts)
        body_parts: list[str] = []

        readme = info["readme"]
        main = blob(row, readme) if readme else None
        if main:
            main = re.sub(r"\A---\n.*?\n---\n", "", main, flags=re.DOTALL)
            body_parts.append(main.strip())

        for extra in info["extra"]:
            text = blob(row, extra)
            if text and len(text.strip()) > 60:
                label = Path(extra["path"]).parent.name
                body_parts.append(f"\n## Author's {label} notes\n\n{text.strip()}")

        solvers = solver_files(tree, cdir)
        prefetch(row, solvers)
        for entry in solvers:
            code = blob(row, entry)
            if not code or len(code.strip()) < 40:
                continue
            lines = code.splitlines()
            clipped = "\n".join(lines[:MAX_SOLVER_LINES])
            note = ("\n# ... truncated, full file linked above"
                    if len(lines) > MAX_SOLVER_LINES else "")
            lang = LANG.get(Path(entry["path"]).suffix.lower(), "text")
            link = f"https://github.com/{row['repo']}/blob/{sha}/{entry['path']}"
            body_parts.append(
                f"\n## Solver: `{Path(entry['path']).name}`\n\n"
                f"<{link}>\n\n```{lang}\n{clipped}{note}\n```")

        body = "\n\n".join(p for p in body_parts if p).strip()
        if len(body) < 250:
            skipped["too-short"] = skipped.get("too-short", 0) + 1
            continue
        if looks_like_bait(body).startswith("scraper-bait"):
            skipped["bait"] = skipped.get("bait", 0) + 1
            continue

        name = parts[-1]
        pretty = prettify(re.sub(r"[_-]+", " ", name).strip())
        ctf_name, year = parse_ctf(parts[:-1])
        category = path_category(parts) or categorise(pretty, cdir, body[:8000])
        tags = mine_tags(pretty, cdir, body[:12000],
                         extra=[row["slug"], "author-solution", "challenge-source"])
        for extra_tag in (category, slugify(ctf_name, 30) if ctf_name else ""):
            if extra_tag and extra_tag not in tags and extra_tag != "untitled":
                tags.append(extra_tag)

        # "SECCON CTF 2023 Finals" already carries its year; do not repeat it.
        ctf_label = ctf_name
        if year and str(year) not in ctf_name:
            ctf_label = f"{ctf_name} {year}"

        link = f"https://github.com/{row['repo']}/tree/{sha}/{cdir}"
        header = (f"## Challenge\n\n"
                  f"- **Author:** [{row['repo'].split('/')[0]}]"
                  f"(https://github.com/{row['repo'].split('/')[0]})\n"
                  f"- **Source:** <{link}>\n"
                  + (f"- **CTF:** {ctf_label}\n" if ctf_name else "")
                  + "\n---\n\n")

        # Put the challenge name first: truncating the full path used to cut the
        # challenge name off the end, leaving files called "...-2023-finals-misc".
        context = "-".join(parts[:-1])
        out = (CONTENT / "writeups" / category /
               f"{PREFIX}{slugify(row['slug'].split('-')[0], 16)}"
               f"-{slugify(pretty, 40)}"
               f"-{slugify(context, 34)}.md")
        write_doc(out, {
            "title": f"{pretty} - {ctf_label}" if ctf_name else pretty,
            "category": category,
            "subcategory": pick_subcategory(tags),
            "type": "writeup",
            "tags": tags[:20],
            "summary": (first_sentence(body)
                        or f"Challenge {pretty} with the author's own solution."),
            "source": {"name": row["repo"], "url": link},
            "license": row.get("licence") or "none stated",
            "ctf": {"name": ctf_name, "year": year, "challenge": pretty},
        }, header + truncate(body, 1200, link))

        counts[category] = counts.get(category, 0) + 1
        written += 1

    print(f"  {row['repo']:<38} {written:>4} challenges  {dict(sorted(counts.items()))}")
    if skipped:
        print(f"      skipped: {skipped}")
    return {"repo": row["repo"], "sha": sha, "written": written,
            "by_category": counts, "skipped": skipped, "licence": row.get("licence")}


def write_provenance(reports: list[dict]) -> None:
    lines = [
        "# Challenge-author repositories",
        "",
        "Repositories written by the people who *set* the challenges, so the solution",
        "in them is the intended one rather than one competitor's reconstruction.",
        "",
        "Each ingested document carries a permalink to the exact commit it was read",
        "from, and the body is capped. Nothing is republished: this is a private,",
        "personal index that points back at the original work.",
        "",
        "| Repository | Commit | Licence | Challenges |",
        "|---|---|---|---:|",
    ]
    for r in reports:
        lines.append(f"| [{r['repo']}](https://github.com/{r['repo']}) | `{r['sha'][:12]}` | "
                     f"{r.get('licence') or 'none stated'} | {r['written']} |")
    lines += [
        "",
        "## Licence note",
        "",
        "Where the licence column says **none stated**, the upstream repository has no",
        "LICENSE file, so the work remains fully reserved to its author. Those entries",
        "are indexed here for personal reference with attribution and a link, and must",
        "not be redistributed. To remove one, delete its files and run `make index`.",
        "",
    ]
    (CONTENT / "reference" / "chal-REPOS-PROVENANCE.md").write_text(
        "---\n"
        'title: "Challenge-Author Repositories - Provenance"\n'
        'category: "misc"\n'
        'subcategory: "provenance"\n'
        'type: "reference"\n'
        'tags: ["provenance", "attribution", "sources", "challenge-repos", "licence", "credits"]\n'
        'summary: "Which challenge-author repositories are indexed here, at which commit, '
        'under which licence."\n'
        "---\n\n" + "\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["add", "list", "ingest", "all"])
    parser.add_argument("--url", help="GitHub URL (for `add`)")
    parser.add_argument("--note", default="", help="why this repo is worth having")
    parser.add_argument("--only", help="ingest just this slug")
    args = parser.parse_args()

    CACHE.mkdir(parents=True, exist_ok=True)

    if args.command == "add":
        if not args.url:
            raise SystemExit("add needs --url")
        add_source(args.url, args.note)
        return 0

    rows = load_sources()
    if args.command == "list":
        if not rows:
            print("no repositories tracked yet; add one with:\n"
                  "  python3 ingest/challenge_repos.py add --url https://github.com/owner/name")
        for row in rows:
            print(f"  {row['slug']:<36} {row['repo']:<40} stars {row['stars']:<6} "
                  f"licence {row['licence']}")
        return 0

    if not rows:
        print("nothing to ingest; add a repository first")
        return 1

    reports = []
    for row in rows:
        if args.only and row["slug"] != args.only:
            continue
        try:
            reports.append(ingest_repo(row))
        except Exception as exc:  # noqa: BLE001 - one bad repo must not stop the rest
            print(f"  {row['repo']}: FAILED {exc}")
    if reports:
        save_json(CACHE / "report.json", reports)
        write_provenance(load_json(CACHE / "report.json", []))
    total = sum(r["written"] for r in reports)
    print(f"\n{total} challenge documents from {len(reports)} repositories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
