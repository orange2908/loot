#!/usr/bin/env python3
"""Vendor upstream CTF attack scripts into CTF-Brain, with licences intact.

    python3 ingest/vendor_scripts.py all
    python3 ingest/vendor_scripts.py clone      # shallow-clone the sources
    python3 ingest/vendor_scripts.py vendor     # copy curated files into vendor/
    python3 ingest/vendor_scripts.py wrap       # emit content/scripts/**/vendor-*.md

Only repositories with a clear, permissive licence are copied.  Anything without
one gets a pointer page instead: attribution and a link, no copied code.
Every vendored tree keeps its upstream LICENSE, and vendor/PROVENANCE.md records
repo, commit SHA, licence and what was taken.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    CONTENT, RAW, categorise, mine_tags, pick_subcategory, save_json, slugify, write_doc,
)

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor"
SRC = RAW / "vendor-src"

MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", ".github", "node_modules", "__pycache__", ".idea", "venv", ".venv",
             "test", "tests", "docs", "images", "img", "assets", ".pytest_cache"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip", ".tar",
                 ".gz", ".xz", ".bz2", ".so", ".o", ".a", ".bin", ".exe", ".dll", ".jar",
                 ".mp4", ".webm", ".woff", ".woff2", ".ttf", ".pyc"}

# --------------------------------------------------------------------- sources
# `take`: directories to copy.  `wrap`: glob(s) to turn into knowledge-base pages.
SOURCES: list[dict] = [
    {
        "repo": "jvdsn/crypto-attacks",
        "name": "crypto-attacks",
        "licence": "MIT",
        "about": "Python implementations of a large catalogue of cryptographic attacks.",
        "author": "Joachim Vandersmissen (jvdsn)",
        "take": ["attacks", "shared", "README.md", "LICENSE"],
        "wrap": ["attacks/**/*.py"],
        "category": "crypto",
        "max_wrap": 90,
    },
    {
        "repo": "shellphish/how2heap",
        "name": "how2heap",
        "licence": "MIT",
        "about": "Working demonstrations of every major glibc heap exploitation technique.",
        "author": "Shellphish",
        "take": ["glibc_2.39", "glibc_2.38", "glibc_2.36", "glibc_2.35", "glibc_2.34",
                 "glibc_2.31", "glibc_2.27", "glibc_2.26", "glibc_2.23", "README.md", "LICENSE"],
        "wrap": ["glibc_2.39/*.c", "glibc_2.35/*.c", "glibc_2.31/*.c", "glibc_2.27/*.c",
                 "glibc_2.23/*.c"],
        "category": "pwn",
        "max_wrap": 70,
    },
    {
        "repo": "RsaCtfTool/RsaCtfTool",
        "name": "RsaCtfTool",
        "licence": "MIT",
        "about": "The standard automated RSA attack tool; its attack modules are readable recipes.",
        "author": "RsaCtfTool contributors",
        "take": ["src/RsaCtfTool/attacks", "src/RsaCtfTool/lib", "src/RsaCtfTool/sage",
                 "README.md", "LICENSE.txt"],
        "wrap": ["src/RsaCtfTool/attacks/single_key/*.py",
                 "src/RsaCtfTool/attacks/multi_keys/*.py"],
        "category": "crypto",
        "max_wrap": 45,
    },
    {
        "repo": "ljagiello/ctf-skills",
        "name": "ctf-skills",
        "licence": "MIT",
        "about": "A large, well-organised collection of CTF technique notes by category.",
        "author": "ljagiello",
        "take": ["ctf-ai-ml", "ctf-crypto", "ctf-forensics", "ctf-misc", "ctf-osint",
                 "ctf-pwn", "ctf-reverse", "ctf-web", "ctf-blockchain", "ctf-mobile",
                 "ctf-hardware", "ctf-cloud", "ctf-stego", "README.md", "LICENSE"],
        "wrap": ["ctf-*/*.md"],
        "category": None,          # derived per file from the directory name
        "wrap_type": "reference",
        "max_wrap": 120,
    },
    {
        "repo": "GTFOBins/GTFOBins.github.io",
        "name": "GTFOBins",
        "licence": "GPL-3.0",
        "about": "Unix binaries that can be abused to break out of restricted shells and escalate.",
        "author": "GTFOBins contributors",
        "take": ["_gtfobins", "LICENSE", "README.md"],
        "wrap": [],                # handled by a dedicated builder below
        "category": "misc",
    },
]

# No licence file upstream: link and attribute, never copy.
POINTER_ONLY: list[dict] = [
    {
        "repo": "defund/coppersmith",
        "name": "defund/coppersmith",
        "category": "crypto",
        "about": "Coppersmith's method for multivariate polynomials in SageMath - the standard "
                 "drop-in `small_roots` used across CTF crypto.",
        "why": "No licence file upstream, so nothing is copied here. Clone it yourself when you "
               "need it; it is a single `coppersmith.sage` you place next to your solver.",
        "tags": ["coppersmith", "small-roots", "lattice", "lll", "sage", "sagemath", "rsa",
                 "multivariate", "polynomial", "stereotyped-message", "partial-p"],
    },
    {
        "repo": "interference-security/frida-scripts",
        "name": "interference-security/frida-scripts",
        "category": "mobile",
        "about": "A collection of Frida instrumentation scripts for Android and iOS.",
        "why": "No licence file upstream, so nothing is copied here. See "
               "content/scripts/mobile/frida-script-library.md for locally-authored equivalents.",
        "tags": ["frida", "hooking", "android", "ios", "instrumentation", "ssl-pinning",
                 "root-detection", "runtime", "objection"],
    },
]

CATEGORY_FROM_SKILL_DIR = {
    "ctf-crypto": "crypto", "ctf-web": "web", "ctf-pwn": "pwn", "ctf-reverse": "rev",
    "ctf-forensics": "forensics", "ctf-stego": "stego", "ctf-misc": "misc",
    "ctf-osint": "osint", "ctf-mobile": "mobile", "ctf-hardware": "hardware",
    "ctf-blockchain": "blockchain", "ctf-cloud": "cloud", "ctf-ai-ml": "misc",
}


def run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600)
    return proc.returncode, (proc.stdout + proc.stderr)


# ----------------------------------------------------------------------- clone
def clone() -> dict[str, str]:
    SRC.mkdir(parents=True, exist_ok=True)
    shas: dict[str, str] = {}
    for source in SOURCES:
        dest = SRC / source["name"]
        if dest.exists():
            print(f"  {source['repo']}: already cloned")
        else:
            print(f"  {source['repo']}: cloning...")
            code, out = run(["git", "clone", "--depth", "1", "--quiet",
                             f"https://github.com/{source['repo']}.git", str(dest)])
            if code != 0:
                print(f"    FAILED: {out.strip()[:200]}")
                continue
        code, sha = run(["git", "rev-parse", "HEAD"], cwd=dest)
        shas[source["name"]] = sha.strip()[:12] if code == 0 else "unknown"
    save_json(SRC / "shas.json", shas)
    return shas


# ---------------------------------------------------------------------- vendor
def _copy_tree(src: Path, dst: Path) -> tuple[int, int]:
    files = size = 0
    for item in src.rglob("*"):
        if item.is_dir() or any(p in SKIP_DIRS for p in item.parts):
            continue
        if item.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            if item.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        target = dst / item.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target)
        files += 1
        size += target.stat().st_size
    return files, size


def vendor() -> list[dict]:
    VENDOR.mkdir(parents=True, exist_ok=True)
    shas = {}
    try:
        import json
        shas = json.loads((SRC / "shas.json").read_text())
    except Exception:                                    # noqa: BLE001
        pass

    rows: list[dict] = []
    for source in SOURCES:
        src_root = SRC / source["name"]
        if not src_root.exists():
            print(f"  {source['repo']}: not cloned, skipping")
            continue
        dst_root = VENDOR / source["name"]
        if dst_root.exists():
            shutil.rmtree(dst_root)
        dst_root.mkdir(parents=True)

        files = size = 0
        for entry in source["take"]:
            src_path = src_root / entry
            if not src_path.exists():
                continue
            if src_path.is_dir():
                f, s = _copy_tree(src_path, dst_root / entry)
            else:
                shutil.copy2(src_path, dst_root / src_path.name)
                f, s = 1, src_path.stat().st_size
            files += f
            size += s

        licence_file = next((p for p in dst_root.glob("LICENSE*")), None)
        if licence_file is None:
            # The licence must travel with the code; go and find it.
            for candidate in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"):
                if (src_root / candidate).exists():
                    shutil.copy2(src_root / candidate, dst_root / "LICENSE")
                    licence_file = dst_root / "LICENSE"
                    break

        rows.append({
            "repo": source["repo"], "name": source["name"],
            "url": f"https://github.com/{source['repo']}",
            "sha": shas.get(source["name"], "unknown"),
            "licence": source["licence"],
            "licence_file": bool(licence_file),
            "files": files, "bytes": size,
            "took": ", ".join(source["take"]),
        })
        print(f"  {source['repo']:<38} {files:>5} files  {size/1e6:.1f} MB  "
              f"licence={'yes' if licence_file else 'MISSING'}")

    write_provenance(rows)
    return rows


def write_provenance(rows: list[dict]) -> None:
    lines = [
        "# Vendored source provenance",
        "",
        "Everything under `vendor/` belongs to its original authors and is redistributed",
        "here under the licence shown, with the upstream `LICENSE` file preserved alongside it.",
        "Nothing has been relicensed, and no copyright headers were removed.",
        "",
        "| Repository | Commit | Licence | Files | Size | What was taken |",
        "|---|---|---|---|---|---|",
    ]
    for row in sorted(rows, key=lambda r: r["name"].lower()):
        lines.append(
            f"| [{row['repo']}]({row['url']}) | `{row['sha']}` | {row['licence']} | "
            f"{row['files']} | {row['bytes']/1e6:.1f} MB | {row['took']} |")
    lines += [
        "",
        "## Not vendored (no upstream licence)",
        "",
        "These are referenced by link and attribution only - no code is copied:",
        "",
    ]
    for pointer in POINTER_ONLY:
        lines.append(f"- [{pointer['repo']}](https://github.com/{pointer['repo']}) - {pointer['about']}")
    lines += [
        "",
        "## Removing something",
        "",
        "If you are an author and want your work out of this mirror, delete the directory under",
        "`vendor/` and the matching `content/scripts/**/vendor-*.md` wrappers, then re-run",
        "`ctfbrain index`.",
        "",
    ]
    (VENDOR / "PROVENANCE.md").write_text("\n".join(lines), encoding="utf-8")


# ------------------------------------------------------------------------ wrap
def _docstring(text: str) -> str:
    match = re.search(r'^\s*(?:"""|\'\'\')(.*?)(?:"""|\'\'\')', text, re.DOTALL)
    if match:
        return " ".join(match.group(1).split())[:400]
    comments = []
    for line in text.splitlines()[:40]:
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "/*")) and len(stripped) > 4:
            comments.append(stripped.lstrip("#/*").strip())
        elif comments:
            break
    return " ".join(comments)[:400]


def _code_lang(path: Path) -> str:
    return {".py": "python", ".c": "c", ".cpp": "cpp", ".sh": "bash", ".js": "javascript",
            ".sage": "python", ".rb": "ruby", ".go": "go"}.get(path.suffix.lower(), "text")


def wrap_code_file(source: dict, path: Path, rel: Path, sha: str) -> Path | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if len(text.strip()) < 200:
        return None

    stem = path.stem
    if stem.startswith("__") or stem in ("setup", "conftest"):
        return None

    doc = _docstring(text)
    family = rel.parts[1] if len(rel.parts) > 1 else ""
    pretty = stem.replace("_", " ").replace("-", " ").strip()
    permalink = f"https://github.com/{source['repo']}/blob/{sha}/{rel.as_posix()}"

    category = source["category"] or categorise(pretty, family, doc, text[:4000])
    tags = mine_tags(pretty, family, doc, text[:8000],
                     extra=[source["name"].lower(), family.lower().replace("_", "-")])
    for extra in (slugify(stem), category):
        if extra and extra not in tags:
            tags.append(extra)

    lang = _code_lang(path)
    lines = text.splitlines()
    truncated = len(lines) > 400
    body_code = "\n".join(lines[:400]) if truncated else text

    body = [
        "## What it does", "",
        doc or f"`{rel.as_posix()}` from {source['repo']}: {source['about']}", "",
        "## Where it lives", "",
        f"- Vendored locally at `vendor/{source['name']}/{rel.as_posix()}`",
        f"- Upstream: <{permalink}>", "",
        "## Usage", "",
        "```bash",
        f"# read or run it straight from the vendored copy",
        f"$EDITOR vendor/{source['name']}/{rel.as_posix()}",
    ]
    if lang == "python":
        body.append(f"python3 vendor/{source['name']}/{rel.as_posix()}")
    elif lang == "c":
        body.append(f"gcc -g -o /tmp/{stem} vendor/{source['name']}/{rel.as_posix()} && /tmp/{stem}")
    body += ["```", "", "## Code", "", f"```{lang}", body_code, "```", ""]
    if truncated:
        body.append(f"*Truncated at 400 of {len(lines)} lines - the full file is in "
                    f"`vendor/{source['name']}/{rel.as_posix()}`.*\n")
    body += [
        "## Attribution", "",
        f"- **Author:** {source['author']}",
        f"- **Repository:** <https://github.com/{source['repo']}> (commit `{sha}`)",
        f"- **Licence:** {source['licence']} - see `vendor/{source['name']}/LICENSE`",
        "",
        "This file is a wrapper for search and reference. The code is the original authors' work, "
        "redistributed unmodified under its own licence.",
        "",
    ]

    out = CONTENT / "scripts" / category / f"vendor-{slugify(source['name'], 24)}-{slugify(stem, 40)}.md"
    write_doc(out, {
        "title": f"{pretty.title()} ({source['name']})",
        "category": category,
        "subcategory": pick_subcategory(tags, slugify(family) if family else ""),
        "type": source.get("wrap_type", "script"),
        "tags": tags[:20],
        "summary": (doc[:200] if doc else f"{pretty} - vendored from {source['repo']}."),
        "tools": [source["name"]],
        "source": {"name": source["repo"], "url": permalink},
        "license": source["licence"],
    }, "\n".join(body))
    return out


def wrap_markdown_file(source: dict, path: Path, rel: Path, sha: str) -> Path | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text.strip()) < 400:
        return None
    body = re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.DOTALL)   # drop upstream frontmatter

    top_dir = rel.parts[0] if rel.parts else ""
    category = CATEGORY_FROM_SKILL_DIR.get(top_dir) or categorise(rel.as_posix(), body[:6000])
    title_match = re.search(r"^#\s+(.+)$", body, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else path.stem.replace("-", " ").title()
    permalink = f"https://github.com/{source['repo']}/blob/{sha}/{rel.as_posix()}"
    tags = mine_tags(title, rel.as_posix(), body[:12000], extra=[source["name"].lower()])
    if category not in tags:
        tags.append(category)

    lines = body.splitlines()
    if len(lines) > 1200:
        body = "\n".join(lines[:1200]) + f"\n\n---\n\n*Truncated. Full page: <{permalink}>*\n"

    out = CONTENT / "reference" / f"vendor-{slugify(source['name'], 20)}-{slugify(path.stem, 40)}.md"
    write_doc(out, {
        "title": f"{title} ({source['name']})",
        "category": category,
        "subcategory": slugify(top_dir.replace("ctf-", "")) if top_dir else "",
        "type": "reference",
        "tags": tags[:20],
        "summary": f"{title} - from the {source['name']} collection.",
        "source": {"name": source["repo"], "url": permalink},
        "license": source["licence"],
    }, body.strip() + f"\n\n---\n\n## Source\n\n{source['author']}, "
                      f"<{permalink}> ({source['licence']}).\n")
    return out


FUNCTION_MEANING = {
    "shell": "spawns an interactive shell",
    "command": "runs a single command",
    "reverse-shell": "connects back to a listener you control",
    "bind-shell": "listens for an inbound connection",
    "file-upload": "sends a local file out",
    "file-download": "pulls a remote file in",
    "file-write": "writes to an arbitrary file",
    "file-read": "reads an arbitrary file",
    "library-load": "loads an arbitrary shared library",
    "suid": "abusable when the setuid bit is set",
    "sudo": "abusable via a sudo rule",
    "capabilities": "abusable via file capabilities",
    "limited-suid": "setuid abuse, with constraints",
    "non-interactive-shell": "non-interactive shell only",
    "non-interactive-reverse-shell": "non-interactive reverse shell",
}

# The functions worth a dedicated payload page, in the order you reach for them.
PAYLOAD_PAGES = ["shell", "sudo", "suid", "file-read", "file-write", "command",
                 "reverse-shell", "library-load", "capabilities"]

# Shared across every GTFOBins page. The page-specific term (the context or the
# function) is appended per page, so a query for "sudo" ranks the sudo page first
# instead of tying with every other GTFOBins page.
GTFO_TAGS = ["gtfobins", "privilege-escalation", "privesc", "shell-escape",
             "restricted-shell", "linux", "post-exploitation", "binary-abuse",
             "lolbins", "living-off-the-land"]


def _parse_gtfobins(data_dir: Path) -> list[dict]:
    """Each entry is a YAML document named after the binary, with no file extension."""
    import yaml
    entries: list[dict] = []
    for path in sorted(data_dir.iterdir()):
        if path.is_dir() or path.name.startswith("."):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            body = re.sub(r"\A---\n", "", text)
            body = re.sub(r"\n---\s*\Z", "", body)
            data = yaml.safe_load(body)
        except Exception:                                # noqa: BLE001
            continue
        if not isinstance(data, dict):
            continue
        functions = data.get("functions") or {}
        if not isinstance(functions, dict) or not functions:
            continue
        entries.append({"name": path.name, "functions": functions})
    return entries


def _entry_snippets(functions: dict, function: str) -> list[dict]:
    out: list[dict] = []
    for item in (functions.get(function) or []):
        if not isinstance(item, dict):
            continue
        code = (item.get("code") or "").strip()
        if not code:
            continue
        contexts = item.get("contexts")
        ctx: list[str] = []
        if isinstance(contexts, dict):
            for name, override in contexts.items():
                if isinstance(override, dict) and (override.get("code") or "").strip():
                    ctx.append(f"{name} (variant below)")
                    out.append({"code": override["code"].strip(),
                                "comment": f"{function} - {name} variant",
                                "contexts": [name]})
                else:
                    ctx.append(str(name))
        out.append({"code": code,
                    "comment": (item.get("comment") or "").strip(),
                    "contexts": ctx})
    return out


def build_gtfobins(source: dict, sha: str) -> int:
    """Fold the GTFOBins dataset into an index plus one payload page per function."""
    data_dir = VENDOR / source["name"] / "_gtfobins"
    if not data_dir.exists():
        print("    GTFOBins: _gtfobins not vendored")
        return 0
    entries = _parse_gtfobins(data_dir)
    if not entries:
        print("    GTFOBins: parsed 0 entries")
        return 0

    base_source = {"name": "GTFOBins/GTFOBins.github.io",
                   "url": "https://github.com/GTFOBins/GTFOBins.github.io"}
    all_functions = sorted({f for e in entries for f in e["functions"]})
    written = 0

    # ---- index page
    body = [
        "## What this is", "",
        f"All {len(entries)} GTFOBins binaries and the abuse functions each one supports, as a "
        "single searchable table. Find the binary you have, see what it can do, then open the "
        "matching payload page for the exact command.", "",
        "## How to use it", "",
        "```bash",
        "# what is setuid on this box?",
        "find / -perm -4000 -type f 2>/dev/null",
        "# what may I run with sudo?",
        "sudo -l",
        "# what has capabilities?",
        "getcap -r / 2>/dev/null",
        "# then look the binary up below",
        "```", "",
        "## Payload pages", "",
    ]
    for function in PAYLOAD_PAGES:
        if function in all_functions:
            body.append(f"- **{function}** - {FUNCTION_MEANING.get(function, '')} - "
                        f"`ctfbrain show reference:vendor-gtfobins-{function}`")
    body += ["", "## Function meanings", ""]
    for function in all_functions:
        body.append(f"- `{function}` - {FUNCTION_MEANING.get(function, 'see the upstream entry')}")
    body += ["", "## Every binary", "", "| Binary | Functions |", "|---|---|"]
    for entry in entries:
        functions = ", ".join(f"`{f}`" for f in sorted(entry["functions"]))
        body.append(f"| [`{entry['name']}`](https://gtfobins.github.io/gtfobins/{entry['name']}/) "
                    f"| {functions} |")
    body += ["", "## Attribution", "",
             f"Data from [GTFOBins](https://gtfobins.github.io/) (commit `{sha}`), licensed "
             f"{source['licence']}. Vendored at `vendor/{source['name']}/_gtfobins/`.", ""]

    write_doc(CONTENT / "reference" / "vendor-gtfobins-index.md", {
        "title": "GTFOBins - Complete Binary and Function Index",
        "category": "misc", "subcategory": "privilege-escalation", "type": "reference",
        "tags": GTFO_TAGS + ["index", "binary-index", "suid", "sudo", "capabilities"],
        "summary": f"All {len(entries)} GTFOBins binaries and which abuse functions each supports.",
        "source": base_source, "license": source["licence"],
    }, "\n".join(body))
    written += 1

    # ---- one payload page per function
    for function in PAYLOAD_PAGES:
        rows = [(e["name"], _entry_snippets(e["functions"], function))
                for e in entries if function in e["functions"]]
        rows = [(name, snips) for name, snips in rows if snips]
        if not rows:
            continue
        meaning = FUNCTION_MEANING.get(function, "")
        page = [
            "## What this page is", "",
            f"Every GTFOBins binary whose `{function}` function {meaning}, with the exact command. "
            f"{len(rows)} binaries.", "",
            "## Finding your way in", "",
            "```bash",
            "# intersect what is available with what is on this page",
            "sudo -l" if function == "sudo" else "find / -perm -4000 -type f 2>/dev/null",
            "```", "",
            f"## {function} payloads", "",
        ]
        for name, snips in rows:
            page.append(f"### {name}")
            page.append("")
            for snip in snips:
                if snip["comment"]:
                    page.append(f"{snip['comment']}")
                    page.append("")
                if snip["contexts"]:
                    page.append(f"*Contexts: {', '.join(snip['contexts'])}*")
                    page.append("")
                page += ["```bash", snip["code"], "```", ""]
        page += ["## Attribution", "",
                 f"Data from [GTFOBins](https://gtfobins.github.io/) (commit `{sha}`), licensed "
                 f"{source['licence']}. Vendored at `vendor/{source['name']}/_gtfobins/`.", ""]

        write_doc(CONTENT / "reference" / f"vendor-gtfobins-{function}.md", {
            "title": f"GTFOBins - {function} ({len(rows)} binaries)",
            "category": "misc", "subcategory": "privilege-escalation", "type": "reference",
            "tags": GTFO_TAGS + [function, function.replace("-", "")],
            "summary": f"{len(rows)} Unix binaries whose {function} function {meaning}.",
            "source": base_source, "license": source["licence"],
        }, "\n".join(page))
        written += 1

    # ---- one page per privilege CONTEXT (sudo / suid / capabilities)
    # This is how you actually reach for GTFOBins: "sudo -l says I can run tar, now what".
    contexts_wanted = ["sudo", "suid", "capabilities", "limited-suid"]
    for context in contexts_wanted:
        rows: list[tuple[str, list[dict]]] = []
        for entry in entries:
            snips: list[dict] = []
            for function, items in entry["functions"].items():
                for item in (items or []):
                    if not isinstance(item, dict):
                        continue
                    ctxs = item.get("contexts")
                    if not isinstance(ctxs, dict) or context not in ctxs:
                        continue
                    override = ctxs.get(context)
                    code = ((override or {}).get("code") if isinstance(override, dict) else None) \
                        or (item.get("code") or "")
                    code = code.strip()
                    if code:
                        snips.append({"function": function, "code": code,
                                      "comment": (item.get("comment") or "").strip()})
            if snips:
                rows.append((entry["name"], snips))
        if not rows:
            continue

        how = {
            "sudo": "sudo -l",
            "suid": "find / -perm -4000 -type f 2>/dev/null",
            "limited-suid": "find / -perm -4000 -type f 2>/dev/null",
            "capabilities": "getcap -r / 2>/dev/null",
        }[context]
        page = [
            "## What this page is", "",
            f"Every GTFOBins binary that is abusable in the **{context}** context, grouped by "
            f"binary, with the function each payload provides. {len(rows)} binaries.", "",
            "## Step 1: find out what you have", "",
            "```bash", how, "```", "",
            "## Step 2: look it up", "",
        ]
        for name, snips in rows:
            page += [f"### {name}", ""]
            for snip in snips:
                label = FUNCTION_MEANING.get(snip["function"], snip["function"])
                page.append(f"**{snip['function']}** - {label}")
                page.append("")
                if snip["comment"]:
                    page += [snip["comment"], ""]
                page += ["```bash", snip["code"], "```", ""]
        page += ["## Attribution", "",
                 f"Data from [GTFOBins](https://gtfobins.github.io/) (commit `{sha}`), licensed "
                 f"{source['licence']}. Vendored at `vendor/{source['name']}/_gtfobins/`.", ""]

        write_doc(CONTENT / "reference" / f"vendor-gtfobins-context-{context}.md", {
            "title": f"GTFOBins - {context} context ({len(rows)} binaries)",
            "category": "misc", "subcategory": "privilege-escalation", "type": "reference",
            "tags": GTFO_TAGS + [context, context.replace("-", ""), "escalation-path"],
            "summary": f"{len(rows)} Unix binaries abusable in the {context} context, with the "
                       "payload and the primitive each one yields.",
            "source": base_source, "license": source["licence"],
        }, "\n".join(page))
        written += 1

    print(f"    GTFOBins: {len(entries)} binaries -> {written} pages")
    return written


def write_pointers() -> int:
    written = 0
    for pointer in POINTER_ONLY:
        out = CONTENT / "reference" / f"vendor-pointer-{slugify(pointer['name'], 40)}.md"
        body = (
            f"## What it is\n\n{pointer['about']}\n\n"
            f"## Why there is no copy here\n\n{pointer['why']}\n\n"
            f"## Get it\n\n```bash\ngit clone --depth 1 https://github.com/{pointer['repo']}.git\n```\n\n"
            f"## Attribution\n\nUpstream: <https://github.com/{pointer['repo']}>. "
            "All rights remain with the original authors.\n"
        )
        write_doc(out, {
            "title": f"{pointer['name']} (external reference)",
            "category": pointer["category"],
            "subcategory": "external-tool",
            "type": "reference",
            "tags": pointer["tags"],
            "summary": pointer["about"][:200],
            "source": {"name": pointer["repo"], "url": f"https://github.com/{pointer['repo']}"},
        }, body)
        written += 1
    return written


def wrap() -> dict:
    import json
    try:
        shas = json.loads((SRC / "shas.json").read_text())
    except Exception:                                    # noqa: BLE001
        shas = {}

    counts: dict[str, int] = {}
    for source in SOURCES:
        root = VENDOR / source["name"]
        if not root.exists():
            continue
        sha = shas.get(source["name"], "HEAD")
        made = 0
        for pattern in source.get("wrap", []):
            for path in sorted(root.glob(pattern)):
                if made >= source.get("max_wrap", 60):
                    break
                rel = path.relative_to(root)
                try:
                    out = (wrap_markdown_file(source, path, rel, sha) if path.suffix == ".md"
                           else wrap_code_file(source, path, rel, sha))
                except Exception as exc:                 # noqa: BLE001
                    print(f"    wrap failed {rel}: {exc}")
                    continue
                if out:
                    made += 1
        if source["name"] == "GTFOBins":
            made += build_gtfobins(source, sha)
        counts[source["name"]] = made
        print(f"  {source['name']:<20} {made} wrapper pages")

    counts["pointers"] = write_pointers()
    save_json(RAW / "vendor-src" / "wrap-report.json", counts)
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["clone", "vendor", "wrap", "all"])
    args = parser.parse_args()
    if args.command in ("clone", "all"):
        print("cloning sources..."); clone()
    if args.command in ("vendor", "all"):
        print("vendoring files..."); vendor()
    if args.command in ("wrap", "all"):
        print("writing wrapper pages..."); wrap()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
