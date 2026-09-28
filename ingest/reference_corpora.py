#!/usr/bin/env python3
"""Mirror the open CTF *reference* corpora into CTF-Brain, offline and searchable.

    python3 ingest/reference_corpora.py all
    python3 ingest/reference_corpora.py verify     # gh repo view every source
    python3 ingest/reference_corpora.py clone      # shallow clone into data/raw/corpora/src
    python3 ingest/reference_corpora.py render     # emit content/**/ext-*.md
    python3 ingest/reference_corpora.py provenance # rewrite the provenance table

This pipeline handles whole reference books (CTF Wiki, HackTricks, OWASP WSTG,
PayloadsAllTheThings, ...), not competition writeups -- `ingest/ctftime.py` and
`ingest/github_writeups.py` own those.

Everything is resumable: clones are reused, the per-page render state lives in
data/raw/corpora/state.json, and a page that blows up is recorded and skipped so
one bad file can never abort a run.

SAFETY: mirrored text is DATA.  Every page goes through `ctftime.looks_like_bait`
before it is written, and nothing inside a mirrored document is ever executed or
obeyed.  Pages that carry scraper bait are dropped and counted, never rendered.
"""
from __future__ import annotations

import argparse
import posixpath
import re
import subprocess
import sys
import traceback
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    CONTENT, RAW, categorise, first_sentence, load_json, mine_tags,
    pick_subcategory, save_json, slugify, truncate, write_doc,
)
from ctftime import looks_like_bait  # noqa: E402  - reuse the one bait filter

CORPORA_RAW = RAW / "corpora"
SRC = CORPORA_RAW / "src"
STATE_JSON = CORPORA_RAW / "state.json"
REPORT_JSON = CORPORA_RAW / "report.json"
PROVENANCE = CONTENT / "reference" / "ext-CORPORA-PROVENANCE.md"

MAX_BODY_LINES = 1500
MIN_CONTENT_LINES = 20
MIN_CONTENT_CHARS = 1200
PREFIX = "ext-"

# Pages dropped by the bait filter, recorded so the provenance page can name them.
BAIT_LOG: list[dict] = []

BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
                   ".pdf", ".zip", ".gz", ".tar", ".bin", ".exe", ".mp4", ".webm",
                   ".woff", ".woff2", ".ttf", ".jar", ".so", ".elf", ".apk", ".txt",
                   ".py", ".c", ".sh", ".js", ".json", ".yml", ".yaml", ".rb", ".go"}


# ===========================================================================
# Corpora
# ===========================================================================
# `licence` is copied verbatim from the LICENSE file actually present in the
# repository at the pinned commit -- never from the GitHub API's guess, which
# reports NOASSERTION for several of these.
CORPORA: list[dict] = [
    {
        "key": "ctf-wiki",
        "name": "CTF Wiki",
        "repo": "ctf-wiki/ctf-wiki",
        "url": "https://github.com/ctf-wiki/ctf-wiki",
        "licence": "CC BY-NC-SA 4.0",
        "licence_note": (
            "LICENSE at the repository root is the full text of "
            "'Attribution-NonCommercial-ShareAlike 4.0 International'. The GitHub API "
            "reports NOASSERTION; the file itself is unambiguous CC BY-NC-SA 4.0."),
        "licence_path": "LICENSE",
        "about": "The community CTF wiki: crypto, pwn, reverse, misc, web, android, blockchain.",
        # English first; a Chinese page is only taken when no English page exists
        # at the same relative path (see `collect_ctf_wiki`).
        "roots": ["docs/en/docs", "docs/zh/docs"],
        "took": "docs/en/docs (all English pages) + docs/zh/docs where no English page exists",
    },
    {
        "key": "hacktricks",
        "name": "HackTricks",
        "repo": "HackTricks-wiki/hacktricks",
        "url": "https://github.com/HackTricks-wiki/hacktricks",
        "licence": "CC BY-NC 4.0",
        "licence_note": (
            "src/LICENSE.md is the full text of 'Attribution-NonCommercial 4.0 "
            "International', Copyright (C) Carlos Polop 2021. The GitHub API reports no "
            "licence because the file is not at the repository root. "
            "carlospolop/hacktricks now redirects to HackTricks-wiki/hacktricks, which is "
            "the current canonical repo."),
        "licence_path": "src/LICENSE.md",
        "about": "The largest practical offensive-security book; the CTF-relevant chapters.",
        "roots": ["src"],
        "include": [
            "src/pentesting-web", "src/binary-exploitation", "src/crypto", "src/stego",
            "src/reversing", "src/blockchain", "src/mobile-pentesting",
            "src/hardware-physical-access", "src/generic-methodologies-and-resources",
            "src/generic-hacking",
        ],
        "took": ("src/{pentesting-web, binary-exploitation, crypto, stego, reversing, "
                 "blockchain, mobile-pentesting, hardware-physical-access, "
                 "generic-methodologies-and-resources (incl. basic-forensic-methodology), "
                 "generic-hacking}"),
    },
    {
        "key": "payloads",
        "name": "PayloadsAllTheThings",
        "repo": "swisskyrepo/PayloadsAllTheThings",
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
        "licence": "MIT",
        "licence_note": "LICENSE is the MIT licence, Copyright (c) 2019 Swissky.",
        "licence_path": "LICENSE",
        "about": "Per-vulnerability payload and bypass collections for web and pentest.",
        "roots": ["."],
        "include_glob": ["*/README.md", "Methodology and Resources/*.md",
                         "*/Intruder/*.md", "*/Files/*.md"],
        "exclude_parts": {"_template_vuln", "_LEARNING_AND_SOCIALS", ".github"},
        "took": ("every per-vulnerability README.md. 'Methodology and Resources/*.md' is "
                 "collected too but is almost all pointer stubs upstream now -- that "
                 "content moved to swisskyrepo/InternalAllTheThings, which has no licence "
                 "and is not mirrored"),
    },
    {
        "key": "wstg",
        "name": "OWASP WSTG",
        "repo": "OWASP/wstg",
        "url": "https://github.com/OWASP/wstg",
        "licence": "CC BY-SA 4.0",
        "licence_note": "LICENSE is the full text of Creative Commons Attribution-ShareAlike 4.0 International.",
        "licence_path": "LICENSE",
        "about": "The OWASP Web Security Testing Guide: one page per numbered web test.",
        "roots": ["document/4-Web_Application_Security_Testing"],
        "took": "document/4-Web_Application_Security_Testing/**/*.md (the test pages)",
    },
    {
        "key": "tob-field-guide",
        "name": "Trail of Bits CTF Field Guide",
        "repo": "trailofbits/ctf",
        "url": "https://github.com/trailofbits/ctf",
        "licence": "CC BY-SA 4.0",
        "licence_note": "LICENSE is the full text of Creative Commons Attribution-ShareAlike 4.0 International.",
        "licence_path": "LICENSE",
        "about": "Trail of Bits' CTF Field Guide: how to actually play, by category.",
        "roots": ["."],
        "exclude_parts": {"theme", ".github"},
        "took": "the whole field guide (intro, vulnerabilities, exploits, web, forensics, toolkits, tradecraft)",
    },
    {
        "key": "ctfs-resources",
        "name": "ctfs/resources",
        "repo": "ctfs/resources",
        "url": "https://github.com/ctfs/resources",
        "licence": "CC0 1.0",
        "licence_note": "LICENSE is the full text of the CC0 1.0 Universal public-domain dedication.",
        "licence_path": "LICENSE",
        "about": "The ctfs.github.io resource collection: per-topic and per-tool notes.",
        "roots": ["."],
        "exclude_parts": {".github"},
        "took": "topics/**/*.md and tools/**/*.md",
    },
    {
        "key": "awesome-ctf",
        "name": "Awesome CTF",
        "repo": "apsdehal/awesome-ctf",
        "url": "https://github.com/apsdehal/awesome-ctf",
        "licence": "CC0 1.0",
        "licence_note": "LICENSE is the full text of the CC0 1.0 Universal public-domain dedication.",
        "licence_path": "LICENSE",
        "about": "The canonical curated index of CTF tools, split into one page per section.",
        "roots": [],                    # handled by the dedicated awesome-list builder
        "awesome_list": "README.md",
        "took": "README.md, exploded into one reference page per tool-list section",
    },
]

CORPUS_BY_KEY = {c["key"]: c for c in CORPORA}

# Verified to exist, deliberately NOT mirrored: no licence file upstream, so there is
# no grant to redistribute the text. Linked and attributed only.
SKIPPED_ON_LICENCE: list[dict] = [
    {"repo": "swisskyrepo/InternalAllTheThings",
     "why": "No LICENSE file in the repository and no licence statement in the README. "
            "This is where PayloadsAllTheThings' 'Methodology and Resources' pages were "
            "moved to, so those pages are pointer stubs upstream and are not mirrored "
            "here either."},
    {"repo": "w181496/Web-CTF-Cheatsheet",
     "why": "No LICENSE file (the GitHub API reports NONE). An excellent web-CTF "
            "cheatsheet; clone it yourself if you want it offline."},
    {"repo": "JohnHammond/ctf-katana",
     "why": "No LICENSE file (the GitHub API reports NONE); the repository is a "
            "personal note dump with no redistribution grant."},
    {"repo": "Naetw/CTF-pwn-tips",
     "why": "No LICENSE file (the GitHub API reports NONE)."},
    {"repo": "ctf-wiki/ctf-tools",
     "why": "No LICENSE file (the GitHub API reports NONE); the tool index is covered "
            "by Awesome CTF (CC0) instead."},
]


# ===========================================================================
# Path -> category mapping (source path wins; `categorise()` is the fallback)
# ===========================================================================
# Longest matching prefix wins, so a specific subtree can override its parent.
PATH_CATEGORY: dict[str, list[tuple[str, str]]] = {
    "ctf-wiki": [
        ("crypto", "crypto"),
        ("pwn/linux/kernel-mode", "pwn"),
        ("pwn/browser", "pwn"),
        ("pwn/hardware", "hardware"),
        ("pwn/sandbox", "misc"),
        ("pwn/virtualization", "pwn"),
        ("pwn", "pwn"),
        ("reverse", "rev"),
        ("assembly", "rev"),
        ("executable", "rev"),
        ("android", "mobile"),
        ("blockchain", "blockchain"),
        ("ics", "hardware"),
        ("web", "web"),
        ("misc/traffic", "forensics"),
        ("misc/disk-memory", "forensics"),
        ("misc/archive", "misc"),
        ("misc/audio", "stego"),
        ("misc/picture", "stego"),
        ("misc/figure", "stego"),
        ("misc/encode", "crypto"),
        ("misc/recon", "osint"),
        ("misc", "misc"),
        ("ai", "misc"),
    ],
    "hacktricks": [
        ("src/pentesting-web", "web"),
        ("src/binary-exploitation", "pwn"),
        ("src/crypto/ctf-misc", "misc"),
        ("src/crypto", "crypto"),
        ("src/stego", "stego"),
        ("src/reversing", "rev"),
        ("src/blockchain", "blockchain"),
        ("src/mobile-pentesting", "mobile"),
        ("src/hardware-physical-access", "hardware"),
        ("src/generic-methodologies-and-resources/basic-forensic-methodology", "forensics"),
        ("src/generic-methodologies-and-resources/pentesting-network", "forensics"),
        ("src/generic-methodologies-and-resources/pentesting-wifi", "hardware"),
        ("src/generic-methodologies-and-resources/external-recon-methodology", "osint"),
        ("src/generic-methodologies-and-resources/python", "misc"),
        ("src/generic-methodologies-and-resources/lua", "misc"),
        ("src/generic-methodologies-and-resources/phishing-methodology", "osint"),
        ("src/generic-methodologies-and-resources", "misc"),
        ("src/generic-hacking", "misc"),
    ],
    "payloads": [
        ("Methodology and Resources/Cloud - AWS Pentest", "cloud"),
        ("Methodology and Resources/Cloud - Azure Pentest", "cloud"),
        ("Methodology and Resources/Container - Docker Pentest", "cloud"),
        ("Methodology and Resources/Container - Kubernetes Pentest", "cloud"),
        ("Methodology and Resources/Hash Cracking", "crypto"),
        ("Methodology and Resources/Network Discovery", "misc"),
        ("Methodology and Resources/Network Pivoting Techniques", "misc"),
        ("Methodology and Resources", "misc"),
        ("Insecure Randomness", "crypto"),
        ("Zip Slip", "misc"),
        ("CVE Exploits", "misc"),
        ("Denial of Service", "misc"),
        ("Dependency Confusion", "misc"),
        ("Insecure Source Code Management", "misc"),
        ("API Key Leaks", "misc"),
    ],
    "wstg": [
        ("document/4-Web_Application_Security_Testing/09-Weak_Cryptography", "crypto"),
        ("document/4-Web_Application_Security_Testing/13-WebAssembly_Testing", "rev"),
        ("document/4-Web_Application_Security_Testing", "web"),
    ],
    "tob-field-guide": [
        ("exploits", "pwn"),
        ("vulnerabilities/source", "rev"),
        ("vulnerabilities/binary", "pwn"),
        ("vulnerabilities", "pwn"),
        ("web", "web"),
        ("forensics", "forensics"),
        ("toolkits", "misc"),
        ("tradecraft", "misc"),
        ("intro", "misc"),
    ],
    "ctfs-resources": [
        ("topics/binary", "pwn"),
        ("topics/cryptography", "crypto"),
        ("topics/forensics", "forensics"),
        ("topics/steganography", "stego"),
        ("topics/web", "web"),
        ("topics/reversing", "rev"),
        ("topics", "misc"),
        ("tools", "misc"),
    ],
}

# Corpus-level default when no path prefix matches and `categorise()` is unsure.
DEFAULT_CATEGORY = {
    "payloads": "web",
    "wstg": "web",
    "hacktricks": "misc",
    "ctf-wiki": "misc",
    "tob-field-guide": "misc",
    "ctfs-resources": "misc",
    "awesome-ctf": "misc",
}

# Meta / navigation pages that carry no technique content.
SKIP_PATH_SUBSTRINGS = (
    "/contribute/", "/introduction/", "SUMMARY.md", "README-zh", "CONTRIBUTING",
    "CODE_OF_CONDUCT", "/welcome/", "banners/", "LICENSE", "/.github/",
    "missing-translation", "mkdocs", "/theme/", "/images/", "/files/",
    "document/4-Web_Application_Security_Testing/README.md",
)


# ===========================================================================
# technique promotion
# ===========================================================================
# A page is only promoted out of `reference` into `content/techniques/` when the
# source file really is one self-contained attack.  Keyed by the *stem* of the
# source path so the table stays readable and auditable.
TECHNIQUE_STEMS = {
    # PayloadsAllTheThings: every per-vulnerability README is one attack class.
    "payloads": "dir",              # use the parent directory name
    # HackTricks / CTF Wiki / WSTG: matched against the stem list below.
}

# Deliberately specific: generic words like "attack", "leak" or "testing" would sweep
# in whole chapters and survey pages, which belong in content/reference/.
ATTACK_STEM_WORDS = (
    "injection", "overflow", "traversal", "smuggling", "pollution", "deserialization",
    "xss", "csrf", "ssrf", "ssti", "xxe", "lfi", "rfi", "sqli", "-rop", "ret2",
    "use-after-free", "double-free", "off-by-one", "format-string", "padding-oracle",
    "length-extension", "common-modulus", "wiener", "coppersmith", "hastad",
    "nonce-reuse", "bit-flipping", "race-condition", "open-redirect", "clickjacking",
    "takeover", "poisoning", "hijacking", "forgery", "fixation", "clobbering",
    "house-of", "uaf", "tcache", "fastbin", "unlink", "spraying", "rebinding",
    "type-juggling", "mass-assignment", "prototype-pollution", "zip-slip",
    "downgrade", "collision", "brute-force", "tabnabbing", "xs-leak", "dos",
)

# Difficulty is an editorial call about the *class* of attack, never about a
# specific challenge.  Anything not listed defaults to "medium".
DIFFICULTY_BY_CATEGORY = {"pwn": "hard", "rev": "hard", "crypto": "medium",
                          "web": "medium", "forensics": "medium", "stego": "easy",
                          "misc": "medium", "osint": "easy", "mobile": "medium",
                          "hardware": "hard", "blockchain": "medium", "cloud": "medium"}


# ===========================================================================
# Site-generator cruft / sponsor banners -- an explicit pattern list
# ===========================================================================
# These appear on *nearly every page* of their corpus; they are navigation and
# advertising, not knowledge.  Ordered: block removals first, then line removals.
BANNER_BLOCK_PATTERNS = [
    # HackTricks mdBook banner include (the sponsor block, unexpanded in source)
    re.compile(r"\{\{#include\s+[^}]*banners/[^}]*\}\}"),
    # ...and the same banner already expanded, as it appears on the rendered site
    re.compile(r"^>\s*\[!TIP\]\s*\n(?:^>.*\n)*?^>\s*</details>\s*$", re.MULTILINE),
    re.compile(r"<details>\s*<summary>\s*Support HackTricks\s*</summary>.*?</details>",
               re.DOTALL | re.IGNORECASE),
    # HackTricks sponsor logos / ad figures
    re.compile(r"<figure\b[^>]*class=\"sponsor-logo\"[^>]*>.*?</figure>", re.DOTALL),
    re.compile(r"<figure\b[^>]*>\s*<img[^>]*(?:hacktricks-training|sponsor|logo-naxus|"
               r"lasttower|k8studio|websec|stm |cyberhelmets)[^>]*>.*?</figure>",
               re.DOTALL | re.IGNORECASE),
    # any remaining mdBook include of a file we did not mirror
    re.compile(r"\{\{#include\s+[^}]*\}\}"),
    # mkdocs-material / Jekyll nav includes
    re.compile(r"^\{%\s*include[^%]*%\}\s*$", re.MULTILINE),
    re.compile(r"^\{:\s*\.[a-z-]+\s*\}\s*$", re.MULTILINE),
    # GitBook leftovers
    re.compile(r"^\{%\s*(?:hint|endhint|tabs|endtabs|tab|endtab|content-ref|"
               r"endcontent-ref|embed|file)[^%]*%\}\s*$", re.MULTILINE),
]

BANNER_LINE_PATTERNS = [
    re.compile(r"^>?\s*Learn\s*&\s*practice\s+(?:AWS|GCP|Az|Azure)\s+Hacking", re.I),
    re.compile(r"^>?\s*Browse the \[\*\*full HackTricks Training catalog", re.I),
    re.compile(r"^>?\s*-?\s*\*?\*?Check the \[\*\*subscription plans", re.I),
    re.compile(r"^>?\s*-?\s*\*?\*?Join the\*?\*?\s*.{0,4}\s*\[\*\*Discord group", re.I),
    re.compile(r"^>?\s*-?\s*\*?\*?Share hacking tricks by submitting PRs", re.I),
    re.compile(r"^>?\s*-?\s*Support HackTricks\s*$", re.I),
    re.compile(r"^\s*<summary>\s*Support HackTricks\s*</summary>\s*$", re.I),
    re.compile(r"^\s*!\[\]\(https?://(?:cdn\.rawgit\.com|img\.shields\.io|"
               r"travis-ci\.org|repobeats\.axiom\.co)/", re.I),
    re.compile(r"^\s*\[!\[.*\]\(https?://(?:travis-ci|img\.shields)\..*\)\]\(.*\)\s*$"),
    re.compile(r"^\s*<!--\s*(?:more|nav|toc)\s*-->\s*$", re.I),
    # leftover mdBook structural markers once their content has been unwrapped
    re.compile(r"^\s*>?\s*\{\{#(?:tabs|endtabs|tab|endtab|file|endfile|ref|endref|note|"
               r"endnote|hint|endhint)\b[^}]*\}\}\s*$"),
]

# HackTricks structural macros we keep, but rewrite into plain markdown.
TAB_RE = re.compile(r"\{\{#tab\s+name=\"([^\"]*)\"\s*\}\}")
REF_BLOCK_RE = re.compile(r"\{\{#ref\s*\}\}\s*\n(.*?)\n\s*\{\{#endref\s*\}\}", re.DOTALL)
# the same macro inside a blockquote, and squeezed onto a single line inside a link
REF_QUOTED_RE = re.compile(r"^>\s*\{\{#ref\s*\}\}\s*\n((?:^>.*\n)*?)^>\s*\{\{#endref\s*\}\}[^\n]*$",
                           re.MULTILINE)
REF_INLINE_RE = re.compile(r"\{\{#ref\s*\}\}\s*([^\s{}]+)\s*\{\{#endref\s*\}\}")
FILE_BLOCK_RE = re.compile(r"\{\{#file\s*\}\}\s*\n(.*?)\n\s*\{\{#endfile\s*\}\}", re.DOTALL)
FRONTMATTER_RE = re.compile(r"\A---\s*\n.*?\n---\s*\n", re.DOTALL)
H1_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
H2_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)


# ===========================================================================
# shell helpers
# ===========================================================================
def run(cmd: list[str], cwd: Path | None = None, timeout: int = 900) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:                                    # noqa: BLE001
        return 1, f"{type(exc).__name__}: {exc}"
    return proc.returncode, (proc.stdout + proc.stderr)


def head_sha(path: Path) -> str:
    code, out = run(["git", "rev-parse", "HEAD"], cwd=path)
    return out.strip() if code == 0 else "unknown"


# ===========================================================================
# verify
# ===========================================================================
def verify() -> dict[str, bool]:
    """`gh repo view` every source before we crawl it. Never trust the list blindly."""
    ok: dict[str, bool] = {}
    for corpus in CORPORA:
        alive, out = False, ""
        for _ in range(3):                      # the GitHub API drops connections
            code, out = run(["gh", "repo", "view", corpus["repo"],
                             "--json", "nameWithOwner,isArchived,defaultBranchRef"],
                            timeout=60)
            if code == 0:
                alive = '"nameWithOwner"' in out
                break
            if "Could not resolve" in out or "404" in out:
                break                            # a real 404, not a flaky connection
        ok[corpus["key"]] = alive
        print(f"  {corpus['repo']:<40} {'OK' if alive else 'MISSING (404) - will be skipped'}")
        if not alive:
            print(f"      {out.strip()[:160]}")
    save_json(CORPORA_RAW / "verify.json", ok)
    return ok


# ===========================================================================
# clone
# ===========================================================================
def clone(only: set[str] | None = None) -> dict[str, str]:
    SRC.mkdir(parents=True, exist_ok=True)
    shas: dict[str, str] = load_json(SRC / "shas.json", {}) or {}
    for corpus in CORPORA:
        if only and corpus["key"] not in only:
            continue
        dest = SRC / corpus["key"]
        if not dest.exists():
            print(f"  {corpus['repo']}: cloning...")
            code, out = run(["git", "clone", "--depth", "1", "--quiet",
                             f"https://github.com/{corpus['repo']}.git", str(dest)])
            if code != 0:
                print(f"    FAILED: {out.strip()[:200]}")
                continue
        shas[corpus["key"]] = head_sha(dest)
        licence_path = dest / corpus["licence_path"]
        print(f"  {corpus['repo']:<40} {shas[corpus['key']][:12]}  "
              f"licence-file={'present' if licence_path.exists() else 'MISSING'}")
    save_json(SRC / "shas.json", shas)
    return shas


# ===========================================================================
# normalisation
# ===========================================================================
FENCE_SPLIT_RE = re.compile(r"(```.*?```|~~~.*?~~~)", re.DOTALL)


def _strip_chunk(text: str) -> str:
    # Keep the content of the structural macros, drop the macro syntax.
    text = REF_INLINE_RE.sub(lambda m: m.group(1).strip(), text)
    text = REF_QUOTED_RE.sub(
        lambda m: "\n".join("> " + ln.lstrip("> ").strip()
                            for ln in m.group(1).splitlines() if ln.strip(" >")), text)
    text = REF_BLOCK_RE.sub(lambda m: f"\n- <{m.group(1).strip()}>\n", text)
    text = FILE_BLOCK_RE.sub(lambda m: f"\n`{m.group(1).strip()}`\n", text)
    text = TAB_RE.sub(lambda m: f"\n**{m.group(1).strip()}**\n", text)

    for pattern in BANNER_BLOCK_PATTERNS:
        text = pattern.sub("", text)

    return "\n".join(line for line in text.splitlines()
                     if not any(p.search(line) for p in BANNER_LINE_PATTERNS))


def strip_banners(text: str) -> str:
    """Remove site-generator cruft and the repeated sponsor/support banners.

    Fenced code is left completely alone: `{{#each ...}}` inside an SSTI payload is
    the *subject* of the page, not an mdBook macro, and must survive verbatim.
    """
    text = FRONTMATTER_RE.sub("", text)
    chunks = FENCE_SPLIT_RE.split(text)
    for i, chunk in enumerate(chunks):
        if not chunk.startswith(("```", "~~~")):
            chunks[i] = _strip_chunk(chunk)
    text = "".join(chunks)

    # Collapse the holes the removals left behind.
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()


def _is_asset(target: str) -> bool:
    return Path(target.split("?")[0].split("#")[0]).suffix.lower() in BINARY_SUFFIXES


def _absolutise(target: str, repo: str, sha: str, rel_dir: str) -> str:
    """Rewrite one relative link/image target to an absolute URL on the source repo."""
    raw = target.strip()
    if not raw or raw.startswith(("http://", "https://", "//", "#", "mailto:", "data:",
                                  "javascript:", "tel:")):
        return target
    frag = ""
    if "#" in raw:
        raw, _, frag = raw.partition("#")
        frag = "#" + frag
    if not raw:
        return target
    joined = posixpath.normpath(posixpath.join(rel_dir, raw.lstrip("/")))
    if joined.startswith(".."):
        return target                       # escapes the repo; leave it alone
    encoded = quote(joined, safe="/._-~()[]%")
    host = "raw.githubusercontent.com" if _is_asset(raw) else "github.com/" + repo + "/blob"
    if host.startswith("raw"):
        return f"https://raw.githubusercontent.com/{repo}/{sha}/{encoded}{frag}"
    return f"https://github.com/{repo}/blob/{sha}/{encoded}{frag}"


# Two target shapes: a bare target, and the <angle-bracket> form, which is how
# HackTricks writes image paths that contain spaces -- `![](<../images/a (1).png>)`.
MD_LINK_RE = re.compile(
    r"(!?\[[^\]]*\])\(\s*(?:<([^>\n]*)>|([^)\s>]+))(\s+\"[^\"]*\")?\s*\)")
MD_REF_DEF_RE = re.compile(r"^(\[[^\]]+\]:\s*)(\S+)", re.MULTILINE)
HTML_ATTR_RE = re.compile(r"""(\b(?:src|href)\s*=\s*)(["'])([^"']+)\2""", re.IGNORECASE)


def rewrite_links(text: str, repo: str, sha: str, rel: str) -> str:
    rel_dir = posixpath.dirname(rel)

    def md(match: re.Match) -> str:
        target = match.group(2) if match.group(2) is not None else match.group(3)
        title = match.group(4) or ""
        return f"{match.group(1)}({_absolutise(target, repo, sha, rel_dir)}{title})"

    def ref(match: re.Match) -> str:
        return match.group(1) + _absolutise(match.group(2), repo, sha, rel_dir)

    def html(match: re.Match) -> str:
        return (match.group(1) + match.group(2)
                + _absolutise(match.group(3), repo, sha, rel_dir) + match.group(2))

    # Protect fenced code: links inside code blocks are examples, not navigation.
    chunks = re.split(r"(```.*?```|~~~.*?~~~)", text, flags=re.DOTALL)
    for i, chunk in enumerate(chunks):
        if chunk.startswith(("```", "~~~")):
            continue
        chunk = MD_LINK_RE.sub(md, chunk)
        chunk = MD_REF_DEF_RE.sub(ref, chunk)
        chunk = HTML_ATTR_RE.sub(html, chunk)
        chunks[i] = chunk
    return "".join(chunks)


NAV_LINE_RE = re.compile(r"[*+-]?\s*\d*\.?\s*\[[^\]]+\]\([^)]*\)[.,:;]?")


def is_nav_stub(text: str) -> bool:
    """True for a page that is a table of contents rather than a document.

    "Real content" is measured two ways because both shapes exist upstream: a long
    page of prose/commands, and a short-but-dense page (Trail of Bits' field-guide
    modules run to a couple of paragraphs).  A page passes on either measure, and a
    page that is almost entirely bare links is a stub whatever its length.
    """
    lines = 0
    nav = 0
    chars = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or re.fullmatch(r"[-=|\s>*_]+", line):
            continue
        lines += 1
        if NAV_LINE_RE.fullmatch(line):
            nav += 1
            continue
        chars += len(re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", line))
    if lines == 0:
        return True
    if nav / lines >= 0.85 and lines < 40:
        return True                                   # a pure table of contents
    return lines < MIN_CONTENT_LINES and chars < MIN_CONTENT_CHARS


# ===========================================================================
# metadata derivation
# ===========================================================================
def _prefix_matches(rel: str, prefix: str) -> bool:
    """True when `prefix` matches `rel` on whole path segments, anywhere in the path."""
    return rel == prefix or rel.startswith(prefix + "/") or f"/{prefix}/" in rel \
        or rel.endswith("/" + prefix)


def category_for(corpus: dict, rel: str, title: str, body: str) -> str:
    bare = rel[:-3] if rel.endswith(".md") else rel
    best, chosen = "", ""
    for prefix, category in PATH_CATEGORY.get(corpus["key"], []):
        if (_prefix_matches(rel, prefix) or _prefix_matches(bare, prefix)) \
                and len(prefix) > len(best):
            best, chosen = prefix, category
    if best:
        return chosen
    guessed = categorise(title, rel.replace("/", " "), body[:6000])
    if guessed != "misc":
        return guessed
    return DEFAULT_CATEGORY.get(corpus["key"], "misc")


# Path segments that say where a file lives in its repo, not what it is about.
PATH_NOISE = {"docs", "src", "document", "en", "zh", "zh-tw", "readme", "index",
              "web_application_security_testing", "web-application-security-testing",
              "methodology-and-resources", "generic-methodologies-and-resources",
              "pentesting-web", "binary-exploitation", "topics", "tools"}


def doc_stem(rel: str) -> str:
    """A short, stable, human-readable slug built from the tail of the source path."""
    parts: list[str] = []
    for part in Path(rel).with_suffix("").parts:
        cleaned = slugify(re.sub(r"^\d+[.\-_]+", "", part), 45)
        if not cleaned or cleaned in PATH_NOISE:
            continue
        parts.append(cleaned)
    if not parts:                                   # e.g. docs/en/docs/index.md
        parts = [slugify(Path(rel).stem, 45)]
    return slugify("-".join(parts[-3:]), 72)


# Words that make a useless tag: they appear on every page of some corpus.
TAG_NOISE = {"readme", "index", "the", "and", "for", "with", "a", "an", "of", "to", "in",
             "on", "docs", "doc", "src", "document", "en", "zh", "zh-tw", "md", "testing",
             "test", "guide", "page", "introduction", "summary", "basic", "part"}


def pad_tags(tags: list[str], rel: str, title: str, category: str,
             corpus_key: str, minimum: int = 8, limit: int = 20,
             headings: list[str] | None = None, subcategory: str = "") -> list[str]:
    """Top a tag list up to the spec's 8-20 using real signals from the document.

    `mine_tags` only fires on its known vocabulary, so a page about something the
    vocabulary does not cover comes back thin.  The path segments and title words are
    the next-best real signal -- nothing here is invented.
    """
    out = [t for t in dict.fromkeys(tags) if t][:limit]

    def add(candidate: str) -> None:
        raw = re.sub(r"^\d+[.\-_]+", "", str(candidate or "")).strip()
        if not raw:
            return
        clean = slugify(raw, 32)
        # slugify() returns "untitled" for text with no ASCII alphanumerics, which is
        # exactly what a Chinese heading gives us. That is not a tag.
        if clean in ("", "untitled") or len(clean) <= 2:
            return
        if clean not in TAG_NOISE and clean not in out:
            out.append(clean)

    if len(out) < minimum:
        for part in Path(rel).with_suffix("").parts[::-1]:
            add(part)
            for word in re.split(r"[-_\s]+", part):
                if len(out) >= minimum:
                    break
                add(word)
            if len(out) >= minimum:
                break
    if len(out) < minimum:
        for word in re.split(r"[^A-Za-z0-9+.]+", title):
            add(word)
            if len(out) >= minimum:
                break
    for heading in (headings or []):
        if len(out) >= minimum:
            break
        clean = re.sub(r"[`*_\[\]()]", " ", heading)
        add(clean.strip())
        for word in re.split(r"[^A-Za-z0-9+.]+", clean):
            if len(out) >= minimum:
                break
            add(word)
    for fallback in (category, slugify(corpus_key, 24), subcategory,
                     "ctf", "offline-mirror", "external-corpus", "reference-corpus"):
        if len(out) >= minimum:
            break
        add(fallback)
    return out[:limit]


def subcategory_for(rel: str, tags: list[str]) -> str:
    parts = [p for p in posixpath.dirname(rel).split("/") if p]
    skip = {"docs", "src", "document", "en", "zh", "zh-tw", "."}
    leaf = ""
    for part in reversed(parts):
        cleaned = re.sub(r"^\d+[.\-_]*", "", part)
        if cleaned.lower() in skip or not cleaned:
            continue
        leaf = slugify(cleaned, 40)
        break
    return leaf or pick_subcategory(tags)


def is_technique(corpus: dict, rel: str, title: str) -> bool:
    stem = Path(rel).stem.lower()
    parent = Path(rel).parent.name.lower()
    if corpus["key"] == "payloads" and stem == "readme" and parent not in ("", "."):
        return any(w in slugify(parent) for w in ATTACK_STEM_WORDS)
    probe = f"{slugify(stem)}-{slugify(title)}"
    if stem in ("readme", "index"):
        probe = f"{slugify(parent)}-{slugify(title)}"
    return any(w in probe for w in ATTACK_STEM_WORDS)


def when_to_use_from(body: str, limit: int = 5) -> list[str]:
    """Trigger bullets taken from the document's own section headings."""
    out: list[str] = []
    for heading in H2_RE.findall(body):
        clean = re.sub(r"[`*_#]", "", heading).strip()
        clean = re.sub(r"\s+", " ", clean)
        if not clean or len(clean) < 4 or len(clean) > 90:
            continue
        if clean.lower() in ("references", "summary", "contents", "see also", "resources",
                             "further reading", "conclusion", "tools"):
            continue
        out.append(clean)
        if len(out) >= limit:
            break
    return out


def title_for(body: str, rel: str) -> str:
    match = H1_RE.search(body)
    if match:
        title = re.sub(r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)", "", match.group(1))
        title = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", title)
        title = re.sub(r"[`*_]", "", title).strip()
        if title:
            return title[:120]
    stem = Path(rel).stem
    if stem.lower() in ("readme", "index"):
        stem = Path(rel).parent.name or stem
    stem = re.sub(r"^\d+[.\-_]*", "", stem)
    return stem.replace("_", " ").replace("-", " ").strip().title() or "Untitled"


# ===========================================================================
# render
# ===========================================================================
def collect(corpus: dict, root: Path) -> list[str]:
    """Relative POSIX paths of the markdown files this corpus contributes."""
    found: list[str] = []
    if corpus["key"] == "ctf-wiki":
        return collect_ctf_wiki(root)

    globs = corpus.get("include_glob")
    if globs:
        for pattern in globs:
            found += [p.relative_to(root).as_posix() for p in root.glob(pattern) if p.is_file()]
    else:
        for sub in corpus.get("roots", []):
            base = root / sub if sub not in (".", "") else root
            if not base.exists():
                continue
            found += [p.relative_to(root).as_posix() for p in base.rglob("*.md")]

    include = corpus.get("include")
    if include:
        found = [r for r in found if any(r == i or r.startswith(i.rstrip("/") + "/")
                                         for i in include)]
    exclude = corpus.get("exclude_parts", set())
    found = [r for r in found if not (set(r.split("/")) & exclude)]
    return sorted(set(found))


def collect_ctf_wiki(root: Path) -> list[str]:
    """English pages first; a Chinese page only when no English page covers it."""
    en_root, zh_root = root / "docs/en/docs", root / "docs/zh/docs"
    english = {p.relative_to(en_root).as_posix() for p in en_root.rglob("*.md")} \
        if en_root.exists() else set()
    out = [f"docs/en/docs/{r}" for r in sorted(english)]
    if zh_root.exists():
        for path in sorted(zh_root.rglob("*.md")):
            rel = path.relative_to(zh_root).as_posix()
            if rel not in english:
                out.append(f"docs/zh/docs/{rel}")
    return out


def render_one(corpus: dict, root: Path, rel: str, sha: str,
               taken: set[str]) -> tuple[Path | None, str]:
    """Return (written path, status). Status is 'ok' or a drop reason."""
    if any(s in "/" + rel for s in SKIP_PATH_SUBSTRINGS):
        return None, "skipped-meta-page"

    source_file = root / rel
    try:
        text = source_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"unreadable:{type(exc).__name__}"

    body = strip_banners(text)
    if is_nav_stub(body):
        return None, "nav-stub"

    # Mirrored text is DATA. Anything carrying scraper bait is dropped, never obeyed.
    reason = looks_like_bait(body)
    if reason:
        if reason.startswith("scraper-bait"):
            BAIT_LOG.append({"corpus": corpus["key"], "file": rel, "reason": reason})
        return None, reason

    title = title_for(body, rel)
    # CTF Wiki's Chinese pages have Chinese H1s, which are invisible to an English
    # search. The source *filename* is English and authentic, so lead with it.
    if not re.search(r"[A-Za-z]", title):
        english = re.sub(r"^\d+[.\-_]+", "", Path(rel).stem)
        if english.lower() in ("readme", "index"):
            english = Path(rel).parent.name
        english = english.replace("_", " ").replace("-", " ").strip().title()
        if english:
            title = f"{english} - {title}"
    body = rewrite_links(body, corpus["repo"], sha, rel)
    permalink = (f"https://github.com/{corpus['repo']}/blob/{sha}/"
                 f"{quote(rel, safe='/._-~()[]%')}")
    body = truncate(body, MAX_BODY_LINES, permalink)

    category = category_for(corpus, rel, title, body)
    tags = mine_tags(title, rel.replace("/", " ").replace("-", " "), body[:12000],
                     extra=[corpus["key"], category])
    if category not in tags:
        tags.append(category)
    # The source path is English even when the page is not; those words are the only
    # handle an English search has on a Chinese page.
    for part in Path(rel).with_suffix("").parts[-2:]:
        for word in (slugify(re.sub(r"^\d+[.\-_]+", "", part), 32),
                     *re.split(r"[-_\s]+", part)):
            clean = slugify(word, 32)
            if clean and len(clean) > 2 and clean not in TAG_NOISE and clean not in tags:
                tags.append(clean)
    if rel.startswith("docs/zh/"):        # real metadata: this page is Chinese-language
        for lang_tag in ("chinese", "zh"):
            if lang_tag not in tags:
                tags.append(lang_tag)
    subcategory = subcategory_for(rel, tags) or category
    tags = pad_tags(tags, rel, title, category, corpus["key"],
                    headings=H2_RE.findall(body), subcategory=subcategory)

    technique = is_technique(corpus, rel, title)
    doctype = "technique" if technique else "reference"
    summary = first_sentence(body) or f"{title} - from the {corpus['name']} reference corpus."
    summary = summary[:200]

    footer = (f"\n\n---\n\n## Source\n\n"
              f"{corpus['name']} - <{permalink}>\n\n"
              f"Mirrored into CTF-Brain at commit `{sha[:12]}`. "
              f"Licence: {corpus['licence']}. The text is the original authors' work.\n")

    frontmatter: dict = {
        "title": f"{title} ({corpus['name']})",
        "category": category,
        "subcategory": subcategory,
        "type": doctype,
        "tags": tags,
        "summary": summary,
        "source": {"name": corpus["name"], "url": permalink},
        "license": corpus["licence"],
    }
    if technique:
        frontmatter["difficulty"] = DIFFICULTY_BY_CATEGORY.get(category, "medium")
        triggers = when_to_use_from(body)
        if triggers:
            frontmatter["when_to_use"] = triggers

    stem = f"{PREFIX}{corpus['key']}-{doc_stem(rel)}"
    out_dir = CONTENT / "techniques" / category if technique else CONTENT / "reference"
    out = out_dir / f"{stem}.md"
    n = 2
    while out.as_posix() in taken:
        out = out_dir / f"{stem}-{n}.md"
        n += 1
    taken.add(out.as_posix())

    write_doc(out, frontmatter, body + footer)
    return out, "ok"


# --------------------------------------------------------------- awesome lists
AWESOME_ITEM_RE = re.compile(
    r"^\s*[-*]\s*\[([^\]]+)\]\(([^)]+)\)\s*[---:]*\s*(.*)$")


def render_awesome(corpus: dict, root: Path, sha: str, taken: set[str]) -> list[Path]:
    """Explode a curated `awesome-*` README into one reference page per section."""
    path = root / corpus["awesome_list"]
    if not path.exists():
        return []
    text = strip_banners(path.read_text(encoding="utf-8", errors="replace"))
    permalink = f"https://github.com/{corpus['repo']}/blob/{sha}/{corpus['awesome_list']}"

    part = ""
    section = ""
    blurb: list[str] = []
    items: list[tuple[str, str, str]] = []
    written: list[Path] = []

    def flush() -> None:
        nonlocal items, blurb
        if section and len(items) >= 3:
            page = _write_awesome_section(corpus, part, section, blurb, items,
                                          permalink, sha, taken)
            if page:
                written.append(page)
        items, blurb = [], []

    for line in text.splitlines():
        h1 = re.match(r"^#\s+(.+)$", line)
        h2 = re.match(r"^##\s+(.+)$", line)
        if h1:
            flush()
            part = re.sub(r"\[!\[.*", "", h1.group(1)).strip()
            section = ""
            continue
        if h2:
            flush()
            section = re.sub(r"[`*_]", "", h2.group(1)).strip()
            continue
        item = AWESOME_ITEM_RE.match(line)
        if item and section:
            name, url, desc = item.group(1).strip(), item.group(2).strip(), item.group(3).strip()
            desc = re.sub(r"^[---:]\s*", "", desc).strip()
            items.append((name, url, desc))
        elif section and line.strip().startswith("*") and line.strip().endswith("*") \
                and not line.strip().startswith("* "):
            blurb.append(line.strip().strip("*").strip())
    flush()
    return written


def _write_awesome_section(corpus: dict, part: str, section: str, blurb: list[str],
                           items: list[tuple[str, str, str]], permalink: str,
                           sha: str, taken: set[str]) -> Path | None:
    label = f"{section} ({part})" if part and part.lower() not in section.lower() else section
    blob = " ".join(f"{n} {d}" for n, _, d in items)
    category = categorise(section, part, blob)
    if category == "misc":
        category = DEFAULT_CATEGORY["awesome-ctf"]

    lines = [f"Curated CTF tools for **{section.lower()}**"
             + (f" ({part.lower()})" if part else "") + ".", ""]
    if blurb:
        lines += ["> " + "; ".join(blurb), ""]
    lines += ["| Tool | What it does | Link |", "|---|---|---|"]
    for name, url, desc in items:
        clean = re.sub(r"\s*\|\s*", " / ", desc).strip() or "(no description upstream)"
        lines.append(f"| {name} | {clean} | <{url}> |")
    lines += ["", "---", "", "## Source", "",
              f"{corpus['name']} - <{permalink}> (section `## {section}`)", "",
              f"Mirrored into CTF-Brain at commit `{sha[:12]}`. "
              f"Licence: {corpus['licence']}.", ""]

    tags = mine_tags(section, part, blob, extra=["awesome-ctf", "tool-index", category])
    for extra in (category, slugify(section, 30), "tools", "tool-list", "curated"):
        if extra and extra not in tags:
            tags.append(extra)
    tags = pad_tags(tags, f"{slugify(part)}/{slugify(section)}", section, category,
                    corpus["key"])

    stem = f"{PREFIX}awesome-ctf-{slugify(part, 20)}-{slugify(section, 30)}".strip("-")
    out = CONTENT / "reference" / f"{stem}.md"
    n = 2
    while out.as_posix() in taken:
        out = CONTENT / "reference" / f"{stem}-{n}.md"
        n += 1
    taken.add(out.as_posix())

    write_doc(out, {
        "title": f"{label} tool index (Awesome CTF)",
        "category": category,
        "subcategory": slugify(section, 30),
        "type": "reference",
        "tags": tags[:20],
        "summary": f"{len(items)} curated {section.lower()} CTF tools, each with what it "
                   f"does and where to get it."[:200],
        "tools": [n for n, _, _ in items][:20],
        "source": {"name": corpus["name"], "url": permalink},
        "license": corpus["licence"],
    }, "\n".join(lines))
    return out


# ===========================================================================
# driver
# ===========================================================================
def render(only: set[str] | None = None, limit: int = 0) -> dict:
    shas: dict[str, str] = load_json(SRC / "shas.json", {}) or {}
    state: dict = load_json(STATE_JSON, {}) or {}
    # A scoped run (--corpus) must not erase the other corpora from the report, or the
    # provenance table would come back with only the corpus that was just rendered.
    previous: dict = load_json(REPORT_JSON, {}) or {}
    report: dict = {"corpora": dict(previous.get("corpora") or {}) if only else {},
                    "failures": [], "bait": []}
    taken: set[str] = set()

    for corpus in CORPORA:
        key = corpus["key"]
        if only and key not in only:
            continue
        root = SRC / key
        if not root.exists():
            print(f"  {corpus['name']}: not cloned, skipping")
            report["corpora"][key] = {"status": "not-cloned", "pages": 0}
            continue
        sha = shas.get(key) or head_sha(root)
        shas[key] = sha

        counts: dict[str, int] = {}
        by_category: dict[str, int] = {}
        pages = 0
        drops: dict[str, int] = {}

        if corpus.get("awesome_list"):
            try:
                written = render_awesome(corpus, root, sha, taken)
            except Exception:                                 # noqa: BLE001
                report["failures"].append({"corpus": key, "file": corpus["awesome_list"],
                                           "error": traceback.format_exc(limit=2)[-400:]})
                written = []
            pages = len(written)
            by_category = _tally_categories(written)
        else:
            rels = collect(corpus, root)
            if limit:
                rels = rels[:limit]
            written_paths: list[Path] = []
            for rel in rels:
                try:
                    out, status = render_one(corpus, root, rel, sha, taken)
                except Exception:                             # noqa: BLE001
                    report["failures"].append({"corpus": key, "file": rel,
                                               "error": traceback.format_exc(limit=2)[-400:]})
                    drops["exception"] = drops.get("exception", 0) + 1
                    continue
                if out is None:
                    drops[status] = drops.get(status, 0) + 1
                    continue
                written_paths.append(out)
                pages += 1
            by_category = _tally_categories(written_paths)

        counts = {"pages": pages, "dropped": drops, "by_category": by_category,
                  "sha": sha, "licence": corpus["licence"]}
        report["corpora"][key] = counts
        state[key] = {"sha": sha, "pages": pages}
        drop_note = ", ".join(f"{k}={v}" for k, v in sorted(drops.items())) or "none"
        print(f"  {corpus['name']:<32} {pages:>5} pages   dropped: {drop_note}")

    # BAIT_LOG only fills up during the loop above, so collect it afterwards.
    report["bait"] = (list(previous.get("bait") or []) if only else []) + BAIT_LOG

    save_json(SRC / "shas.json", shas)
    save_json(STATE_JSON, state)
    save_json(REPORT_JSON, report)
    if report["failures"]:
        print(f"  {len(report['failures'])} page(s) raised and were skipped "
              f"(details in {REPORT_JSON})")
    return report


def _cat_of(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:600]
        match = re.search(r"^category:\s*\"?([a-z]+)", text, re.MULTILINE)
        return match.group(1) if match else "misc"
    except OSError:
        return "misc"


def _tally_categories(paths: list[Path]) -> dict[str, int]:
    tally: dict[str, int] = {}
    for path in paths:
        category = path.parent.name if path.parent.parent.name == "techniques" else _cat_of(path)
        tally[category] = tally.get(category, 0) + 1
    return dict(sorted(tally.items(), key=lambda kv: -kv[1]))


# ===========================================================================
# provenance
# ===========================================================================
def provenance() -> Path:
    report = load_json(REPORT_JSON, {}) or {}
    rows = report.get("corpora", {})
    total = sum(r.get("pages", 0) for r in rows.values())

    lines = [
        "---",
        'title: "Mirrored reference corpora - provenance and licences"',
        "category: misc",
        "subcategory: provenance",
        "type: reference",
        "tags: [provenance, licence, license, attribution, corpora, mirror, ctf-wiki, "
        "hacktricks, payloadsallthethings, owasp-wstg, awesome-ctf, trail-of-bits, "
        "sources, offline, reference]",
        f'summary: "Every external reference corpus mirrored into CTF-Brain: repo, '
        f'commit, licence and page count ({total} pages)."',
        "---",
        "",
        "# Mirrored reference corpora",
        "",
        "Every `content/**/ext-*.md` page in CTF-Brain is a mirror of one document from one",
        "of the corpora below. Nothing here is CTF-Brain's own work: the text belongs to the",
        "original authors and is redistributed under the licence shown, with a `source:` link",
        "back to the exact file at the exact commit in every page's frontmatter.",
        "",
        "Regenerate with `python3 ingest/reference_corpora.py all`.",
        "",
        "| Corpus | Repository | Commit | Licence | Pages | What was taken |",
        "|---|---|---|---|---|---|",
    ]
    for corpus in CORPORA:
        row = rows.get(corpus["key"], {})
        sha = row.get("sha", "not-cloned")
        lines.append(
            f"| {corpus['name']} | [{corpus['repo']}]({corpus['url']}) | `{sha[:12]}` | "
            f"{corpus['licence']} | {row.get('pages', 0)} | {corpus['took']} |")
    lines += ["", f"**Total mirrored pages: {total}**", "", "## Licence notes", ""]
    for corpus in CORPORA:
        lines += [f"### {corpus['name']} - {corpus['licence']}", "",
                  f"- Repository: <{corpus['url']}>",
                  f"- Licence file read: `{corpus['licence_path']}`",
                  f"- {corpus['licence_note']}", ""]
    lines += [
        "## What the non-commercial licences mean here",
        "",
        "CTF Wiki is CC BY-NC-SA 4.0 and HackTricks is CC BY-NC 4.0. Both permit copying and",
        "redistribution with attribution for non-commercial use; CTF Wiki additionally",
        "requires ShareAlike on adaptations. This mirror is a personal, offline, non-commercial",
        "knowledge base and attributes every page to its source, which is within those terms.",
        "**Do not redistribute this mirror commercially.** The remaining corpora (MIT,",
        "CC BY-SA 4.0, CC0 1.0) carry no such restriction.",
        "",
        "## Per-corpus page counts by category",
        "",
    ]
    for corpus in CORPORA:
        row = rows.get(corpus["key"], {})
        by_cat = row.get("by_category") or {}
        if not by_cat:
            continue
        spread = ", ".join(f"{cat} {n}" for cat, n in by_cat.items())
        lines.append(f"- **{corpus['name']}** ({row.get('pages', 0)}): {spread}")
    lines += [
        "",
        "## Pages that were deliberately dropped",
        "",
        "| Corpus | Reason | Count |",
        "|---|---|---|",
    ]
    for corpus in CORPORA:
        for reason, count in sorted((rows.get(corpus["key"], {}).get("dropped") or {}).items()):
            lines.append(f"| {corpus['name']} | `{reason}` | {count} |")
    lines += [
        "",
        "`nav-stub` is a page with fewer than 20 lines of real content (a table of contents).",
        "`skipped-meta-page` is repository housekeeping (contributing guides, licences, nav).",
        "`scraper-bait` and `too-short` come from `ingest/ctftime.py::looks_like_bait`:",
        "a handful of mirrored pages contain text addressed at automated scrapers. Those pages",
        "are dropped rather than mirrored, and no instruction found inside any mirrored",
        "document is ever acted on -- mirrored text is data.",
        "",
        "### Pages the bait filter dropped",
        "",
    ]
    for row in report.get("bait") or []:
        lines.append(f"- `{row['corpus']}` / `{row['file']}` -- {row['reason']}")
    if not report.get("bait"):
        lines.append("- (none in this run)")
    lines += [
        "",
        "A page can trip this filter innocently: a page *about* prompt injection quotes",
        "the same strings an attacker would plant. The filter does not try to tell the two",
        "apart, because a mirror has no need to carry either.",
        "",
        "## Corpora verified but not mirrored, on licence grounds",
        "",
        "These repositories exist and are useful, but carry no licence granting",
        "redistribution. Nothing from them is copied here -- clone them yourself.",
        "",
    ]
    for row in SKIPPED_ON_LICENCE:
        lines.append(f"- [{row['repo']}](https://github.com/{row['repo']}) -- {row['why']}")
    lines += [
        "",
        "## Removing something",
        "",
        "If you are an author and want your work out of this mirror, delete the matching",
        "`content/**/ext-<corpus>-*.md` files and re-run `ctfbrain index`.",
        "",
    ]
    PROVENANCE.parent.mkdir(parents=True, exist_ok=True)
    PROVENANCE.write_text("\n".join(lines), encoding="utf-8")
    print(f"  wrote {PROVENANCE.relative_to(CONTENT.parent)}")
    return PROVENANCE


def purge(only: set[str] | None = None) -> int:
    """Delete the pages this pipeline owns, so a re-render never leaves orphans.

    Scoped to the selected corpora, so `--corpus hacktricks` never touches the rest.
    """
    prefixes = tuple(f"{PREFIX}{key}-" for key in (only or CORPUS_BY_KEY))
    removed = 0
    for path in list(CONTENT.glob("reference/ext-*.md")) + \
            list(CONTENT.glob("techniques/*/ext-*.md")):
        if path.name.startswith(prefixes):
            path.unlink()
            removed += 1
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("stage", choices=["all", "verify", "clone", "render",
                                          "provenance", "purge"])
    parser.add_argument("--corpus", action="append", default=[],
                        help="restrict to one corpus key (repeatable)")
    parser.add_argument("--limit", type=int, default=0,
                        help="cap pages per corpus (for smoke tests)")
    args = parser.parse_args()

    only = set(args.corpus) or None
    if only:
        unknown = only - set(CORPUS_BY_KEY)
        if unknown:
            print(f"unknown corpus key(s): {', '.join(sorted(unknown))}")
            print(f"known: {', '.join(CORPUS_BY_KEY)}")
            return 2

    if args.stage in ("all", "verify"):
        print("verify:")
        verify()
    if args.stage in ("all", "clone"):
        print("clone:")
        clone(only)
    if args.stage == "purge":
        print(f"purge: removed {purge(only)} ext-* pages")
        return 0
    if args.stage in ("all", "render"):
        print("render:")
        purged = purge(only)
        if purged:
            print(f"  cleared {purged} previously rendered ext-* pages")
        report = render(only, args.limit)
        total = sum(r.get("pages", 0) for r in report["corpora"].values())
        print(f"  TOTAL {total} pages")
    if args.stage in ("all", "provenance"):
        print("provenance:")
        provenance()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
