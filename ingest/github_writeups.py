#!/usr/bin/env python3
"""Harvest CTF writeups from well-known public team repositories on GitHub.

    python3 ingest/github_writeups.py verify
    python3 ingest/github_writeups.py tree
    python3 ingest/github_writeups.py fetch  --limit 3000
    python3 ingest/github_writeups.py render
    python3 ingest/github_writeups.py all

Everything goes through the authenticated `gh` CLI and is cached under
`data/raw/github/`:

    repos.json          one entry per verified repository (stars, branch, head sha)
    trees/<slug>.json   the recursive git tree of each repository
    candidates.json     every markdown path that looks like a real writeup
    blobs/<ab>/<sha>    the decoded blob, keyed by its immutable git blob sha
    report.json         per-repo and per-category counts

Because blobs are content-addressed the cache never goes stale and a re-run is
free.  A file that fails to fetch, decode or render is recorded and skipped; one
bad file never aborts the run.  `gh api rate_limit` is polled and the run backs
off whenever fewer than 100 core requests remain.

This module also owns the small `gh` plumbing (`gh_api`, `gh_blob`,
`wait_for_rate_limit`) that `ingest/alpacahack.py` imports.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    CATEGORIES, CONTENT, RAW, STRONG_SIGNALS, categorise, first_sentence,
    load_json, mine_tags, pick_subcategory, save_json, slugify, truncate, write_doc,
)
from ctftime import looks_like_bait  # noqa: E402  - reuse the scraper-bait filter

CACHE = RAW / "github"
BLOBS = CACHE / "blobs"
TREES = CACHE / "trees"
REPOS_JSON = CACHE / "repos.json"
CANDIDATES_JSON = CACHE / "candidates.json"
REPORT_JSON = CACHE / "report.json"

# The repositories we ingest.  Every one of them is verified with
# `gh repo view` before it is crawled - nothing here is assumed to exist.
REPOS: tuple[str, ...] = (
    "Dvd848/CTFs",
    "perfectblue/ctf-writeups",
    "Adamkadaban/CTFs",
    "susers/Writeups",
    "bl4de/ctf",
    "balsn/ctf_writeup",
    "sixstars/ctf",
    "sajjadium/ctf-writeups",
    "nobodyisnobody/write-ups",
    "project-sekai-ctf/sekaictf-2022",
    "project-sekai-ctf/sekaictf-2023",
    "project-sekai-ctf/sekaictf-2024",
    "TFNS/writeups",
    # Two HTB Cyber Apocalypse editions: they are the densest public source of
    # hardware, blockchain and ML challenges, which the team repos barely cover.
    "hackthebox/cyber-apocalypse-2024",
    "hackthebox/cyber-apocalypse-2025",
)

# Keep breadth over depth: no single repo or single CTF may dominate the corpus.
PER_REPO_CAP = 130
PER_CTF_CAP = 26

# ---------------------------------------------------------------- path vocabulary
# A directory whose name is one of these tells us the category outright.
CATEGORY_DIRS: dict[str, str] = {}
for _cat, _aliases in {
    "crypto": ("crypto", "cryptography", "crypt", "cryptanalysis", "密码", "密码学"),
    "web": ("web", "websec", "web-security", "web-exploitation", "webexploitation",
            "web-exploit", "web安全", "网络安全"),
    "pwn": ("pwn", "pwnable", "pwnables", "pwning", "exploit", "exploitation",
            "binary-exploitation", "binaryexploitation", "binary", "bin", "系统安全",
            "二进制"),
    "rev": ("rev", "reverse", "reversing", "reverse-engineering", "reverseengineering",
            "re", "crackme", "crackmes", "逆向"),
    "forensics": ("forensics", "forensic", "network", "networking", "net", "取证",
                  "网络协议", "traffic"),
    "stego": ("stego", "steganography", "steg", "隐写"),
    "misc": ("misc", "miscellaneous", "ppc", "programming", "trivia", "warmup",
              "jail", "sandbox", "ml", "ai", "machine-learning", "coding", "杂项"),
    "osint": ("osint", "recon", "reconnaissance"),
    "mobile": ("mobile", "android", "ios", "apk"),
    "hardware": ("hardware", "embedded", "radio", "rf", "iot", "ics", "scada",
                 "sidechannel", "side-channel", "hw"),
    "blockchain": ("blockchain", "smart-contract", "smartcontract", "smartcontracts",
                   "ethereum", "solidity", "defi", "web3"),
    "cloud": ("cloud", "kubernetes", "k8s", "devops", "container", "containers"),
}.items():
    for _alias in _aliases:
        CATEGORY_DIRS[_alias] = _cat

# Directory names that wrap a writeup but are not the challenge itself.
WRAPPER_DIRS = {
    "solution", "solutions", "sol", "writeup", "writeups", "write-up", "write-ups",
    "wu", "assets", "images", "img", "media", "files", "src", "source", "docs", "doc",
    "solver", "solvers", "exploit", "exploits", "release", "dist", "attachments",
    "public", "handout", "handouts", "chall", "challenge",
}

# Repository-level directories that carry no meaning.
NOISE_DIRS = {
    "ctfs", "ctf", "writeups", "writeup", "write-ups", "docs", "content", "src",
    "1.ctfs", "2.tools", "0.notes", "notes", "archive", "misc-ctfs", "competitions",
}

# Vendored third-party code checked into a challenge directory; its README is
# somebody else's library documentation, not a writeup.
VENDOR_DIRS = {
    "node_modules", "vendor", "third_party", "thirdparty", "site-packages",
    "bower_components", "deps", "lib", "libs", "target", "build", "venv",
    "forge-std", "openzeppelin-contracts", "openzeppelin-contracts-upgradeable",
}

# Round qualifiers that belong on the CTF name, not instead of it.
ROUND_WORDS = {
    "quals", "qual", "qualifier", "qualifiers", "qualification", "qualifications",
    "finals", "final", "prequals", "prequal", "online", "onsite", "teaser",
}

# Generic file names: several of these in one directory describe one challenge.
GENERIC_NAMES = {
    "readme", "index", "writeup", "writeups", "write-up", "write_up", "wu",
    "solution", "solutions", "sol", "notes", "report",
}

# Never a writeup.
SKIP_NAMES = {
    "contributing", "license", "licence", "code_of_conduct", "code-of-conduct",
    "security", "changelog", "change_log", "history", "todo", "authors",
    "pull_request_template", "issue_template", "support", "funding", "description",
    "template", "_index", "summary", "toc",
}

DIFFICULTIES = ("trivial", "easy", "medium", "hard", "insane")
DIFFICULTY_RE = re.compile(
    r"(?:difficulty|level)\s*[:\|]?\s*\**\s*(trivial|very easy|easy|medium|hard|insane|"
    r"very hard)\b", re.IGNORECASE)

YEAR_RE = re.compile(r"(?:19|20)\d{2}")
ISO_DATE_DIR_RE = re.compile(r"^((?:19|20)\d{2})[-_.](\d{2})[-_.](\d{2})[-_.](.+)$")
COMPACT_DATE_DIR_RE = re.compile(r"^((?:19|20)\d{2})(\d{2})(\d{2})[-_.](.+)$")


# ------------------------------------------------------------------- gh plumbing
_RATE_LOCK = threading.Lock()
_RATE_STATE = {"checked": 0.0, "remaining": 5000}


def _gh_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("GH_PAGER", "cat")
    env.setdefault("CLICOLOR", "0")
    return env


def gh_raw(args: list[str], *, timeout: int = 90) -> tuple[int, str, str]:
    """Run `gh` and return (returncode, stdout, stderr).  Never raises."""
    try:
        proc = subprocess.run(["gh", *args], capture_output=True, text=True,
                              timeout=timeout, env=_gh_env())
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:                          # noqa: BLE001 - subprocess is hostile
        return 1, "", str(exc)


def wait_for_rate_limit(floor: int = 100, force: bool = False) -> int:
    """Poll `gh api rate_limit`; sleep until reset when core credit runs low."""
    with _RATE_LOCK:
        now = time.time()
        if not force and now - _RATE_STATE["checked"] < 60 and _RATE_STATE["remaining"] > floor * 3:
            return _RATE_STATE["remaining"]
        code, stdout, _ = gh_raw(["api", "rate_limit"], timeout=30)
        if code != 0:
            _RATE_STATE["checked"] = now
            return _RATE_STATE["remaining"]
        try:
            core = json.loads(stdout)["resources"]["core"]
        except Exception:                             # noqa: BLE001
            _RATE_STATE["checked"] = now
            return _RATE_STATE["remaining"]
        remaining, reset = int(core.get("remaining", 0)), int(core.get("reset", 0))
        _RATE_STATE.update(checked=time.time(), remaining=remaining)
        if remaining < floor:
            nap = max(5, min(3600, reset - int(time.time()) + 5))
            print(f"  rate limit: {remaining} left - sleeping {nap}s until reset")
            time.sleep(nap)
            _RATE_STATE["remaining"] = 5000
        return _RATE_STATE["remaining"]


def gh_api(endpoint: str, *, jq: str | None = None, timeout: int = 120) -> str | None:
    """One `gh api` call with rate-limit backoff and a couple of retries."""
    args = ["api", endpoint]
    if jq:
        args += ["--jq", jq]
    for attempt in range(3):
        wait_for_rate_limit()
        with _RATE_LOCK:
            _RATE_STATE["remaining"] -= 1
        code, stdout, stderr = gh_raw(args, timeout=timeout)
        if code == 0:
            return stdout
        low = stderr.lower()
        if "not found" in low or "404" in low:
            return None
        if "rate limit" in low or "abuse" in low or "secondary" in low:
            wait_for_rate_limit(force=True)
        time.sleep(1.5 * (attempt + 1))
    return None


def gh_json(endpoint: str, *, timeout: int = 120):
    raw = gh_api(endpoint, timeout=timeout)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:                                 # noqa: BLE001
        return None


def blob_path(sha: str) -> Path:
    return BLOBS / sha[:2] / f"{sha}.txt"


def gh_blob(repo: str, sha: str) -> str | None:
    """Fetch one blob's text, cached forever under its immutable sha."""
    cache = blob_path(sha)
    if cache.exists():
        text = cache.read_text(encoding="utf-8", errors="replace")
        return None if text == "\x00FAILED" else text
    payload = gh_json(f"repos/{repo}/git/blobs/{sha}")
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not payload or "content" not in payload:
        cache.write_text("\x00FAILED", encoding="utf-8")
        return None
    try:
        data = base64.b64decode(payload["content"])
        text = data.decode("utf-8", errors="replace")
    except Exception:                                 # noqa: BLE001
        cache.write_text("\x00FAILED", encoding="utf-8")
        return None
    cache.write_text(text, encoding="utf-8")
    return text


# ------------------------------------------------------------------ path parsing
def _clean_name(text: str) -> str:
    text = re.sub(r"[_.+]+", " ", str(text or ""))
    text = re.sub(r"(?<=[a-z0-9])-(?=[a-z0-9])", " ", text)
    text = re.sub(r"\s{2,}", " ", text).strip(" -")
    return text


def _norm_dir(name: str) -> str:
    return re.sub(r"[\s_]+", "-", str(name or "").strip().lower())


def _split_date_dir(name: str) -> tuple[str, int] | None:
    """`2019-09-14-rwctf` / `20171104-hitconctfquals` -> (name, year)."""
    for pattern in (ISO_DATE_DIR_RE, COMPACT_DATE_DIR_RE):
        match = pattern.match(name)
        if match:
            return _clean_name(match.group(4)), int(match.group(1))
    return None


def _name_and_year(component: str) -> tuple[str, int | None]:
    dated = _split_date_dir(component)
    if dated:
        return dated
    years = YEAR_RE.findall(component)
    if not years:
        return _clean_name(component), None
    year = int(years[-1])
    # `\b` is useless here: `_` is a word character, so `2019_SunshineCTF` would
    # never match.  Guard on digits instead.
    stripped = re.sub(r"[-_. ]*(?<![0-9])%s(?![0-9])[-_. ]*" % years[-1],
                      " ", component, count=1)
    return _clean_name(stripped) or _clean_name(component), year


def parse_path(path: str, repo_ctf: tuple[str, int | None]) -> dict | None:
    """Turn a repository path into {ctf, year, challenge, category} or None to skip."""
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return None                                   # a root-level README
    if any(p.startswith(".") for p in parts):
        return None
    if any(_norm_dir(p) in VENDOR_DIRS for p in parts[:-1]):
        return None
    filename = parts[-1]
    stem = re.sub(r"\.md$", "", filename, flags=re.I)
    key = _norm_dir(stem)
    if key in SKIP_NAMES or key.replace("-", "_") in SKIP_NAMES:
        return None
    if "license" in key or "template" in key:
        return None

    dirs = parts[:-1]
    generic = key in GENERIC_NAMES

    # Walk past wrapper directories (solution/, writeup/, assets/ ...).
    if generic:
        idx = len(dirs) - 1
        while idx >= 0 and _norm_dir(dirs[idx]) in WRAPPER_DIRS:
            idx -= 1
        if idx < 0:
            return None
        challenge_dir = dirs[idx]
        context = dirs[:idx]
        group = "/".join(dirs[:idx + 1])
    else:
        challenge_dir = ""
        context = dirs
        group = path

    # The category can be stated by any directory on the way down.
    category = ""
    for component in reversed(context + ([challenge_dir] if challenge_dir else [])):
        hit = CATEGORY_DIRS.get(_norm_dir(component))
        if hit:
            category = hit
            break

    # Locate the CTF directory.
    ctf_name, year = "", None
    ctf_index = -1
    for i in range(len(context) - 1, -1, -1):
        component = context[i]
        if not YEAR_RE.search(component):
            continue
        if re.fullmatch(r"(?:19|20)\d{2}", component.strip()):
            year = int(component.strip())
            before = context[i - 1] if i > 0 else ""
            after = context[i + 1] if i + 1 < len(context) else ""
            if before and _norm_dir(before) not in NOISE_DIRS \
                    and _norm_dir(before) not in CATEGORY_DIRS:
                ctf_name = _clean_name(before)
                if after and _norm_dir(after) in ROUND_WORDS:
                    ctf_name = f"{ctf_name} {_clean_name(after)}"
                ctf_index = i - 1
            elif after and _norm_dir(after) not in CATEGORY_DIRS \
                    and _norm_dir(after) not in NOISE_DIRS:
                ctf_name = _clean_name(after)
                ctf_index = i + 1
            else:
                ctf_index = i
            break
        name, found_year = _name_and_year(component)
        if name:
            ctf_name, year, ctf_index = name, found_year, i
            break

    meaningful = [c for c in context
                  if _norm_dir(c) not in NOISE_DIRS and _norm_dir(c) not in CATEGORY_DIRS
                  and _norm_dir(c) not in WRAPPER_DIRS
                  and not re.fullmatch(r"(?:19|20)\d{2}", c.strip())]
    if not ctf_name and meaningful:
        ctf_name = _clean_name(meaningful[0])
        ctf_index = context.index(meaningful[0])

    if not ctf_name and generic and challenge_dir and not meaningful \
            and (not context or YEAR_RE.search(challenge_dir)):
        # A repository organised one-README-per-event: the directory holding the
        # README is the CTF itself, and the file covers the whole event.
        name, found_year = _name_and_year(challenge_dir)
        if name:
            ctf_name, ctf_index = name, len(context)
            year = found_year if found_year is not None else year

    if not ctf_name:
        ctf_name, year = repo_ctf[0], repo_ctf[1] if year is None else year
    if year is None:
        year = repo_ctf[1]

    if generic:
        # A README sitting directly on the CTF or category directory is an index,
        # unless the whole repository is organised one-writeup-per-CTF.
        norm_challenge = _norm_dir(challenge_dir)
        if norm_challenge in CATEGORY_DIRS or norm_challenge in NOISE_DIRS \
                or re.fullmatch(r"(?:19|20)\d{2}", challenge_dir.strip()):
            return None
        is_ctf_dir = (ctf_index >= 0 and ctf_index == len(context)) or (
            len(context) == 0 and YEAR_RE.search(challenge_dir) is not None)
        if is_ctf_dir or (not context and _norm_dir(challenge_dir) == _norm_dir(ctf_name)):
            challenge = ""
        else:
            challenge = _clean_name(challenge_dir)
    else:
        challenge = _clean_name(stem)
        challenge = re.sub(r"\b(write ?-?up|writeup|solution)\b", "", challenge,
                           flags=re.I).strip(" -") or _clean_name(stem)

    if not ctf_name:
        return None
    return {
        "ctf": ctf_name[:80],
        "year": year,
        "challenge": challenge[:80],
        "category_dir": category,
        "generic": generic,
        "group": group,
    }


# ------------------------------------------------------------------ body helpers
def _resolve_relative(target: str, dirpath: str) -> str:
    """Join a relative path onto a directory, clamping `..` at the repo root.

    `urljoin` silently swallows a `..` that climbs above the base, which turns
    `../../assets/x.png` into a URL missing the repo and ref entirely.
    """
    segments = [p for p in dirpath.split("/") if p] if dirpath else []
    if target.startswith("/"):
        segments, target = [], target.lstrip("/")
    for segment in target.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/".join(segments)


def rewrite_links(body: str, repo: str, sha: str, dirpath: str) -> str:
    """Point every relative link/image at an absolute github URL."""
    raw_base = f"https://raw.githubusercontent.com/{repo}/{sha}/"
    blob_base = f"https://github.com/{repo}/blob/{sha}/"

    def fix(url: str) -> str:
        target = url.strip()
        if not target or target.startswith(
                ("http://", "https://", "mailto:", "data:", "#", "//", "<", "{")):
            return url
        path, sep, tail = target.partition("#")
        if not path:
            return url
        try:
            resolved = _resolve_relative(path, dirpath)
            if not resolved:
                return url
            base = blob_base if resolved.lower().endswith(".md") else raw_base
            return base + quote(resolved, safe="/%?&=~._-+()[]!$'*,;:@") + sep + tail
        except Exception:                             # noqa: BLE001
            return url

    body = re.sub(r"(!?\[[^\]\n]*\]\()([^)\s]+)((?:\s+\"[^\"]*\")?\))",
                  lambda m: m.group(1) + fix(m.group(2)) + m.group(3), body)
    body = re.sub(r"(<(?:img|a|source|video|embed)\b[^>]*?\s(?:src|href)=)(['\"])([^'\"]+)(\2)",
                  lambda m: m.group(1) + m.group(2) + fix(m.group(3)) + m.group(4),
                  body, flags=re.I)
    return body


def looks_like_index(body: str) -> bool:
    """A table of contents pointing at other writeups is not itself a writeup."""
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    if not lines:
        return True
    link_only = re.compile(r"^[-*+>]?\s*\d*\.?\s*!?\[[^\]]+\]\([^)]*\)\s*\.?$")
    linky, prose = 0, 0
    for line in lines:
        if line.startswith("|") or link_only.match(line):
            linky += 1
        else:
            prose += len(re.sub(r"\s+", " ", line))
    # A table of contents is links with almost no prose around them.  A short
    # writeup that merely attaches its exploit files is not one.
    return linky >= 4 and prose < 260 and body.count("```") < 4


def ascii_ratio(text: str) -> float:
    sample = re.sub(r"\s+", "", text[:1500])
    if not sample:
        return 1.0
    return sum(1 for ch in sample if ord(ch) < 128) / len(sample)


def strip_code(body: str) -> str:
    """Prose only - fenced code and HTML make for terrible one-line summaries."""
    text = re.sub(r"^[ \t]*```.*?^[ \t]*```", "", body, flags=re.DOTALL | re.MULTILINE)
    text = re.sub(r"^[ \t]*~~~.*?^[ \t]*~~~", "", text, flags=re.DOTALL | re.MULTILINE)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"^(?: {4,}|\t).*$", "", text, flags=re.MULTILINE)


def build_summary(body: str, challenge: str, ctf: str, category: str,
                  tags: list[str]) -> str:
    candidate = first_sentence(strip_code(body))
    if candidate and ascii_ratio(candidate) > 0.9 and len(candidate) > 30 \
            and not candidate.lower().startswith(("http", "|", "flag{", "author")):
        return candidate[:200]
    topic = ", ".join(t for t in tags if t != category)[:90]
    label = challenge or "challenge set"
    head = f"{category} writeup for \"{label}\"" + (f" from {ctf}" if ctf else "")
    return (f"{head} - techniques: {topic}." if topic else f"{head}.")[:200]


# Prose keyword scoring is substring-based, so a short keyword can fire on an
# unrelated word ("defi" inside "defined").  For the narrow categories a single
# stray hit is enough to win, so they additionally need a mined tag to back them.
NARROW_CATEGORIES = {"blockchain", "cloud", "mobile", "hardware", "osint", "stego"}


# `mine_tags` matches plain substrings, which is fast but fires on innocent
# words: "message" contains "sage ", "defined" contains "defi", "recipe" contains
# "pie ".  We cannot change that shared table, so the handful of fragile tags get
# a word-boundary second opinion here before they reach the frontmatter.
TAG_CONFIRM: dict[str, re.Pattern[str]] = {
    tag: re.compile(pattern, re.IGNORECASE) for tag, pattern in {
        "sage": r"\bsage(?:math)?\b",
        "heap": r"\bheaps?\b",
        "png-chunks": r"\bpng chunk|\bIDAT\b|\bIHDR\b",
        "eval": r"\beval\s*\(",
        "exec": r"\bexec\s*\(",
        "regex": r"\bregular expressions?\b|\bre\.(?:fullmatch|match|search)\b",
        "jit": r"\bjit\b|turbofan",
        "orw": r"\borw\b|open.{0,8}read.{0,8}write",
        "cgi": r"cgi-bin|\bcgi\b",
        "pie": r"\bpie\b",
        "gef": r"\bgef\b",
        "lsb": r"\blsbs?\b|least significant bit",
        "xor": r"\bxor(?:ed|ing|s)?\b|\^=",
        "des": r"\b3?des\b",
        "ecb": r"\becb\b", "cbc": r"\bcbc\b", "ctr": r"\bctr\b", "gcm": r"\bgcm\b",
        "crt": r"\bcrt\b|chinese remainder",
        "redis": r"\bredis\b", "sqlite": r"\bsqlite\b", "mysql": r"\bmysql\b",
        "nginx": r"\bnginx\b", "base64": r"\bbase64\b", "base32": r"\bbase32\b",
        "gets": r"\bgets\s*\(", "exif": r"\bexif\b",
    }.items()
}


def prune_tags(tags: Iterable[str], body: str) -> list[str]:
    """Drop mined tags that only matched as a substring of an unrelated word."""
    sample = body[:40000]
    return [tag for tag in tags
            if tag not in TAG_CONFIRM or TAG_CONFIRM[tag].search(sample)]


CATEGORY_SYNONYMS = {
    "crypto": "cryptography", "web": "web-exploitation",
    "pwn": "binary-exploitation", "rev": "reverse-engineering",
    "forensics": "forensic", "stego": "steganography", "misc": "miscellaneous",
    "osint": "open-source-intelligence", "mobile": "mobile-app",
    "hardware": "embedded", "blockchain": "smart-contract", "cloud": "cloud-security",
}
TAG_STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "from", "you", "your", "not",
    "are", "was", "can", "all", "but", "has", "its", "our", "out", "part",
    "cannot", "please", "just", "how", "why", "what", "when", "who", "into",
    "then", "than", "also", "over", "very", "here", "there", "make", "made",
    "does", "did", "will", "would", "should", "could", "let", "lets", "get",
    "got", "one", "two", "three", "four", "five", "day", "days", "day1",
}


def pad_tags(tags: list[str], category: str, subcategory: str, ctf: str,
             challenge: str, year: int | None, extra: Iterable[str] = (),
             floor: int = 6, limit: int = 20) -> list[str]:
    """The spec wants 6-20 tags; top up from metadata we already trust."""
    out = list(dict.fromkeys(t for t in tags if t))
    extras = [category, subcategory, CATEGORY_SYNONYMS.get(category, ""),
              slugify(challenge, 40) if challenge else "", slugify(ctf, 34)]
    extras += [slugify(str(e), 30) for e in extra if e]
    for word in re.split(r"[^A-Za-z0-9]+", f"{challenge} {ctf}"):
        token = word.lower()
        if len(token) > 2 and token not in TAG_STOPWORDS and not token.isdigit():
            extras.append(token)
    if year:
        extras.append(str(year))
    for extra in extras:
        if len(out) >= max(floor, len(tags)) and len(out) >= floor:
            break
        if extra and extra not in ("untitled", "") and extra not in out:
            out.append(extra)
    return out[:limit]


def choose_category(tags: list[str], *texts: str, stated: str = "") -> str:
    """Directory beats mined tags, mined tags beat raw prose keyword scoring."""
    if stated in CATEGORIES:
        return stated
    from_tags = categorise(tags=tags)
    if from_tags != "misc":
        return from_tags
    from_text = categorise(*texts)
    if from_text not in CATEGORIES:
        return "misc"
    if from_text in NARROW_CATEGORIES and not any(
            STRONG_SIGNALS.get(tag) == from_text for tag in tags):
        return "misc"
    return from_text


def find_difficulty(body: str) -> str:
    match = DIFFICULTY_RE.search(body[:4000])
    if not match:
        return ""
    value = match.group(1).lower()
    return {"very easy": "trivial", "very hard": "insane"}.get(value, value)


# ---------------------------------------------------------------------- verify
def verify(repos: tuple[str, ...]) -> list[dict]:
    known = {r["repo"]: r for r in (load_json(REPOS_JSON, []) or [])}
    out: list[dict] = []
    for repo in repos:
        raw = gh_api(f"repos/{repo}")
        if not raw:
            print(f"  {repo:<44} MISSING - skipped")
            continue
        try:
            meta = json.loads(raw)
        except Exception:                             # noqa: BLE001
            print(f"  {repo:<44} unparseable metadata - skipped")
            continue
        branch = meta.get("default_branch") or "main"
        head = gh_json(f"repos/{repo}/commits/{branch}")
        sha = (head or {}).get("sha") or branch
        name, year = _name_and_year(meta.get("name", repo.split("/")[-1]))
        record = {
            "repo": meta.get("full_name", repo),
            "stars": meta.get("stargazers_count", 0),
            "branch": branch,
            "sha": sha,
            "repo_ctf": name,
            "repo_year": year,
            "description": (meta.get("description") or "")[:200],
        }
        out.append(record)
        was = known.get(repo, {}).get("sha")
        flag = "" if was in (None, sha) else "  (head moved)"
        print(f"  {record['repo']:<44} stars={record['stars']:<6} {branch}@{sha[:8]}{flag}")
    save_json(REPOS_JSON, out)
    print(f"verify: {len(out)}/{len(repos)} repositories usable")
    return out


# ------------------------------------------------------------------------ tree
def collect_candidates() -> list[dict]:
    repos = load_json(REPOS_JSON, []) or []
    if not repos:
        print("nothing verified - run `verify` first")
        return []
    TREES.mkdir(parents=True, exist_ok=True)
    candidates: list[dict] = []

    for record in repos:
        repo, sha = record["repo"], record["sha"]
        cache = TREES / f"{slugify(repo, 60)}-{sha[:8]}.json"
        tree = load_json(cache)
        if tree is None:
            tree = gh_json(f"repos/{repo}/git/trees/{sha}?recursive=1")
            if not tree:
                print(f"  {repo:<44} tree fetch failed - skipped")
                continue
            save_json(cache, tree)
        blobs = [n for n in tree.get("tree", [])
                 if n.get("type") == "blob" and re.search(r"\.md$", n.get("path", ""), re.I)]

        repo_ctf = (record.get("repo_ctf") or "", record.get("repo_year"))
        # Group the generic-named files so one challenge yields one document.
        groups: dict[str, list[dict]] = {}
        for node in blobs:
            info = parse_path(node["path"], repo_ctf)
            if not info:
                continue
            entry = {
                "repo": repo, "sha": sha, "path": node["path"],
                "blob": node["sha"], "size": node.get("size", 0), **info,
            }
            groups.setdefault(f"{info['group']}|{info['challenge'].lower()}", []).append(entry)

        def rank(entry: dict) -> tuple[int, int]:
            # `chall/solution/README.md` is the writeup; `chall/README.md` next to
            # it is usually only the challenge description.
            wrappers = {p.lower() for p in entry["path"].split("/")[:-1]}
            return (1 if wrappers & {"solution", "solutions", "sol", "writeup",
                                     "writeups", "write-up", "wu"} else 0,
                    entry["size"])

        picked = [max(items, key=rank) for items in groups.values()]

        # Some authors keep both `Chall.md` and `Chall/README.md`; keep the longer.
        unique: dict[tuple[str, str, str], dict] = {}
        for entry in picked:
            key = (entry["ctf"].lower(), entry["category_dir"],
                   entry["challenge"].lower())
            if key[2] and (key not in unique or entry["size"] > unique[key]["size"]):
                unique[key] = entry
            elif not key[2]:
                unique[(entry["ctf"].lower(), entry["category_dir"],
                        entry["path"])] = entry
        picked = list(unique.values())

        # Round-robin over (ctf, category) buckets so no single event dominates.
        buckets: dict[tuple[str, str], list[dict]] = {}
        for entry in sorted(picked, key=lambda e: (-e["size"], e["path"])):
            buckets.setdefault((entry["ctf"].lower(), entry["category_dir"]), []).append(entry)
        for items in buckets.values():
            del items[PER_CTF_CAP:]

        order = sorted(buckets, key=lambda k: (-len(buckets[k]), k))
        chosen: list[dict] = []
        round_no = 0
        while len(chosen) < PER_REPO_CAP:
            added = False
            for key in order:
                items = buckets[key]
                if round_no < len(items):
                    chosen.append(items[round_no])
                    added = True
                    if len(chosen) >= PER_REPO_CAP:
                        break
            if not added:
                break
            round_no += 1

        candidates.extend(chosen)
        print(f"  {repo:<44} {len(blobs):>4} md -> {len(picked):>4} writeups"
              f" -> {len(chosen):>4} selected")

    save_json(CANDIDATES_JSON, candidates)
    print(f"tree: {len(candidates)} candidate writeups across {len(repos)} repositories")
    return candidates


# ----------------------------------------------------------------------- fetch
def fetch(limit: int, workers: int) -> int:
    candidates = (load_json(CANDIDATES_JSON, []) or [])[:limit]
    if not candidates:
        print("nothing to fetch - run `tree` first")
        return 0
    todo = [c for c in candidates if not blob_path(c["blob"]).exists()]
    print(f"fetch: {len(todo)} blobs to pull, {len(candidates) - len(todo)} cached")
    ok = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(gh_blob, c["repo"], c["blob"]): c for c in todo}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                if future.result():
                    ok += 1
            except Exception as exc:                  # noqa: BLE001
                print(f"    {futures[future]['path']}: {exc}")
            if i % 100 == 0:
                print(f"  {i}/{len(todo)} fetched  (rate credit ~{_RATE_STATE['remaining']})")
    print(f"fetch: {ok}/{len(todo)} new blobs stored")
    return ok


# ---------------------------------------------------------------------- render
def render(limit: int) -> dict:
    candidates = (load_json(CANDIDATES_JSON, []) or [])[:limit]
    by_repo: dict[str, int] = {}
    by_category: dict[str, int] = {}
    dropped: dict[str, int] = {}
    seen: set[Path] = set()
    written = 0

    for entry in candidates:
        try:
            body = gh_blob(entry["repo"], entry["blob"])
        except Exception as exc:                      # noqa: BLE001
            dropped[f"fetch-error"] = dropped.get("fetch-error", 0) + 1
            print(f"    {entry['path']}: {exc}")
            continue
        if not body:
            dropped["no-body"] = dropped.get("no-body", 0) + 1
            continue
        body = body.strip()

        # Scraped markdown is data, never instructions: bait is dropped, not followed.
        reason = looks_like_bait(body)
        if reason:
            dropped[reason.split(":")[0]] = dropped.get(reason.split(":")[0], 0) + 1
            continue
        if looks_like_index(body):
            dropped["link-index"] = dropped.get("link-index", 0) + 1
            continue

        repo, sha, path = entry["repo"], entry["sha"], entry["path"]
        challenge = entry.get("challenge") or ""
        ctf = entry.get("ctf") or ""
        year = entry.get("year")
        dirpath = "/".join(path.split("/")[:-1])

        tags = prune_tags(
            mine_tags(challenge, ctf, body[:16000],
                      extra=[t for t in (entry.get("category_dir"),) if t]), body)
        category = choose_category(tags, challenge, ctf, body[:10000],
                                   stated=entry.get("category_dir") or "")
        if category not in tags:
            tags.insert(0, category)
        subcategory = pick_subcategory(tags, category)
        tags = pad_tags(tags, category, subcategory, ctf, challenge, year,
                        extra=repo.split("/"))

        permalink = f"https://github.com/{repo}/blob/{sha}/" + quote(path, safe="/")
        summary = build_summary(body, challenge, ctf, category, tags)

        title_bits = challenge or (f"{ctf} writeups" if ctf else path)
        ctf_label = f"{ctf} {year}".strip() if year else ctf
        title = f"{title_bits} - {ctf_label}" if ctf_label and challenge else title_bits

        # A wholly non-ASCII name slugifies to nothing; fall back to the blob sha
        # so the file still has a stable, unique, identifiable name.
        ctf_slug = slugify(ctf, 34)
        challenge_slug = slugify(challenge, 44) if challenge else ""
        if challenge and challenge_slug in ("", "untitled"):
            challenge_slug = entry["blob"][:10]
        if ctf_slug in ("", "untitled"):
            ctf_slug = slugify(repo.split("/")[-1], 20)
        stem = "-".join(x for x in ("gh", slugify(repo.split("/")[0], 18),
                                    ctf_slug, challenge_slug) if x)
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
            f"- **Repository:** [{repo}](https://github.com/{repo})",
            f"- **File:** <{permalink}>",
            "", "---", "",
        ]

        frontmatter = {
            "title": title,
            "category": category,
            "subcategory": subcategory,
            "type": "writeup",
            "tags": tags,
            "difficulty": find_difficulty(body),
            "summary": summary,
            "source": {"name": repo, "url": permalink},
            "ctf": {"name": ctf, "year": year, "challenge": challenge},
        }
        try:
            write_doc(out_path, frontmatter,
                      "\n".join(meta)
                      + truncate(rewrite_links(body, repo, sha, dirpath), 1200, permalink))
        except Exception as exc:                      # noqa: BLE001
            dropped["write-error"] = dropped.get("write-error", 0) + 1
            print(f"    {path}: {exc}")
            continue

        written += 1
        by_repo[repo] = by_repo.get(repo, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1

    report = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "repositories": len(load_json(REPOS_JSON, []) or []),
        "candidates": len(candidates),
        "rendered": written,
        "by_repo": dict(sorted(by_repo.items(), key=lambda kv: -kv[1])),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "dropped": dict(sorted(dropped.items(), key=lambda kv: -kv[1])),
    }
    alpaca = load_json(CACHE / "alpacahack-report.json")
    if alpaca:
        report["alpacahack"] = alpaca
    save_json(REPORT_JSON, report)

    print(f"render: {written} documents")
    for repo, n in report["by_repo"].items():
        print(f"    {repo:<44} {n}")
    print()
    for category, n in report["by_category"].items():
        print(f"    {category:<12} {n}")
    if dropped:
        print(f"  dropped: {dropped}")
    return report


# ------------------------------------------------------------------------ main
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["verify", "tree", "fetch", "render", "all"])
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    CACHE.mkdir(parents=True, exist_ok=True)
    if args.command in ("verify", "all"):
        verify(REPOS)
    if args.command in ("tree", "all"):
        collect_candidates()
    if args.command in ("fetch", "all"):
        fetch(args.limit, args.workers)
    if args.command in ("render", "all"):
        render(args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
