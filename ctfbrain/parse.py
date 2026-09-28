"""Parse a CTF-Brain markdown document into a structured record.

Content is authored by many hands (and several ingestion pipelines), so this
parser is deliberately forgiving: it will salvage a document with slightly
malformed YAML rather than drop it from the index.  `ctfbrain lint` reports
whatever had to be salvaged.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a hard requirement at runtime
    yaml = None

from .config import CATEGORIES, CONTENT_DIR, DIFFICULTIES, DOC_TYPES

FM_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)
FENCE_RE = re.compile(r"^[ \t]*```([^\n`]*)\n(.*?)^[ \t]*```", re.DOTALL | re.MULTILINE)
TAGSPLIT_RE = re.compile(r"[,\s]+")


@dataclass
class Doc:
    """One indexed document."""

    slug: str
    path: str
    title: str
    category: str
    subcategory: str = ""
    type: str = "reference"
    tags: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    related: list[str] = field(default_factory=list)
    difficulty: str = ""
    summary: str = ""
    when_to_use: list[str] = field(default_factory=list)
    source_name: str = ""
    source_url: str = ""
    original_source: str = ""
    license: str = ""
    ctf_name: str = ""
    ctf_year: int | None = None
    ctf_challenge: str = ""
    body: str = ""
    headings: list[str] = field(default_factory=list)
    code: str = ""
    languages: list[str] = field(default_factory=list)
    n_lines: int = 0
    n_code_blocks: int = 0
    mtime: float = 0.0
    sha: str = ""
    problems: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- helpers

def _as_list(value: Any) -> list[str]:
    """Coerce a frontmatter value into a clean list of lowercase-kebab strings."""
    if value is None:
        return []
    if isinstance(value, str):
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1]
        parts = TAGSPLIT_RE.split(value)
    elif isinstance(value, (list, tuple, set)):
        parts = []
        for item in value:
            if isinstance(item, (list, tuple)):
                parts.extend(str(i) for i in item)
            else:
                parts.append(str(item))
    else:
        parts = [str(value)]
    out: list[str] = []
    for part in parts:
        cleaned = part.strip().strip("\"'`[]").lower()
        if cleaned and cleaned not in out:
            out.append(cleaned)
    return out


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(_as_text(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_as_text(v) for v in value.values())
    return str(value).strip()


def _fallback_yaml(raw: str) -> dict[str, Any]:
    """A last-resort line parser for frontmatter that PyYAML rejects.

    Handles the shapes our authors actually produce: `key: value`,
    `key: [a, b]`, nested one-level maps, and `- item` lists.
    """
    data: dict[str, Any] = {}
    current_key: str | None = None
    nested_key: str | None = None
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if stripped.startswith("- "):
            item = stripped[2:].strip().strip("\"'")
            if indent >= 2 and nested_key and isinstance(data.get(nested_key), dict):
                pass  # a list inside a nested map: not something we rely on
            elif current_key:
                data.setdefault(current_key, [])
                if isinstance(data[current_key], list):
                    data[current_key].append(item)
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip().strip("\"'")
        value = value.strip()
        if indent >= 2 and nested_key:
            parent = data.get(nested_key)
            if isinstance(parent, dict):
                parent[key] = value.strip("\"'")
            continue
        if not value:
            data[key] = []
            current_key, nested_key = key, key
            data[key] = {} if key in ("source", "ctf") else []
        else:
            data[key] = value.strip("\"'")
            current_key, nested_key = key, None
    return data


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str, list[str]]:
    """Return (frontmatter, body, problems)."""
    problems: list[str] = []
    match = FM_RE.match(text)
    if not match:
        return {}, text, ["no-frontmatter"]
    raw, body = match.group(1), match.group(2)
    data: Any = None
    if yaml is not None:
        try:
            data = yaml.safe_load(raw)
        except Exception as exc:  # noqa: BLE001 - we want every failure mode
            problems.append(f"yaml-error: {str(exc).splitlines()[0][:120]}")
    if not isinstance(data, dict):
        if data is not None and not problems:
            problems.append("frontmatter-not-a-mapping")
        data = _fallback_yaml(raw)
        if data:
            problems.append("salvaged-by-fallback-parser")
    return data, body, problems


def _derive_category(fm: dict[str, Any], path: Path) -> tuple[str, list[str]]:
    problems: list[str] = []
    category = _as_text(fm.get("category")).lower().strip()
    if category in CATEGORIES:
        return category, problems
    # Fall back to the directory the file lives in: content/<kind>/<category>/x.md
    for part in reversed(path.parts):
        if part.lower() in CATEGORIES:
            if category:
                problems.append(f"bad-category:{category}->{part.lower()}")
            else:
                problems.append("missing-category-inferred-from-path")
            return part.lower(), problems
    problems.append(f"unknown-category:{category or '<empty>'}")
    return "misc", problems


def _derive_type(fm: dict[str, Any], path: Path) -> tuple[str, list[str]]:
    problems: list[str] = []
    doctype = _as_text(fm.get("type")).lower().strip()
    if doctype in DOC_TYPES:
        return doctype, problems
    kind_dir = {
        "cheatsheets": "cheatsheet", "techniques": "technique", "scripts": "script",
        "writeups": "writeup", "playbooks": "playbook", "tools": "tool",
        "reference": "reference",
    }
    for part in path.parts:
        if part in kind_dir:
            if doctype:
                problems.append(f"bad-type:{doctype}->{kind_dir[part]}")
            else:
                problems.append("missing-type-inferred-from-path")
            return kind_dir[part], problems
    problems.append(f"unknown-type:{doctype or '<empty>'}")
    return "reference", problems


def make_slug(path: Path) -> str:
    """Stable, collision-free id: the content-relative path minus the suffix."""
    try:
        rel = path.resolve().relative_to(CONTENT_DIR.resolve())
    except ValueError:
        rel = Path(path.name)
    return str(rel.with_suffix("")).replace("/", ":")


def parse_file(path: Path) -> Doc:
    text = path.read_text(encoding="utf-8", errors="replace")
    fm, body, problems = parse_frontmatter(text)

    category, cat_problems = _derive_category(fm, path)
    doctype, type_problems = _derive_type(fm, path)
    problems += cat_problems + type_problems

    title = _as_text(fm.get("title")).strip('"')
    if not title:
        problems.append("missing-title")
        heading = HEADING_RE.search(body)
        title = heading.group(1).strip() if heading else path.stem.replace("-", " ").title()

    summary = _as_text(fm.get("summary"))
    if not summary:
        problems.append("missing-summary")
        for line in body.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "`", ">", "-", "|", "*")):
                summary = line[:200]
                break

    tags = _as_list(fm.get("tags"))
    if len(tags) < 3:
        problems.append(f"too-few-tags:{len(tags)}")

    difficulty = _as_text(fm.get("difficulty")).lower()
    if difficulty and difficulty not in DIFFICULTIES:
        problems.append(f"bad-difficulty:{difficulty}")
        difficulty = ""

    source = fm.get("source") or {}
    if isinstance(source, str):
        source = {"url": source} if source.startswith("http") else {"name": source}
    ctf = fm.get("ctf") or {}
    if isinstance(ctf, str):
        ctf = {"name": ctf}

    year_raw = _as_text(ctf.get("year")) if isinstance(ctf, dict) else ""
    year_match = re.search(r"(19|20)\d{2}", year_raw)
    ctf_year = int(year_match.group(0)) if year_match else None

    headings = [h.strip() for h in HEADING_RE.findall(body)]
    blocks = FENCE_RE.findall(body)
    languages = sorted({(lang.strip().lower().split()[0] if lang.strip() else "")
                        for lang, _ in blocks} - {""})
    code = "\n".join(src for _, src in blocks)

    when_to_use = fm.get("when_to_use") or fm.get("when-to-use") or []
    if isinstance(when_to_use, str):
        when_to_use = [when_to_use]
    when_to_use = [_as_text(w) for w in when_to_use if _as_text(w)]

    stat = path.stat()
    return Doc(
        slug=make_slug(path),
        path=str(path),
        title=title,
        category=category,
        subcategory=_as_text(fm.get("subcategory")).lower(),
        type=doctype,
        tags=tags,
        tools=_as_list(fm.get("tools")),
        cves=[c.upper() for c in _as_list(fm.get("cves"))],
        related=_as_list(fm.get("related")),
        difficulty=difficulty,
        summary=summary[:400],
        when_to_use=when_to_use,
        source_name=_as_text(source.get("name")) if isinstance(source, dict) else "",
        source_url=_as_text(source.get("url")) if isinstance(source, dict) else "",
        original_source=_as_text(fm.get("original_source")),
        license=_as_text(fm.get("license")),
        ctf_name=_as_text(ctf.get("name")) if isinstance(ctf, dict) else "",
        ctf_year=ctf_year,
        ctf_challenge=_as_text(ctf.get("challenge")) if isinstance(ctf, dict) else "",
        body=body,
        headings=headings,
        code=code,
        languages=languages,
        n_lines=body.count("\n") + 1,
        n_code_blocks=len(blocks),
        mtime=stat.st_mtime,
        sha=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16],
        problems=problems,
    )


def iter_content_files(root: Path | None = None):
    """Yield every markdown document in the content tree, deterministically."""
    base = root or CONTENT_DIR
    if not base.exists():
        return
    for path in sorted(base.rglob("*.md")):
        if any(part.startswith(".") for part in path.parts):
            continue
        yield path
