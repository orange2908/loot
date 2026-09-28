"""Build the SQLite FTS5 search index from the content tree."""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from collections import Counter
from pathlib import Path

from .config import CONTENT_DIR, INDEX_DB
from .parse import Doc, iter_content_files, parse_file

SCHEMA = """
PRAGMA journal_mode = WAL;

DROP TABLE IF EXISTS docs_fts;
DROP TABLE IF EXISTS docs;
DROP TABLE IF EXISTS doc_tags;
DROP TABLE IF EXISTS doc_problems;
DROP TABLE IF EXISTS meta;

CREATE TABLE docs (
    id              INTEGER PRIMARY KEY,
    slug            TEXT UNIQUE NOT NULL,
    path            TEXT NOT NULL,
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,
    subcategory     TEXT,
    type            TEXT NOT NULL,
    difficulty      TEXT,
    summary         TEXT,
    tags_text       TEXT,
    tools_text      TEXT,
    cves_text       TEXT,
    related_text    TEXT,
    when_text       TEXT,
    headings_text   TEXT,
    source_name     TEXT,
    source_url      TEXT,
    original_source TEXT,
    license         TEXT,
    ctf_name        TEXT,
    ctf_year        INTEGER,
    ctf_challenge   TEXT,
    body            TEXT,
    code            TEXT,
    languages_text  TEXT,
    n_lines         INTEGER,
    n_code_blocks   INTEGER,
    mtime           REAL,
    sha             TEXT
);

CREATE INDEX idx_docs_category ON docs(category);
CREATE INDEX idx_docs_type     ON docs(type);
CREATE INDEX idx_docs_subcat   ON docs(subcategory);
CREATE INDEX idx_docs_diff     ON docs(difficulty);
CREATE INDEX idx_docs_ctf      ON docs(ctf_name);

CREATE TABLE doc_tags (
    doc_id INTEGER NOT NULL REFERENCES docs(id) ON DELETE CASCADE,
    tag    TEXT NOT NULL
);
CREATE INDEX idx_doc_tags_tag ON doc_tags(tag);
CREATE INDEX idx_doc_tags_doc ON doc_tags(doc_id);

CREATE TABLE doc_problems (
    doc_id  INTEGER NOT NULL REFERENCES docs(id) ON DELETE CASCADE,
    problem TEXT NOT NULL
);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);

-- External-content FTS5: column names must match the `docs` columns above.
CREATE VIRTUAL TABLE docs_fts USING fts5(
    title, tags_text, summary, when_text, headings_text, body, code,
    content='docs', content_rowid='id',
    tokenize="unicode61 remove_diacritics 2 tokenchars '_-$.'"
);
"""

FTS_COLUMNS = ("title", "tags_text", "summary", "when_text", "headings_text", "body", "code")


def check_fts5(conn: sqlite3.Connection) -> None:
    opts = {row[0] for row in conn.execute("PRAGMA compile_options")}
    has = any("FTS5" in o for o in opts)
    if not has:
        try:
            conn.execute("CREATE VIRTUAL TABLE __fts5_probe USING fts5(x)")
            conn.execute("DROP TABLE __fts5_probe")
        except sqlite3.OperationalError as exc:
            raise RuntimeError(
                "This Python's SQLite lacks FTS5 support, which CTF-Brain requires.\n"
                "Fix: use the provided Docker image (`make docker-up`), or install a "
                "Python built against a full SQLite (e.g. `brew install python`)."
            ) from exc


def _row(doc: Doc) -> tuple:
    return (
        doc.slug, doc.path, doc.title, doc.category, doc.subcategory, doc.type,
        doc.difficulty, doc.summary,
        " ".join(doc.tags), " ".join(doc.tools), " ".join(doc.cves), " ".join(doc.related),
        "\n".join(doc.when_to_use), "\n".join(doc.headings),
        doc.source_name, doc.source_url, doc.original_source, doc.license,
        doc.ctf_name, doc.ctf_year, doc.ctf_challenge,
        doc.body, doc.code, " ".join(doc.languages),
        doc.n_lines, doc.n_code_blocks, doc.mtime, doc.sha,
    )


INSERT_SQL = """
INSERT INTO docs (
    slug, path, title, category, subcategory, type, difficulty, summary,
    tags_text, tools_text, cves_text, related_text, when_text, headings_text,
    source_name, source_url, original_source, license,
    ctf_name, ctf_year, ctf_challenge, body, code, languages_text,
    n_lines, n_code_blocks, mtime, sha
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


def build(content_dir: Path | None = None, db_path: Path | None = None,
          verbose: bool = True) -> dict:
    """Rebuild the index from scratch. Returns a stats dict."""
    content_dir = content_dir or CONTENT_DIR
    db_path = db_path or INDEX_DB
    db_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.time()
    # A unique temp name per process: an ingestion pipeline and a manual
    # `ctfbrain index` can legitimately run at the same time, and a shared
    # filename let one rename a half-built database over the other's work.
    tmp_path = db_path.with_suffix(f".building.{os.getpid()}.{uuid.uuid4().hex[:8]}")

    conn = sqlite3.connect(tmp_path)
    check_fts5(conn)
    conn.executescript(SCHEMA)

    stats: Counter = Counter()
    by_category: Counter = Counter()
    by_type: Counter = Counter()
    tag_counts: Counter = Counter()
    problem_counts: Counter = Counter()
    seen_slugs: set[str] = set()
    errors: list[str] = []

    for path in iter_content_files(content_dir):
        try:
            doc = parse_file(path)
        except Exception as exc:  # noqa: BLE001 - one bad file must not stop the build
            errors.append(f"{path}: {exc}")
            stats["failed"] += 1
            continue

        if doc.slug in seen_slugs:
            errors.append(f"{path}: duplicate slug {doc.slug}")
            stats["duplicate"] += 1
            continue
        seen_slugs.add(doc.slug)

        cur = conn.execute(INSERT_SQL, _row(doc))
        doc_id = cur.lastrowid
        if doc.tags:
            conn.executemany(
                "INSERT INTO doc_tags(doc_id, tag) VALUES (?,?)",
                [(doc_id, t) for t in doc.tags],
            )
            tag_counts.update(doc.tags)
        if doc.problems:
            conn.executemany(
                "INSERT INTO doc_problems(doc_id, problem) VALUES (?,?)",
                [(doc_id, p) for p in doc.problems],
            )
            problem_counts.update(p.split(":")[0] for p in doc.problems)

        stats["indexed"] += 1
        stats["lines"] += doc.n_lines
        stats["code_blocks"] += doc.n_code_blocks
        by_category[doc.category] += 1
        by_type[doc.type] += 1

        if verbose and stats["indexed"] % 500 == 0:
            print(f"  ... {stats['indexed']} documents", flush=True)

    # Populate the FTS index from the now-complete docs table.
    cols = ", ".join(FTS_COLUMNS)
    conn.execute(f"INSERT INTO docs_fts(rowid, {cols}) SELECT id, {cols} FROM docs")
    conn.execute("INSERT INTO docs_fts(docs_fts) VALUES('optimize')")

    summary = {
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "duration_s": round(time.time() - started, 2),
        "documents": stats["indexed"],
        "failed": stats["failed"],
        "duplicates": stats["duplicate"],
        "total_lines": stats["lines"],
        "code_blocks": stats["code_blocks"],
        "unique_tags": len(tag_counts),
        "by_category": dict(by_category.most_common()),
        "by_type": dict(by_type.most_common()),
        "top_tags": dict(tag_counts.most_common(60)),
        "problems": dict(problem_counts.most_common()),
        "errors": errors[:50],
    }
    conn.executemany(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?,?)",
        [(k, json.dumps(v)) for k, v in summary.items()],
    )
    conn.commit()
    conn.execute("VACUUM")
    conn.close()

    for suffix in ("-wal", "-shm"):
        stale = Path(str(tmp_path) + suffix)
        if stale.exists():
            stale.unlink()
    tmp_path.replace(db_path)          # atomic: readers never see a partial index
    return summary


def load_meta(db_path: Path | None = None) -> dict:
    db_path = db_path or INDEX_DB
    if not db_path.exists():
        return {}
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return {k: json.loads(v) for k, v in conn.execute("SELECT key, value FROM meta")}
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
