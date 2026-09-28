"""Query engine: FTS5 + synonym expansion + CTF-aware re-ranking."""
from __future__ import annotations

import re
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .config import (
    BM25_WEIGHTS, BONUS_EXACT_TAG, BONUS_SUBCATEGORY, BONUS_TITLE_SUB,
    CATEGORIES, DOC_TYPES, INDEX_DB, SNIPPET_TOKENS, TYPE_BONUS,
)
from .synonyms import expand, normalise

# `cat:crypto`, `type:cheatsheet`, `tag:rsa`, `diff:hard`, `ctf:sekai`, `lang:python`
FILTER_RE = re.compile(
    r"\b(cat|category|type|kind|tag|tags|diff|difficulty|ctf|tool|lang|year|source)"
    r":([^\s]+)", re.IGNORECASE)
PHRASE_RE = re.compile(r'"([^"]+)"')
TERM_RE = re.compile(r"[A-Za-z0-9_$.\-]+")

FILTER_ALIASES = {
    "category": "cat", "kind": "type", "tags": "tag", "difficulty": "diff",
}

BODY_COL = 5  # index of `body` among the FTS columns
CANDIDATE_WINDOW = 400  # rows pulled for Python-side re-ranking


@dataclass
class Hit:
    slug: str
    title: str
    category: str
    subcategory: str
    type: str
    difficulty: str
    summary: str
    tags: list[str]
    source_url: str
    source_name: str
    ctf_name: str
    ctf_year: int | None
    path: str
    n_lines: int
    score: float
    bm25: float
    snippet: str = ""
    why: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug, "title": self.title, "category": self.category,
            "subcategory": self.subcategory, "type": self.type,
            "difficulty": self.difficulty, "summary": self.summary, "tags": self.tags,
            "source_url": self.source_url, "source_name": self.source_name,
            "ctf_name": self.ctf_name, "ctf_year": self.ctf_year,
            "n_lines": self.n_lines, "score": round(self.score, 3),
            "snippet": self.snippet, "why": self.why,
        }


class Brain:
    """Read-only handle on the index.

    `ctfbrain index` writes a new database and renames it into place, so a
    long-running server would otherwise keep serving the old file through its
    open handle. Every query checks whether the file on disk has been replaced
    and reopens if so, which is what makes `make index` visible in a browser
    tab that is already open.
    """

    def __init__(self, db_path: Path | None = None):
        self.db_path = Path(db_path or INDEX_DB)
        if not self.db_path.exists():
            raise FileNotFoundError(
                f"No index at {self.db_path}. Build it with: ctfbrain index")
        self._lock = threading.Lock()
        self.conn = self._connect()

    def _connect(self) -> sqlite3.Connection:
        stat = self.db_path.stat()
        self._fingerprint = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_fresh(self) -> None:
        """Reopen if the index file has been replaced since we opened it."""
        try:
            stat = self.db_path.stat()
        except OSError:
            return                      # mid-rename; the current handle still works
        if (stat.st_ino, stat.st_mtime_ns, stat.st_size) == self._fingerprint:
            return
        with self._lock:
            try:
                stat = self.db_path.stat()
            except OSError:
                return
            if (stat.st_ino, stat.st_mtime_ns, stat.st_size) == self._fingerprint:
                return
            old = self.conn
            try:
                self.conn = self._connect()
            except sqlite3.Error:
                return                  # keep serving the old index rather than 500
            try:
                old.close()
            except sqlite3.Error:
                pass

    # ------------------------------------------------------------ query build
    @staticmethod
    def parse_filters(query: str) -> tuple[str, dict[str, list[str]]]:
        """Pull `key:value` filters out of the query, returning (rest, filters)."""
        filters: dict[str, list[str]] = {}
        for match in FILTER_RE.finditer(query):
            key = match.group(1).lower()
            key = FILTER_ALIASES.get(key, key)
            filters.setdefault(key, []).append(match.group(2).lower().strip(",")) 
        rest = FILTER_RE.sub(" ", query).strip()
        return rest, filters

    @staticmethod
    def build_match(text: str, use_synonyms: bool = True) -> tuple[str, list[str], list[str]]:
        """Return (fts_match_expression, user_terms, expansion_terms)."""
        phrases = PHRASE_RE.findall(text)
        without_phrases = PHRASE_RE.sub(" ", text)
        terms = [t.lower() for t in TERM_RE.findall(without_phrases) if len(t) > 1]
        expansions = expand(text) if use_synonyms else []

        clauses: list[str] = []
        for phrase in phrases:
            cleaned = phrase.replace('"', " ").strip()
            if cleaned:
                clauses.append(f'"{cleaned}"')

        exp_norm = {normalise(e): e for e in expansions}
        for term in terms:
            group = [f'"{term}"', f'"{term}"*']
            # Attach only the expansions this particular term implies.
            for extra in expand(term):
                if normalise(extra) != normalise(term):
                    group.append(f'"{extra}"')
                    exp_norm.pop(normalise(extra), None)
            clauses.append("(" + " OR ".join(dict.fromkeys(group)) + ")")

        if not clauses and exp_norm:
            clauses.append("(" + " OR ".join(f'"{e}"' for e in exp_norm.values()) + ")")

        match = " AND ".join(clauses) if clauses else ""
        # Phrase-level expansions (e.g. "crypto attack") widen the whole query.
        if match and exp_norm:
            extra = " OR ".join(f'"{e}"' for e in exp_norm.values())
            match = f"({match}) OR ({extra})"
        return match, terms + [p.lower() for p in phrases], expansions

    @staticmethod
    def _filter_sql(filters: dict[str, list[str]],
                    category: str | None, doctype: str | None,
                    tags: Iterable[str] | None, difficulty: str | None
                    ) -> tuple[str, list[Any]]:
        where: list[str] = []
        params: list[Any] = []

        def add_in(column: str, values: list[str]) -> None:
            values = [v for v in values if v]
            if not values:
                return
            where.append(f"d.{column} IN ({','.join('?' * len(values))})")
            params.extend(values)

        cats = list(filters.get("cat", []))
        if category:
            cats.append(category.lower())
        add_in("category", [c for c in cats if c in CATEGORIES])

        types = list(filters.get("type", []))
        if doctype:
            types.append(doctype.lower())
        add_in("type", [t for t in types if t in DOC_TYPES])

        diffs = list(filters.get("diff", []))
        if difficulty:
            diffs.append(difficulty.lower())
        add_in("difficulty", diffs)

        for value in filters.get("ctf", []):
            where.append("lower(d.ctf_name) LIKE ?")
            params.append(f"%{value}%")
        for value in filters.get("source", []):
            where.append("(lower(d.source_name) LIKE ? OR lower(d.source_url) LIKE ?)")
            params.extend([f"%{value}%", f"%{value}%"])
        for value in filters.get("tool", []):
            where.append("(' ' || d.tools_text || ' ') LIKE ?")
            params.append(f"% {value} %")
        for value in filters.get("lang", []):
            where.append("(' ' || d.languages_text || ' ') LIKE ?")
            params.append(f"% {value} %")
        for value in filters.get("year", []):
            if value.isdigit():
                where.append("d.ctf_year = ?")
                params.append(int(value))

        all_tags = list(filters.get("tag", [])) + list(tags or [])
        for tag in all_tags:
            where.append("EXISTS (SELECT 1 FROM doc_tags dt WHERE dt.doc_id = d.id AND dt.tag = ?)")
            params.append(tag.lower())

        return (" AND " + " AND ".join(where) if where else ""), params

    # ---------------------------------------------------------------- search
    def search(self, query: str, *, category: str | None = None,
               doctype: str | None = None, tags: Iterable[str] | None = None,
               difficulty: str | None = None, limit: int = 20, offset: int = 0,
               synonyms: bool = True) -> tuple[list[Hit], int]:
        """Return (hits, total_matches)."""
        self._ensure_fresh()
        text, filters = self.parse_filters(query or "")
        match, terms, expansions = self.build_match(text, use_synonyms=synonyms)
        where_sql, where_params = self._filter_sql(
            filters, category, doctype, tags, difficulty)

        if not match:
            return self._browse(where_sql, where_params, limit, offset)

        weights = ", ".join(str(w) for w in BM25_WEIGHTS)
        # Two phases, because `snippet()` costs ~0.5ms per row: rank a bounded
        # candidate window on metadata only, then generate snippets for the handful
        # of rows actually being returned.
        window = max(CANDIDATE_WINDOW, offset + limit + 100)
        sql = f"""
            SELECT d.id, d.slug, d.title, d.category, d.subcategory, d.type,
                   d.difficulty, d.summary, d.tags_text, d.source_url, d.source_name,
                   d.ctf_name, d.ctf_year, d.path, d.n_lines,
                   bm25(docs_fts, {weights}) AS bm
            FROM docs_fts
            JOIN docs d ON d.id = docs_fts.rowid
            WHERE docs_fts MATCH ?{where_sql}
            ORDER BY bm
            LIMIT ?
        """
        count_sql = f"""
            SELECT COUNT(*) FROM docs_fts JOIN docs d ON d.id = docs_fts.rowid
            WHERE docs_fts MATCH ?{where_sql}
        """

        def run(expression: str) -> tuple[list[sqlite3.Row], int]:
            rows = self.conn.execute(sql, [expression, *where_params, window]).fetchall()
            if len(rows) < window:
                return rows, len(rows)
            total = self.conn.execute(count_sql, [expression, *where_params]).fetchone()[0]
            return rows, total

        used = match
        try:
            rows, total = run(match)
        except sqlite3.OperationalError:
            # Malformed FTS expression (a stray operator in user input): retry literally.
            used = " OR ".join(f'"{t}"' for t in terms) or '""'
            try:
                rows, total = run(used)
            except sqlite3.OperationalError:
                rows, total = [], 0

        if not rows and terms:
            # AND was too strict, so fall back to OR over everything we know.
            used = " OR ".join(f'"{t}"*' for t in terms)
            if expansions:
                used += " OR " + " OR ".join(f'"{e}"' for e in expansions)
            try:
                rows, total = run(used)
            except sqlite3.OperationalError:
                rows, total = [], 0

        hits = [self._rank(row, terms) for row in rows]
        hits.sort(key=lambda h: -h.score)
        page = hits[offset:offset + limit]
        self._attach_snippets(page, used)
        return page, total

    def _attach_snippets(self, hits: list[Hit], match: str) -> None:
        """Fill in highlighted snippets for just the hits being returned."""
        if not hits or not match:
            return
        ids = {h.slug: None for h in hits}
        placeholders = ",".join("?" * len(hits))
        try:
            rows = self.conn.execute(f"""
                SELECT d.slug AS slug,
                       snippet(docs_fts, {BODY_COL}, '\x02', '\x03', ' … ', {SNIPPET_TOKENS}) AS snip
                FROM docs_fts JOIN docs d ON d.id = docs_fts.rowid
                WHERE docs_fts MATCH ? AND d.slug IN ({placeholders})
            """, [match, *ids]).fetchall()
        except sqlite3.OperationalError:
            return
        found = {r["slug"]: r["snip"] for r in rows}
        for hit in hits:
            snip = found.get(hit.slug)
            if not snip:
                continue
            snip = snip.replace("\x02", "«").replace("\x03", "»")
            hit.snippet = re.sub(r"\s+", " ", snip).strip() or hit.snippet

    def _rank(self, row: sqlite3.Row, terms: list[str]) -> Hit:
        tags = (row["tags_text"] or "").split()
        title_l = (row["title"] or "").lower()
        subcat = (row["subcategory"] or "").lower()
        score = -float(row["bm"])
        why: list[str] = []

        norm_tags = {normalise(t) for t in tags}
        for term in terms:
            nt = normalise(term)
            if not nt:
                continue
            if nt in norm_tags:
                score += BONUS_EXACT_TAG
                why.append(f"tag:{term}")
            if term in title_l:
                score += BONUS_TITLE_SUB
                why.append(f"title:{term}")
            if nt and nt == normalise(subcat):
                score += BONUS_SUBCATEGORY
                why.append(f"subcat:{term}")

        bonus = TYPE_BONUS.get(row["type"], 0.0)
        score += bonus
        if bonus >= 2.0:
            why.append(row["type"])

        return Hit(
            slug=row["slug"], title=row["title"], category=row["category"],
            subcategory=row["subcategory"] or "", type=row["type"],
            difficulty=row["difficulty"] or "", summary=row["summary"] or "",
            tags=tags, source_url=row["source_url"] or "",
            source_name=row["source_name"] or "", ctf_name=row["ctf_name"] or "",
            ctf_year=row["ctf_year"], path=row["path"], n_lines=row["n_lines"] or 0,
            score=score, bm25=float(row["bm"]),
            snippet=(row["summary"] or "")[:240],
            why=list(dict.fromkeys(why))[:5],
        )

    def _browse(self, where_sql: str, params: list[Any],
                limit: int, offset: int) -> tuple[list[Hit], int]:
        """No search terms: list documents matching the filters alone."""
        base = f"FROM docs d WHERE 1=1{where_sql}"
        total = self.conn.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
        rows = self.conn.execute(f"""
            SELECT d.id, d.slug, d.title, d.category, d.subcategory, d.type,
                   d.difficulty, d.summary, d.tags_text, d.source_url, d.source_name,
                   d.ctf_name, d.ctf_year, d.path, d.n_lines, 0.0 AS bm
            {base}
            ORDER BY CASE d.type
                       WHEN 'playbook' THEN 0 WHEN 'cheatsheet' THEN 1
                       WHEN 'technique' THEN 2 WHEN 'script' THEN 3
                       WHEN 'tool' THEN 4 WHEN 'reference' THEN 5 ELSE 6 END,
                     d.title
            LIMIT ? OFFSET ?
        """, [*params, limit, offset]).fetchall()
        return [self._rank(r, []) for r in rows], total

    # ------------------------------------------------------------- retrieval
    def get(self, slug: str) -> dict | None:
        self._ensure_fresh()
        row = self.conn.execute("SELECT * FROM docs WHERE slug = ?", (slug,)).fetchone()
        if row is None:
            row = self.conn.execute(
                "SELECT * FROM docs WHERE slug LIKE ? ORDER BY length(slug) LIMIT 1",
                (f"%{slug}",)).fetchone()
        if row is None:
            return None
        doc = dict(row)
        doc["tags"] = (doc.pop("tags_text") or "").split()
        doc["tools"] = (doc.pop("tools_text") or "").split()
        doc["cves"] = (doc.pop("cves_text") or "").split()
        doc["related_slugs"] = (doc.pop("related_text") or "").split()
        doc["when_to_use"] = [l for l in (doc.pop("when_text") or "").split("\n") if l]
        doc["languages"] = (doc.pop("languages_text") or "").split()
        doc.pop("headings_text", None)
        return doc

    def related(self, slug: str, limit: int = 10) -> list[dict]:
        """Documents sharing tags, topped up with same-subcategory then same-category.

        Tag overlap is the strongest signal, but a freshly written page may not
        share a tag with anything yet, and falling back keeps the panel useful.
        """
        self._ensure_fresh()
        row = self.conn.execute(
            "SELECT id, tags_text, category, subcategory FROM docs WHERE slug = ?",
            (slug,)).fetchone()
        if row is None:
            return []

        out: list[dict] = []
        seen: set[str] = set()

        def take(rows: Iterable[sqlite3.Row]) -> None:
            for r in rows:
                if len(out) >= limit:
                    return
                if r["slug"] in seen:
                    continue
                seen.add(r["slug"])
                out.append({k: r[k] for k in ("slug", "title", "category", "type", "summary")})

        tags = (row["tags_text"] or "").split()
        if tags:
            placeholders = ",".join("?" * len(tags))
            take(self.conn.execute(f"""
                SELECT d.slug, d.title, d.category, d.type, d.summary,
                       COUNT(*) AS shared
                FROM doc_tags dt JOIN docs d ON d.id = dt.doc_id
                WHERE dt.tag IN ({placeholders}) AND d.id != ?
                GROUP BY d.id
                ORDER BY shared DESC, (d.category = ?) DESC, d.title
                LIMIT ?
            """, [*tags, row["id"], row["category"], limit]))

        if len(out) < limit and row["subcategory"]:
            take(self.conn.execute("""
                SELECT slug, title, category, type, summary FROM docs
                WHERE subcategory = ? AND category = ? AND id != ?
                ORDER BY CASE type WHEN 'playbook' THEN 0 WHEN 'cheatsheet' THEN 1
                                   WHEN 'technique' THEN 2 ELSE 3 END, title
                LIMIT ?
            """, [row["subcategory"], row["category"], row["id"], limit]))

        if len(out) < limit:
            take(self.conn.execute("""
                SELECT slug, title, category, type, summary FROM docs
                WHERE category = ? AND id != ?
                ORDER BY CASE type WHEN 'playbook' THEN 0 WHEN 'cheatsheet' THEN 1
                                   WHEN 'technique' THEN 2 ELSE 3 END, title
                LIMIT ?
            """, [row["category"], row["id"], limit]))

        return out

    def tags(self, category: str | None = None, limit: int = 400) -> list[dict]:
        self._ensure_fresh()
        sql = """
            SELECT dt.tag AS tag, COUNT(*) AS n
            FROM doc_tags dt JOIN docs d ON d.id = dt.doc_id
            {where}
            GROUP BY dt.tag ORDER BY n DESC, dt.tag LIMIT ?
        """
        params: list[Any] = []
        where = ""
        if category:
            where = "WHERE d.category = ?"
            params.append(category)
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql.format(where=where), params)]

    def facets(self, query: str = "") -> dict:
        """Category/type counts for the current result set (drives the UI sidebar)."""
        self._ensure_fresh()
        text, filters = self.parse_filters(query or "")
        match, _, _ = self.build_match(text)
        if match:
            try:
                rows = self.conn.execute("""
                    SELECT d.category, d.type FROM docs_fts
                    JOIN docs d ON d.id = docs_fts.rowid WHERE docs_fts MATCH ?
                """, (match,)).fetchall()
            except sqlite3.OperationalError:
                rows = []
        else:
            rows = self.conn.execute("SELECT category, type FROM docs").fetchall()
        cats: dict[str, int] = {}
        types: dict[str, int] = {}
        for row in rows:
            cats[row["category"]] = cats.get(row["category"], 0) + 1
            types[row["type"]] = types.get(row["type"], 0) + 1
        return {"categories": cats, "types": types, "total": len(rows)}

    def stats(self) -> dict:
        self._ensure_fresh()
        conn = self.conn
        out: dict[str, Any] = {
            "documents": conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0],
            "total_lines": conn.execute("SELECT COALESCE(SUM(n_lines),0) FROM docs").fetchone()[0],
            "code_blocks": conn.execute("SELECT COALESCE(SUM(n_code_blocks),0) FROM docs").fetchone()[0],
            "unique_tags": conn.execute("SELECT COUNT(DISTINCT tag) FROM doc_tags").fetchone()[0],
            "ctfs": conn.execute(
                "SELECT COUNT(DISTINCT ctf_name) FROM docs WHERE ctf_name != ''").fetchone()[0],
            "sources": conn.execute(
                "SELECT COUNT(DISTINCT source_name) FROM docs WHERE source_name != ''").fetchone()[0],
        }
        out["by_category"] = {r["category"]: r["n"] for r in conn.execute(
            "SELECT category, COUNT(*) n FROM docs GROUP BY category ORDER BY n DESC")}
        out["by_type"] = {r["type"]: r["n"] for r in conn.execute(
            "SELECT type, COUNT(*) n FROM docs GROUP BY type ORDER BY n DESC")}
        out["by_difficulty"] = {r["difficulty"]: r["n"] for r in conn.execute(
            "SELECT difficulty, COUNT(*) n FROM docs WHERE difficulty != '' GROUP BY difficulty")}
        out["top_ctfs"] = {r["ctf_name"]: r["n"] for r in conn.execute(
            "SELECT ctf_name, COUNT(*) n FROM docs WHERE ctf_name != ''"
            " GROUP BY ctf_name ORDER BY n DESC LIMIT 25")}
        return out

    def random(self, category: str | None = None, doctype: str | None = None) -> dict | None:
        self._ensure_fresh()
        where, params = [], []
        if category:
            where.append("category = ?")
            params.append(category)
        if doctype:
            where.append("type = ?")
            params.append(doctype)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        row = self.conn.execute(
            f"SELECT slug FROM docs {clause} ORDER BY RANDOM() LIMIT 1", params).fetchone()
        return self.get(row["slug"]) if row else None

    def problems(self) -> list[dict]:
        self._ensure_fresh()
        try:
            return [dict(r) for r in self.conn.execute("""
                SELECT d.slug, d.path, dp.problem
                FROM doc_problems dp JOIN docs d ON d.id = dp.doc_id
                ORDER BY d.path
            """)]
        except sqlite3.OperationalError as exc:
            raise RuntimeError(
                "This index predates the current schema (or was written by a "
                "concurrent build). Re-run: ctfbrain index"
            ) from exc

    def close(self) -> None:
        self.conn.close()
