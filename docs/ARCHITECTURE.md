# Architecture

CTF-Brain is a small, boring, single-process application. That is deliberate: it has
to start instantly and work on an air-gapped laptop during a competition.

```
                 content/**/*.md
                        │
                  parse.py            YAML frontmatter + body -> Doc
                        │
                  index.py            SQLite: docs + doc_tags + docs_fts (FTS5)
                        │
                        ▼
                  data/index.db
                        │
        ┌───────────────┴───────────────┐
        │                               │
   search.py                       render.py
   FTS5 + BM25 + synonyms          markdown -> HTML + Pygments
        │                               │
   ┌────┴────┐                     ┌────┴────┐
   │         │                     │         │
 cli.py   api.py ──────────────────┘    web/static/app.js
 (rich)   (FastAPI)                     (vanilla JS SPA)
```

## Modules

| Module | Responsibility |
|---|---|
| `config.py` | Paths, the 12 categories, the 7 document types, ranking weights |
| `parse.py` | Markdown + frontmatter -> `Doc`. Tolerant: salvages malformed YAML and reports why |
| `index.py` | Builds `data/index.db` from scratch, atomically |
| `synonyms.py` | ~220 trigger terms and ~37 phrases that map symptoms onto corpus vocabulary |
| `search.py` | `Brain`: query parsing, FTS5 matching, re-ranking, facets, related documents |
| `render.py` | markdown-it-py + Pygments, server-side. Two themes in one stylesheet |
| `cli.py` | the `ctfbrain` command, built on argparse + rich |
| `api.py` | FastAPI: the JSON API plus the SPA shell |
| `web/` | `index.html`, `app.js`, `style.css`. No build step, no CDN |

## Index schema

`docs` holds one row per document, including the full body and a concatenation of all
code blocks. `docs_fts` is an **external-content** FTS5 table over `docs`, so the text
is stored once and `snippet()` still works.

```sql
CREATE VIRTUAL TABLE docs_fts USING fts5(
    title, tags_text, summary, when_text, headings_text, body, code,
    content='docs', content_rowid='id',
    tokenize="unicode61 remove_diacritics 2 tokenchars '_-$.'"
);
```

The `tokenchars` setting is load-bearing. Without it, `__free_hook`, `batch-gcd`,
`$ne` and `169.254.169.254` would each be split into fragments and become unsearchable
as written. With it they are single tokens and match exactly.

`doc_tags(doc_id, tag)` is a separate indexed table, which makes `tag:` filters and the
tag facet a cheap index lookup rather than a `LIKE` scan.

`doc_problems(doc_id, problem)` records everything `parse.py` had to salvage; that is
what `ctfbrain lint` reports.

The build writes to `data/index.building` and renames it into place on success, so a
failed or interrupted rebuild never leaves you without a working index.

## Ranking

1. **BM25** over the seven FTS columns with per-column weights (`config.BM25_WEIGHTS`):
   title 12, tags 10, summary 6, when_to_use 5, headings 3, body 1, code 0.7.
   Metadata is weighted far above prose because an author's tags are a much stronger
   statement of what a page is about than an incidental mention in the body.
2. **Post-BM25 bonuses** (`config.py`):
   - `+6` when a query term is verbatim one of the document's tags
   - `+4` when it appears in the title
   - `+2` when it matches the subcategory
   - a type bonus: playbook `+3`, cheatsheet `+2.5`, technique `+2`, script `+1.5`,
     tool `+1`, reference `+0.5`, writeup `0`

The type bonus encodes the core assumption: mid-CTF you want the decision tree and the
cheatsheet before you want someone else's narrative writeup. `why` on each hit reports
which bonuses fired, so ranking is explainable rather than mysterious.

## Query construction

`Brain.build_match` turns human input into an FTS5 expression:

- `key:value` filters are stripped out first and become SQL `WHERE` clauses.
- Each remaining term becomes `("term" OR "term"* OR <its synonyms>)`.
- Those groups are `AND`-ed, so multi-word queries stay precise.
- Phrase-level expansions (from `PHRASES`) are `OR`-ed onto the whole query.
- If the `AND` returns nothing, it retries as a pure `OR`. A ranked long list beats
  than an empty page.
- A malformed expression (a stray quote or operator from the user) is caught and
  retried literally, so the search box can never 500.

## Request flow (web)

1. `GET /` returns the SPA shell. The client fetches `/api/stats` and `/api/tags` once.
2. Typing debounces 130ms, then `GET /api/search?q=...`. A sequence number discards
   responses that a newer keystroke has already superseded.
3. Clicking a result pushes `/doc/<slug>` and fetches `/api/doc/<slug>`, which returns
   metadata, pre-rendered HTML, a table of contents and related documents.
4. Back/forward are handled by `popstate`, so deep links and history work normally.

## Deliberate non-choices

- **No build step.** The UI is three static files. It must still work in five years.
- **No client-side markdown or highlighting library.** Rendering server-side keeps the
  page dependency-free and means no CDN at view time.
- **No incremental indexing.** A full rebuild over thousands of documents takes a few
  seconds; incremental invalidation would be more code and more ways to be subtly wrong.
- **No auth, no multi-user.** It is a personal reference tool on localhost.
