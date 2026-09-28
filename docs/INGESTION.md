# Ingestion

The pipelines in `ingest/` pull public CTF material into `content/` and normalize it to
the format in `CONTENT_SPEC.md`. They are all **resumable, cached and crash-proof**:
re-running one only fetches what is new, and a single bad page is logged and skipped
rather than aborting the run.

## Pipelines

| Script | Source | Output |
|---|---|---|
| `ingest/ctftime.py` | ctftime.org writeup index + the external writeups it links to | `content/writeups/<cat>/ctftime-*.md` |
| `ingest/github_writeups.py` | public CTF team writeup repositories | `content/writeups/<cat>/gh-*.md` |
| `ingest/alpacahack.py` | the Daily_AlpacaHack collection | `content/writeups/<cat>/alpacahack-*.md` |
| `ingest/reference_corpora.py` | CTF Wiki, HackTricks, PayloadsAllTheThings, OWASP WSTG | `content/reference/ext-*.md`, `content/techniques/<cat>/ext-*.md` |
| `ingest/vendor_scripts.py` | upstream attack-script repos | `vendor/` + `content/scripts/<cat>/vendor-*.md` |
| `ingest/challenge_repos.py` | repos by the people who *set* the challenges | `content/writeups/<cat>/chal-*.md` |
| `ingest/local_notes.py` | a local folder of your own markdown notes | `content/*/<cat>/notes-*.md` |

Each has a `README-*.md` next to it with its own specifics.

## Running them

```bash
make ingest            # everything, then reindex
make ingest-ctftime
make ingest-github
make ingest-corpora
make ingest-vendor

python3 ingest/ctftime.py all --pages 60     # or drive one directly
```

Caches live under `data/raw/<source>/` and are gitignored. Delete a cache directory to
force a full refetch.

## Conventions every pipeline follows

**Filename prefixes** keep sources from colliding, since several pipelines write into the
same directories: `ctftime-`, `gh-`, `alpacahack-`, `ext-`, `vendor-`, `chal-`, `notes-`.

**Attribution is mandatory.** Every emitted document carries a `source:` block with a
working permalink, and `original_source:` when the content came from somewhere the
aggregator merely linked to.

**Never fabricate.** If a body cannot be fetched, the pipeline either skips the document
or emits a stub that says only metadata was available. It never invents a solution, a CTF
name, or a year.

**Politeness.** Browser `User-Agent`, 1-1.5s between requests, retry with backoff, and
everything cached so a re-run costs nothing. `gh api` is used for GitHub (authenticated,
5000 req/hr) rather than scraping.

**Categorisation** is a keyword table in each script, mapping path/title/body keywords onto
the 12 categories, with a technique vocabulary that mines 6-20 tags per document. The tag
mining is the part worth improving, because it is what makes an ingested writeup findable.

## Adding a challenge repo

Repositories by challenge authors are the best writeup source there is: the solution in
them is the intended one, not a competitor's reconstruction. They are tracked in
`ingest/sources.json`, so adding one is a single command.

```bash
make add-repo URL=https://github.com/owner/name
make repos                 # what is currently tracked
make ingest-repos          # re-ingest everything tracked, picking up new challenges
```

The pipeline finds each directory containing a `README.md`, folds any `solver/`,
`solve/`, `solution/` or `exploit/` README into it, and inlines up to four solver source
files. Category comes from the path when the repo states it (`.../web/cookie-spinner/`),
and the CTF name and year come from the enclosing directory
(`202112_SECCON_CTF_2021` becomes "SECCON CTF 2021", 2021).

Find them with `ctfbrain search "" --tag challenge-source`.

## Importing your own notes

```bash
make ingest-notes SRC="/path/to/your/notes"
```

Free-form markdown is fine: no frontmatter needed, Obsidian callouts and `[[wiki links]]`
are normalised, and category comes from the folder names. Everything imported is tagged
`my-notes`, so `ctfbrain search "rsa tag:my-notes"` narrows to your own material. The
source folder is never modified.

## Adding a source

1. Write `ingest/<source>.py` with `crawl` / `fetch` / `render` / `all` subcommands.
2. Cache raw responses under `data/raw/<source>/`, keyed by URL hash.
3. Emit to `content/writeups/<category>/<source>-<slug>.md` with a unique prefix.
4. Reuse the categorisation and tag-mining tables from an existing pipeline.
5. Add a `make ingest-<source>` target and a `README-<source>.md`.
6. Run `ctfbrain index && ctfbrain lint` and fix anything your files introduce.

## Licensing

Ingested content belongs to its authors. Reference corpora record their licence in the
frontmatter (`license:`) and in `content/reference/ext-CORPORA-PROVENANCE.md`. Vendored
repositories keep their upstream `LICENSE` file, with `vendor/PROVENANCE.md` recording
repo, commit SHA, licence and what was taken.

A corpus whose licence is not clearly permissive is either excerpted with attribution or
skipped, and the decision is recorded. To remove something, delete the file and re-run
`make index`.
