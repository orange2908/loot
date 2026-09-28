# Challenge-author repositories

`ingest/challenge_repos.py` indexes repositories published by the people who *set* the
challenges. The solution in them is the intended one, not a competitor's reconstruction,
which makes them the single best writeup source available.

## Adding one

```bash
make add-repo URL=https://github.com/owner/name
make add-repo URL=https://github.com/owner/name NOTE="why this is worth having"
```

That registers the repo in `ingest/sources.json`, ingests it, and reindexes.

```bash
make repos          # what is tracked
make ingest-repos   # re-ingest everything, picking up newly added challenges
```

## How a challenge is found

A challenge is any directory containing a `README.md`, with two rules:

- a README inside `solver/`, `solve/`, `solution/`, `exploit/` or `writeup/` is folded
  into the challenge above it rather than becoming its own document
- scaffolding directories (`dist/`, `files/`, `assets/`, `node_modules/`, `.github/`, ...)
  are ignored

Up to four solver source files from those directories are inlined under
`## Solver: <filename>`, each capped at 220 lines with a permalink to the full file.

## What is inferred

**Category** comes from the path when the repo states it. `arkark` lays challenges out as
`challenges/<ctf>/<category>/<name>/`, so `web/cookie-spinner` is filed under web with no
guessing. When the path says nothing, the text is classified instead.

**CTF name and year** come from the enclosing directory. `202112_SECCON_CTF_2021` becomes
"SECCON CTF 2021" with year 2021; the leading `YYYYMM` is stripped. When no year can be
found, the field is omitted rather than guessed.

**Tags** include `challenge-source` and `author-solution` on every document, so you can
narrow to intended solutions:

```bash
ctfbrain search "" --tag author-solution -n 100
ctfbrain search "reentrancy tag:challenge-source"
```

## Caching

Blobs are fetched by their immutable git sha into `data/raw/challenge-repos/blobs/`, so
the cache can never go stale and a re-run only fetches genuinely new files. Trees and head
shas are cached per repo. Delete `data/raw/challenge-repos/tree-<slug>.json` and
`sha-<slug>.json` to force a re-crawl after the upstream repo gains new challenges.

## Licensing

Many challenge repos have no LICENSE file, which means the work stays fully reserved to
its author. Those are still indexed here, but only as a personal, private reference:

- every document carries attribution and a permalink to the exact commit
- bodies are capped rather than mirrored whole
- the licence status is recorded per document and in
  `content/reference/chal-REPOS-PROVENANCE.md`

**Do not redistribute this index.** If you are an author and want your work out, delete
the matching `content/writeups/*/chal-*.md` files and run `make index`.
