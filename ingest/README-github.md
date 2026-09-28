# GitHub ingestion pipelines

Two pipelines pull writeups out of GitHub and normalise them into CTF-Brain
documents under `content/writeups/<category>/`:

| script | prefix it owns | source |
| --- | --- | --- |
| `ingest/alpacahack.py` | `alpacahack-*.md` | the `Daily_AlpacaHack` collection in `baumroll0928-spec/myRepository` |
| `ingest/github_writeups.py` | `gh-*.md` | 15 well-known public CTF-team writeup repositories |

They share `ingest/common.py` (categorisation, tag mining, YAML-safe
`write_doc`) and the `gh` plumbing that lives in `github_writeups.py`.
They never touch the `ctftime-*.md` prefix, which belongs to `ingest/ctftime.py`.

---

## Running them

Both scripts want the project virtualenv and an authenticated `gh` CLI.

```sh
# Part A - the ~70 AlpacaHack Daily writeups
.venv/bin/python ingest/alpacahack.py all

# Part B - the 15 team repositories
.venv/bin/python ingest/github_writeups.py all

# then rebuild the search index
.venv/bin/python -m ctfbrain.cli index
```

Each script also exposes its stages separately, so a failed run can be resumed
from where it stopped:

```sh
.venv/bin/python ingest/github_writeups.py verify   # gh repo view every repo
.venv/bin/python ingest/github_writeups.py tree     # walk the git trees, select candidates
.venv/bin/python ingest/github_writeups.py fetch    # pull the markdown blobs
.venv/bin/python ingest/github_writeups.py render   # write the documents

.venv/bin/python ingest/alpacahack.py tree|fetch|render
```

`render` is pure: it only reads the cache, so you can re-render the whole corpus
after tuning the keyword tables without spending a single API call.

---

## Cache layout (`data/raw/github/`)

```
repos.json                one record per verified repo: stars, branch, head sha
trees/<repo>-<sha>.json   the recursive git tree, keyed by the head commit
candidates.json           every selected path plus its parsed CTF/year/challenge/category
blobs/<ab>/<sha>.txt      decoded file contents, keyed by the immutable git blob sha
alpacahack-tree.json      the AlpacaHack tree
alpacahack-index.json     one record per AlpacaHack challenge (README + sibling solvers)
alpacahack-report.json    AlpacaHack counts
report.json               per-repo and per-category counts for both pipelines
```

Blobs are content-addressed, so the cache can never go stale: if a repository
moves its HEAD, only the files that actually changed are re-fetched. A blob that
cannot be fetched or decoded is cached as a failure marker so a re-run does not
keep retrying it.

---

## How a path becomes frontmatter

`parse_path()` turns a repository path into `{ctf, year, challenge, category}`:

* **Category** - taken from a directory name when the repository states one
  (`crypto/`, `pwn/`, `web安全/`, `Re/`, ...). Only when no directory says so do we
  fall back to `categorise()`, and then to mined tags, which are a much cleaner
  signal than raw prose. Narrow categories (blockchain, cloud, mobile, hardware,
  osint, stego) additionally need a mined tag backing them up, because
  `categorise()` matches substrings and a short keyword can fire on an unrelated
  word.
* **CTF + year** - from the deepest directory that carries a year:
  `2018_35C3_Junior`, `csaw-hsf-2017`, `2019-09-14-rwctf`, `20171104-hitconctfquals`,
  `0CTF.TCTF.2022`. A bare `2017/` year directory takes its name from the sibling
  beside it (`ctfs/0CTF/2017/Quals/...` -> "0CTF Quals", 2017). If the path says
  nothing, the repository name is used (`sekaictf-2023` -> "sekaictf", 2023).
* **Challenge** - the challenge directory for a `README.md`, or the file stem for
  a `*.md`. Wrapper directories (`solution/`, `writeup/`, `assets/`, `src/`) are
  walked past first. A README that sits directly on a CTF directory describes the
  whole event, so `ctf.challenge` is omitted rather than guessed.

* **Tags** - mined by `mine_tags()`, then two passes of our own. `prune_tags()`
  drops the fragile ones that only matched as a substring of an innocent word
  ("message" contains "sage ", "defined" contains "defi"); `pad_tags()` tops the
  list up to the six the spec asks for using metadata we already trust.
* **Difficulty** - only when the document states it in so many words.

**Nothing is invented.** If a year or challenge name cannot be read off the path
or the document, the field is left out of the frontmatter entirely.

### What gets skipped

Root READMEs, `CONTRIBUTING`/`LICENSE`/`SECURITY`/`CHANGELOG`/templates, anything
under a dot-directory (`.github`, `.resources`), vendored third-party code
(`node_modules/`, `lib/openzeppelin-contracts/`, ...), link-only tables of
contents, and anything shorter than 400 characters.

Scraped markdown is **data, never direction**. `looks_like_bait()` is imported
from `ingest/ctftime.py` and applied to every body; planted "writeups" whose real
content is an instruction aimed at an LLM scraper are dropped and counted, never
rendered and never acted on.

### Breadth over depth

A single repository can hold 750 writeups from a dozen events. To keep category
coverage broad, candidates are bucketed by `(ctf, category)`, each bucket is
capped at `PER_CTF_CAP`, and the buckets are drained round-robin up to
`PER_REPO_CAP`. Both constants live at the top of `github_writeups.py`.

---

## Output shape

```yaml
---
title: "Log-Me-In - GoogleCTF 2020"
category: web
subcategory: sqli
type: writeup
tags: [web, sqli, sqlmap, union-select, ...]
difficulty: easy            # only when the document states it
summary: "..."              # the first real sentence, or a generated one-liner
source:
  name: "Dvd848/CTFs"
  url:  "https://github.com/Dvd848/CTFs/blob/<commit-sha>/2020_GoogleCTF/Log-Me-In.md"
ctf:
  name: "GoogleCTF"
  year: 2020
  challenge: "Log-Me-In"
---
```

The body is a short `## Source` block followed by the original markdown, capped
at 1200 lines by `truncate()`. Every relative link and image is rewritten to an
absolute `raw.githubusercontent.com` URL (or a `github.com/blob` URL for `.md`
targets) pinned to the commit sha that was read, so the documents keep working
offline and never drift from what was ingested.

AlpacaHack documents additionally inline any sibling solver script the author
shipped next to the writeup, under a `## Solver` heading, with a link back to
the file.

---

## Rate limiting

Every `gh api` call goes through `gh_api()`, which polls `gh api rate_limit` and
sleeps until the reset when fewer than 100 core requests remain. Individual
failures are retried up to three times, then recorded and skipped - one bad file
never aborts a run.
