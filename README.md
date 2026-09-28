<p align="center">
  <img src="docs/assets/cover.svg" alt="CTF-Brain" width="100%">
</p>

<p align="center">
  <b>An offline, searchable knowledge base for CTF competitions.</b><br>
  Writeups, attack techniques, cheatsheets and ready-to-run scripts, in one full-text index
  you can query from a terminal or a browser with no network connection.
</p>

---

## Why this exists

Mid-competition you rarely remember what the attack is called. You remember what you are
looking at: two moduli that look similar, a `%n` in a printf, a chunk freed twice, an image
that looks like coloured blocks.

CTF-Brain is built around that. You type the symptom, it gives you the technique, working
code, and the writeups where someone already solved it.

```
$ ctfbrain search gcd

 1. RSA: Shared Prime / Batch GCD Across Many Moduli
    crypto/technique · easy  techniques:crypto:rsa-common-factor-batch-gcd
    Two RSA moduli generated with bad entropy share a prime, so gcd(n1, n2) factors both
    instantly; batch GCD does it for millions of keys.
    #rsa  #batch-gcd  #common-factor  #shared-prime  #gcd  #factordb

 2. Playbook: RSA Decision Tree by Known Parameters
    crypto/playbook  playbooks:rsa-decision-tree
    Given exactly which RSA values you know, which attack applies and the command to run.
```

## What you get

| | |
|---|---|
| **4,500+ documents** | across crypto, web, pwn, rev, forensics, stego, misc, osint, mobile, hardware, blockchain, cloud and sherlocks (HTB blue team DFIR) |
| **1.2M lines, 39k code blocks** | techniques with complete exploits, not fragments |
| **2,800+ writeups** | harvested from CTFtime, 15 public team repos and the Daily AlpacaHack set, each linking back to its author |
| **970 mirrored reference pages** | CTF Wiki, HackTricks, PayloadsAllTheThings, OWASP WSTG, Trail of Bits CTF Field Guide |
| **300+ vendored attack scripts** | crypto-attacks, how2heap, RsaCtfTool, GTFOBins, ctf-skills, with their licences intact |
| **Sub-50ms search** | SQLite FTS5 with BM25 and CTF-aware ranking |

Run `ctfbrain stats` for live counts.

## Quick start

### Docker

```bash
make docker-up          # builds and serves on http://localhost:8000
make docker-logs
make docker-down
```

`content/` is bind-mounted read-only, so you can edit notes on the host and the container
reindexes on restart. One-off commands work too:

```bash
docker compose run --rm ctfbrain search "tcache poisoning"
```

### Local (Python 3.10+)

```bash
make install            # creates .venv and installs dependencies
make index              # builds data/index.db from content/
make serve              # http://localhost:8000
```

Then either use the browser, or the CLI:

```bash
.venv/bin/ctfbrain search "padding oracle"
.venv/bin/ctfbrain show techniques:crypto:aes-cbc-padding-oracle
.venv/bin/ctfbrain code techniques:crypto:aes-cbc-padding-oracle --first --plain > solve.py
```

Put `.venv/bin` on your `PATH`, or `pipx install -e .`, and it is just `ctfbrain`.

## Searching

Queries are expanded automatically. `gcd` also reaches batch-GCD and shared-prime material,
`penguin` reaches ECB, `stuck` reaches the triage playbooks. About 220 trigger terms and
37 phrases map what you type onto the vocabulary the corpus is written in.

| Syntax | Meaning |
|---|---|
| `rsa gcd` | all terms must appear, with synonym expansion |
| `"chosen ciphertext"` | exact phrase |
| `cat:crypto` | restrict to a category |
| `type:cheatsheet` | `playbook` `cheatsheet` `technique` `script` `writeup` `tool` `reference` |
| `tag:tcache` | require an exact tag |
| `diff:hard` | `trivial` `easy` `medium` `hard` `insane` |
| `ctf:sekai` | match the CTF name |
| `tool:pwntools` | documents that use a given tool |
| `year:2024` | writeups from a given year |

Filters compose: `ctfbrain search "heap uaf cat:pwn type:technique diff:hard"`.

## Commands

```
ctfbrain index                  rebuild the search index from content/
ctfbrain search QUERY           search (-c category, -t type, --tag, -n limit, --json)
ctfbrain show SLUG              render a document in the terminal
ctfbrain cat SLUG               print the raw markdown
ctfbrain code SLUG [--first]    print only the code blocks, ready to pipe into a file
ctfbrain open SLUG [--web]      open in $EDITOR, or in the web UI
ctfbrain related SLUG           documents sharing tags with this one
ctfbrain tags [-c CATEGORY]     the tag vocabulary, by frequency
ctfbrain stats                  corpus statistics
ctfbrain lint                   report frontmatter problems
ctfbrain random [-c CATEGORY]   a random document
ctfbrain serve [--open]         the web UI
```

## Web UI

Search as you type, category and type facets, server-rendered syntax highlighting, a copy
button on every code block, a table of contents, and related documents. Nothing loads from
a CDN, so it works on a locked-down competition network.

Keyboard: `/` focus search, `j`/`k` move through results, `Enter` open, `Backspace` back,
`h` home, `t` theme, `?` help.

## Layout

```
content/
  playbooks/          "I have X, what now" decision trees. Start here when stuck.
  cheatsheets/<cat>/  dense, copy-pasteable command and payload references
  techniques/<cat>/   one attack each: how to recognise it, why it works, a working exploit
  scripts/<cat>/      complete, self-testing tools
  writeups/<cat>/     solved challenges, normalised from CTFtime, GitHub and elsewhere
  tools/              install and the ten invocations that matter, per tool
  reference/          tables: magic bytes, syscalls, flag formats, glossary
vendor/               upstream attack repos, vendored with their licences
ingest/               the pipelines that pull writeups and reference corpora in
ctfbrain/             indexer, search engine, CLI, web app
```

Categories: `crypto` `web` `pwn` `rev` `forensics` `stego` `misc` `osint` `mobile`
`hardware` `blockchain` `cloud` `sherlocks`.

## Growing it

```bash
make add-repo URL=https://github.com/owner/name    # index a challenge-author repo
make ingest-notes SRC="/path/to/your/notes"        # import a folder of your own notes
make repos                                         # what is tracked
make ingest                                        # refresh every source
```

Challenge-author repos are the best writeup source available: the solution in them is the
intended one. Tracked repos live in `ingest/sources.json`.

## Adding your own notes

This is the natural home for your competition notes. They get indexed and ranked alongside
everything else, and the ones you write yourself are usually the ones you search for again.

Drop a markdown file with frontmatter anywhere under `content/`, then `make index`.

```markdown
---
title: "RSA: Common Modulus Attack"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, common-modulus, gcd, bezout, extended-euclidean]
difficulty: medium
summary: "Same n, two coprime e, recover m without factoring."
when_to_use:
  - "Two ciphertexts of the same plaintext under the same modulus n"
  - "gcd(e1, e2) == 1"
tools: [sympy, gmpy2]
---

## TL;DR
...
```

`tags` is the primary search surface. Spell out symbols (`gcd`, `xor`, `phi`, `lsb`) and
include aliases and tool names. The full contract is in
[docs/CONTENT_SPEC.md](docs/CONTENT_SPEC.md), and `ctfbrain lint` checks it.

## Documentation

| Document | Covers |
|---|---|
| [CATALOG.md](docs/CATALOG.md) | What is actually in here, generated from the index |
| [USAGE.md](docs/USAGE.md) | Working recipes: mid-CTF workflows, piping, filters |
| [SEARCH.md](docs/SEARCH.md) | How ranking and synonym expansion work, and how to tune them |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module map, index schema, request flow |
| [INGESTION.md](docs/INGESTION.md) | The ingestion pipelines and how to add a source |
| [CONTENT_SPEC.md](docs/CONTENT_SPEC.md) | The document format contract |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Docker, LAN hosting, backups |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | Conventions and the review checklist |

## Development

```bash
make check       # index + lint + tests
make test        # pytest
make lint        # frontmatter problems in content/
make catalog     # regenerate docs/CATALOG.md
make clean       # drop the index and caches
```

## Attribution and licence

The platform code (`ctfbrain/`, `ingest/`, `tests/`) is MIT licensed.

**Ingested and vendored content belongs to its original authors.** Every ingested document
carries a `source:` link to the original, and everything under `vendor/` keeps its upstream
`LICENSE` file. Provenance is recorded in
[vendor/PROVENANCE.md](vendor/PROVENANCE.md) and
[content/reference/ext-CORPORA-PROVENANCE.md](content/reference/ext-CORPORA-PROVENANCE.md),
including the commit each mirror was taken from.

Two mirrored corpora (CTF Wiki and HackTricks) are CC BY-NC, so **this mirror must not be
redistributed commercially**. If you are an author and want something removed, delete the
file and run `make index`.

Built for CTF competition and security education.
