# siunam321 writeups

Ingests the CTF writeups published at **<https://siunam321.github.io/ctf/>** by
[siunam321](https://siunam321.github.io/) (a web/OSWE-focused player).

- **Source repo:** [`siunam321/siunam321.github.io`](https://github.com/siunam321/siunam321.github.io)
  — a Jekyll / GitHub Pages site.
- **Layout:** `ctf/<CTF>/<Category>/<Challenge>/README.md`, which renders on the
  blog at `https://siunam321.github.io/ctf/<CTF>/<Category>/<Challenge>/`.
- **Output:** `content/writeups/<category>/siunam-*.md`

## Running

```bash
make ingest-siunam            # tree + fetch + render
python3 ingest/siunam.py all  # same, driven directly
python3 ingest/siunam.py tree   # list candidate writeups
python3 ingest/siunam.py fetch  # pull blobs (cached forever by sha)
python3 ingest/siunam.py render # normalise to content/writeups/
```

Then `make index`.

## How it works

The pipeline reuses `github_writeups.py` wholesale — the same path parsing
(`parse_path`), tag mining, categorisation, link rewriting and bait/index
filtering — so the emitted documents are shaped identically to the rest of the
corpus. It differs in two ways:

1. **No per-repo / per-CTF cap.** `github_writeups.py` round-robins and caps each
   source for corpus balance; this pipeline ingests the author's full collection.
2. **Dual attribution.** `source:` points at the live blog page and
   `original_source:` at the exact file on GitHub (pinned to the commit SHA).

Only challenge-level READMEs (`ctf/<CTF>/<Category>/<Challenge>/README.md`,
path depth ≥ 4) are taken; CTF- and category-index READMEs are skipped.

Blobs are cached under `data/raw/github/blobs/` (shared with the GitHub
pipeline, keyed by immutable blob sha), so re-runs are free. Candidates and the
run report live under `data/raw/siunam/`.

As of the first run: **584 writeups** across 55 CTF events (heavily web, plus
crypto/misc/rev/forensics/pwn/osint/stego), including siunam's PortSwigger Web
Security Academy lab notes.

## Licensing

The writeups belong to their author. Each document links back to both the live
blog page and the source file; nothing is redistributed without attribution. To
remove a document, delete the file and run `make index`.
