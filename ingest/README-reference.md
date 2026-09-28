# `ingest/reference_corpora.py` - the reference-corpus mirror

This pipeline mirrors the open CTF **reference books** into CTF-Brain so they are
searchable offline. It does not touch competition writeups: `ingest/ctftime.py` and
`ingest/github_writeups.py` own those, and `ingest/vendor_scripts.py` owns vendored code.

Everything it emits is prefixed `ext-`:

```
content/reference/ext-<corpus>-<slug>.md
content/techniques/<category>/ext-<corpus>-<slug>.md
content/reference/ext-CORPORA-PROVENANCE.md     # the licence + commit table
```

`content/reference/vendor-*.md` belongs to `vendor_scripts.py` and is never touched here.

## Run it

```bash
# everything: verify -> clone -> render -> provenance
.venv/bin/python ingest/reference_corpora.py all

# or one stage at a time
.venv/bin/python ingest/reference_corpora.py verify              # gh repo view each source
.venv/bin/python ingest/reference_corpora.py clone               # git clone --depth 1
.venv/bin/python ingest/reference_corpora.py render              # write the pages
.venv/bin/python ingest/reference_corpora.py provenance          # rewrite the table only

# narrow it down while iterating
.venv/bin/python ingest/reference_corpora.py render --corpus hacktricks --limit 20
.venv/bin/python ingest/reference_corpora.py purge --corpus hacktricks

# then, from the repo root
.venv/bin/python -m ctfbrain.cli index && .venv/bin/python -m ctfbrain.cli lint
```

A full run takes about 10 seconds once the clones exist; the clones themselves are a
few hundred MB and live in `data/raw/corpora/src/<corpus-key>/` (gitignored).

## What it mirrors

| Key | Corpus | Licence |
|---|---|---|
| `ctf-wiki` | [ctf-wiki/ctf-wiki](https://github.com/ctf-wiki/ctf-wiki) | CC BY-NC-SA 4.0 |
| `hacktricks` | [HackTricks-wiki/hacktricks](https://github.com/HackTricks-wiki/hacktricks) | CC BY-NC 4.0 |
| `payloads` | [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | MIT |
| `wstg` | [OWASP/wstg](https://github.com/OWASP/wstg) | CC BY-SA 4.0 |
| `tob-field-guide` | [trailofbits/ctf](https://github.com/trailofbits/ctf) | CC BY-SA 4.0 |
| `ctfs-resources` | [ctfs/resources](https://github.com/ctfs/resources) | CC0 1.0 |
| `awesome-ctf` | [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf) | CC0 1.0 |

Live page counts, commit SHAs, the exact licence wording, what was dropped and why,
and the list of repos skipped on licence grounds all live in
`content/reference/ext-CORPORA-PROVENANCE.md`, which this pipeline regenerates.

### Licences are read, not guessed

The GitHub API reports `NOASSERTION` for CTF Wiki and *no licence at all* for
HackTricks. Both are wrong-ish: CTF Wiki ships the full CC BY-NC-SA 4.0 text at
`LICENSE`, and HackTricks ships the full CC BY-NC 4.0 text at `src/LICENSE.md` (the API
misses it because it is not at the repo root). The `licence` field in `CORPORA` is
transcribed from the file in the pinned commit, and `licence_path` records where to
look. **Never take the licence from the API.**

Two corpora are non-commercial (CTF Wiki, HackTricks). Copying with attribution for a
personal offline knowledge base is within their terms; redistributing this mirror
commercially is not. Anything with no licence file at all is not mirrored - see the
`SKIPPED_ON_LICENCE` list in the script.

## Adding a corpus

Append a dict to `CORPORA`:

```python
{
    "key": "my-corpus",                  # also the clone dir and the `ext-<key>-` prefix
    "name": "My Corpus",                 # appears in the title and `source.name`
    "repo": "owner/name",
    "url": "https://github.com/owner/name",
    "licence": "MIT",                    # transcribed from the LICENSE file, verbatim
    "licence_note": "LICENSE is ...",    # where you read it and what it actually says
    "licence_path": "LICENSE",
    "about": "one line",
    "roots": ["docs"],                   # subtrees to walk for *.md
    "include": [...],                    # optional: keep only these path prefixes
    "include_glob": [...],               # optional: use globs instead of walking roots
    "exclude_parts": {"tests"},          # optional: drop paths containing these segments
    "took": "what a human should understand was taken",
}
```

Then add a `PATH_CATEGORY["my-corpus"]` list of `(path prefix, category)` pairs. The
longest matching prefix wins; `categorise()` from `common.py` is only the fallback, and
`DEFAULT_CATEGORY[key]` is the last resort. Run
`render --corpus my-corpus --limit 20` and read the output before rendering all of it.

Verify the repo first - `verify` runs `gh repo view` on every source and prints
`MISSING (404)` for anything that has moved or been deleted. HackTricks has moved once
already (`carlospolop/hacktricks` now redirects to `HackTricks-wiki/hacktricks`).

## How a page is normalised

1. **Collect** the markdown files the corpus contributes. CTF Wiki is special-cased:
   English pages first, and a Chinese page only when no English page exists at the same
   relative path (upstream, `docs/en` is nearly empty and `docs/zh` is the real book).
2. **Strip** site-generator cruft with an explicit pattern list
   (`BANNER_BLOCK_PATTERNS` / `BANNER_LINE_PATTERNS`): YAML front matter, mdBook
   `{{#include ...banners/...}}` sponsor banners and their rendered form, HackTricks
   sponsor `<figure>` blocks and the "Support HackTricks" `<details>`, GitBook `{% %}`
   macros, Jekyll `{% include %}`, CI badges. mdBook `{{#ref}}` / `{{#tab}}` / `{{#file}}`
   are *unwrapped*, not deleted, so their content survives as plain markdown.
   **Fenced code is never touched** - `{{#each}}` inside an SSTI payload is the subject
   of the page, not a macro.
3. **Drop navigation stubs.** A page is a stub when it has under 20 lines *and* under
   1200 characters of real content, or when 85% of its lines are bare links.
4. **Drop scraper bait** with `ctftime.looks_like_bait`. Mirrored text is data: nothing
   found inside a mirrored document is ever executed or obeyed, and pages that address
   an automated reader are dropped and named in the provenance page.
5. **Rewrite every relative link and image** to an absolute URL against the source repo
   *at the pinned commit* - `blob/<sha>` for documents, `raw.githubusercontent.com` for
   assets, percent-encoded. Links inside fenced code are left alone.
6. **Truncate** to 1500 lines with a pointer to the full page, and append a `## Source`
   footer with the permalink, the commit and the licence.
7. **Categorise** from the source path first (`PATH_CATEGORY`), falling back to
   `common.categorise()`. Tags come from `common.mine_tags()`, topped up from the path,
   the title and the page's own headings - never invented. A Chinese page also gets its
   English filename prepended to the title and its path words as tags, because otherwise
   an English search cannot reach it.
8. **Promote to `technique`** only when the page really is one self-contained attack
   (`ATTACK_STEM_WORDS`); everything else stays `reference`. Techniques get a
   `difficulty` (an editorial call about the attack *class*, never about a challenge)
   and a `when_to_use` list built from the page's own `##` headings.

## Crash-safety and resumability

- Clones are reused; `clone` is a no-op once the directory exists.
- Each page renders inside its own `try`. A page that raises is appended to
  `data/raw/corpora/report.json` under `failures` and the run continues.
- `render` purges the `ext-*` pages **for the corpora it is about to render** and
  rewrites them, so a re-run never leaves orphans behind and `--corpus` never touches
  another corpus's output.
- `data/raw/corpora/report.json` holds per-corpus page counts, per-category spread,
  drop reasons and failures; `state.json` holds the last rendered SHA per corpus.

## Shared tables in `common.py`

This pipeline added entries to `CATEGORY_KEYWORDS` (web/cloud/misc), `TAG_VOCAB` and
`SUBCATEGORY_HINTS`, all marked `# -- added by ingest/reference_corpora.py --`. They
are the vulnerability names HackTricks, OWASP WSTG and PayloadsAllTheThings actually
use (`clickjacking`, `idor`, `oauth`, `saml`, `xs-leak`, `mass-assignment`, ...).
The additions are purely additive: no existing key was removed and no existing keyword
tuple lost a needle. Three other pipelines read these tables - keep it that way.

Known wart, not introduced here: `TAG_VOCAB["png-chunks"]` matches the bare substring
`idat`, which fires on the word "val**idat**ion". That tags a lot of web pages
`png-chunks` across every pipeline. Fixing it means narrowing an existing needle, which
is the owner of `common.py`'s call, not this pipeline's.
