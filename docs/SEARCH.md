# Search: how it works, and how to tune it

## The problem it solves

Under time pressure you recall a *symptom*, not a name. You remember "the two moduli
looked similar", not "batch GCD on a shared prime". A plain full-text index fails here:
`gcd` only matches pages that literally contain "gcd".

CTF-Brain closes that gap in three places: the tag vocabulary authors write, the
synonym layer, and the re-ranker.

## 1. Tags are the search surface

Every document carries 8-20 lowercase-kebab tags, and `CONTENT_SPEC.md` requires them to
include:

- symbols spelled out: `gcd`, `phi`, `xor`, `lsb`, `nth-root`
- aliases: `lll` *and* `lattice` *and* `lattice-reduction`
- the tool that solves it: `rsactftool`, `pwntools`, `volatility3`
- the vulnerable function, when there is one: `strcpy`, `eval`, `pickle-loads`, `_.merge`

Tags are weighted 10 in BM25 and earn a further `+6` on an exact match, so a well-tagged
page beats a long page that merely mentions the word.

## 2. Synonym expansion

`ctfbrain/synonyms.py` holds ~220 single-term triggers and ~37 multi-word phrases.

```python
"gcd": ["common-factor", "batch-gcd", "shared-prime", "euclidean",
        "common-modulus", "bezout", "factoring"],
"penguin": ["ecb", "electronic-codebook"],
"i am stuck": ["stuck", "playbook", "triage", "methodology"],
```

Expansion is `OR`-ed into the term's group, never `AND`-ed, so it can only ever *add*
results. Terms are normalised (punctuation stripped) before lookup, so `common-modulus`,
`common modulus` and `commonmodulus` all hit the same entry.

`--no-synonyms` turns it off when you want literal matching.

### Adding a synonym

Edit `SYNONYMS` (single word) or `PHRASES` (multi-word) and re-run. No reindex is needed, because
expansion happens at query time. Keep values lowercase and free of FTS operators;
`tests/test_synonyms.py` enforces both.

## 3. Re-ranking

BM25 gives relevance. The bonuses in `config.py` give *usefulness mid-CTF*:

| Bonus | Value | Why |
|---|---|---|
| exact tag match | +6 | the author explicitly said this page is about that |
| title substring | +4 | the title is the strongest one-line summary |
| subcategory match | +2 | `subcategory: rsa` is a strong topical signal |
| playbook | +3 | when stuck, a decision tree beats everything |
| cheatsheet | +2.5 | you usually want the command, not the prose |
| technique | +2 | the attack itself |
| script | +1.5 | runnable, but needs context |
| tool / reference | +1 / +0.5 | supporting material |
| writeup | 0 | valuable, but narrative and challenge-specific |

Each hit carries `why`, listing which bonuses fired. It is visible in `--json` and in the API.

## Tuning

- **A category's results feel wrong.** Check the tags first: `ctfbrain tags -c crypto`.
  Nine times out of ten the fix is a better tag, not a ranking change.
- **Writeups drown out techniques.** Raise `TYPE_BONUS["technique"]` or lower the writeup
  entry in `config.py`.
- **A query returns nothing.** `ctfbrain search "<query>" --json` shows whether the AND
  fallback fired. If the vocabulary is genuinely missing, add a synonym.
- **Too many results.** Filters compose: `cat:`, `type:`, `tag:`, `diff:`, `ctf:`, `tool:`.

## Cost

Full rebuild is a few seconds over thousands of documents. Queries are single-digit
milliseconds, because the index is a local SQLite file and `Brain` holds one read-only
connection open for the process lifetime.
