# Usage recipes

Working patterns, written for the middle of a competition when you have ten minutes
and a challenge you do not recognise.

## The first thing to try

```bash
ctfbrain search "<whatever you can see>"
```

Describe the symptom, not the attack. "two moduli", "prints my input back", "freed twice",
"image looks like blocks". The synonym layer is built for exactly this.

If that fails, go to a playbook:

```bash
ctfbrain search type:playbook              # all of them
ctfbrain show playbooks:unknown-file       # I have a file, no idea what it is
ctfbrain show playbooks:crypto-triage
ctfbrain show playbooks:pwn-triage
ctfbrain show playbooks:web-triage
ctfbrain show playbooks:stuck              # 30 minutes in, nothing working
```

## Getting code out fast

```bash
# The first code block of a document, straight to a file
ctfbrain code techniques:crypto:rsa-wiener-small-d --first --plain > solve.py

# Only the python blocks
ctfbrain code scripts:crypto:rsa-toolkit --lang python --plain > rsa_toolkit.py

# The whole document as markdown, into your notes
ctfbrain cat techniques:pwn:rop-ret2libc >> notes.md
```

In the web UI, every code block has a copy button and each document has **copy all code**.

## Narrowing

```bash
ctfbrain search rsa -c crypto -t technique      # flags
ctfbrain search "rsa cat:crypto type:technique" # or inline, same thing
ctfbrain search "heap" --tag tcache --tag uaf   # require exact tags
ctfbrain search "aes" -d hard -n 30
ctfbrain search "ctf:sekai lattice"             # writeups from one CTF
ctfbrain search "tool:volatility3"              # everything that uses a tool
```

## Exploring a topic

```bash
ctfbrain tags -c crypto -n 60          # the crypto vocabulary, by frequency
ctfbrain search "" -c crypto -n 100    # browse a whole category
ctfbrain related techniques:pwn:heap-tcache-poisoning
ctfbrain random -c rev                 # learn something while a scan runs
```

## Scripting against it

`--json` on `search`, `tags` and `stats` gives stable machine-readable output.

```bash
# Every file path matching a query, for grep/ripgrep
ctfbrain search "format string" --json | jq -r '.results[].slug'

# Pull the raw markdown of the top hit
SLUG=$(ctfbrain search "padding oracle" --json | jq -r '.results[0].slug')
ctfbrain cat "$SLUG"

# Everything you have on a CTF you are replaying
ctfbrain search "ctf:sekai" --json -n 200 | jq -r '.results[] | "\(.category)\t\(.title)"'
```

The HTTP API is equally scriptable while `ctfbrain serve` is running:

```bash
curl -s 'localhost:8000/api/search?q=tcache&limit=5' | jq '.results[].title'
curl -s 'localhost:8000/api/doc/techniques:pwn:heap-tcache-poisoning' | jq -r '.html' > doc.html
curl -s 'localhost:8000/api/raw/playbooks:pwn-triage' > triage.md
```

## Adding what you just learned

The highest-value documents in here end up being your own. After a CTF:

```bash
$EDITOR content/writeups/crypto/myctf-2026-babyrsa.md   # follow docs/CONTENT_SPEC.md
ctfbrain lint                                            # check the frontmatter
make index
```

Write the `## Takeaway` section properly. The reusable lesson is what you will search
for next year, not the challenge name.

## Keeping it current

```bash
make ingest          # re-run every pipeline, then reindex
make ingest-ctftime  # just CTFtime
make index           # after editing content/ by hand
```

Pipelines cache aggressively under `data/raw/`, so a re-run only fetches what is new.

## Web UI shortcuts

| Key | Action |
|---|---|
| `/` | focus search |
| `j` / `k` | move through results |
| `Enter` | open the selected result |
| `Backspace` | back |
| `h` | home |
| `t` | toggle light/dark |
| `?` | shortcuts and search syntax |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No index at data/index.db` | `make index` |
| `This Python's SQLite lacks FTS5` | use `make docker-up`, or a Python built against a full SQLite |
| A document you just wrote is missing | `ctfbrain lint`; the frontmatter probably failed to parse |
| Search finds nothing sensible | drop to one word; check `ctfbrain tags` for the real vocabulary |
| Port 8000 taken | `make serve PORT=8123` or `make docker-up PORT=8123` |
