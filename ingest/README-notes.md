# Personal notes import

`ingest/local_notes.py` imports a folder of your own markdown notes.

```bash
make ingest-notes SRC="/path/to/your/notes"
# or
python3 ingest/local_notes.py import --src "/path/to/notes" [--dry-run]
```

## What it assumes

Nothing. Notes are free-form: no frontmatter, no naming convention. The importer works
out the rest.

**Category** comes from the folder names first, content second. The mapping lives in
`DIR_CATEGORY`, and covers the usual spellings (`Cryptography`, `Crypto`, `Reverse`,
`Reversing`, `pwn`, `Jails`, `random`, ...). Folders listed in `PASSTHROUGH_DIRS`
(`HTB Challenges`, `scripts`, `writeups`) are transparent, so
`scripts/pwn/ROP.md` lands in pwn and `HTB Challenges/Web/Slippy.md` lands in web.
Anything unmapped falls back to classifying the text.

**Type** is inferred:

| Signal | Type |
|---|---|
| under `scripts/` or `templates/` | `script` |
| under `writeups/`, `challenges/` or `HTB Challenges/` | `writeup` |
| mostly links, little code | `reference` |
| two or more code blocks | `technique` |
| otherwise | `reference` |

**Tags** are mined from the title, path and body, and always include `my-notes` and
`personal`, so you can narrow to your own material:

```bash
ctfbrain search "rsa tag:my-notes"
ctfbrain search "" --tag my-notes -n 200
```

## What it normalises

- Obsidian callouts (`> [!info] ...`) become plain blockquotes with a bold lead-in.
- `[[wiki links]]` become plain text, since the target is another note and not a URL.
- Bodies are capped at 1200 lines.
- Notes under 40 characters are skipped as empty.

Every imported document keeps its original location in `origin_path` and prints it as a
footer, so you can always find the file you actually edit.

## Re-running

Safe and idempotent. The importer writes `notes-<slugified path>.md`, so a re-run
overwrites the same files. If you rename or move a note in the source folder, the old
imported copy is left behind; delete `content/**/notes-*.md` and re-import for a clean
sweep:

```bash
find content -name 'notes-*.md' -delete
make ingest-notes SRC="/path/to/your/notes"
```

**The source folder is never modified.**
