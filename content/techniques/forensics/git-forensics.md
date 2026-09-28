---
title: "Git Repository Forensics - Dangling Objects, Deleted Commits, .git Exposure"
category: forensics
subcategory: git
type: technique
tags: [git, dangling-objects, git-fsck, reflog, packfile, git-cat-file, loose-objects, zlib, dirc, git-index, git-dumper, exposed-git, trufflehog, gitleaks, secrets, credentials, reset-hard, git-stash, dfir]
difficulty: medium
summary: "Recover deleted commits, amended history and leaked secrets from a .git directory, including dumping an exposed .git over HTTP and inflating objects by hand."
when_to_use:
  - "You were handed a repository, a .git directory, or a tarball containing one"
  - "A secret was committed and 'removed' in a later commit, or history was rewritten"
  - "/.git/HEAD is reachable over HTTP on a web target"
  - "git log looks clean but the challenge insists something was deleted"
tools: [git, git-dumper, gittools, trufflehog, gitleaks, zlib]
related: [container-forensics, disk-linux-forensics, disk-file-carving, disk-image-triage]
---

## TL;DR

`git log` shows the current history -- exactly the part the attacker cleaned up. The evidence is
in **unreachable objects** (`git fsck --unreachable`), the **reflog** (`.git/logs/HEAD`), and
older commits' blobs, which stay in `.git/objects` until `git gc --prune` runs. If `.git/` is
exposed over HTTP, dump it and do all of that locally.

## Recognise it

- A `.git/` directory anywhere in the provided files (`find . -name .git`), or `git fsck
  --unreachable` listing commits and blobs that `git log --all` never shows.
- `.git/logs/HEAD` mentions `rebase`, `commit --amend` or `reset --hard`, or
  `curl -s http://target/.git/HEAD` returns `ref: refs/heads/main`.

## Artifact anatomy: the .git directory

```text
HEAD, ORIG_HEAD    current ref (or a raw SHA when detached); where HEAD was before the
                   last merge/rebase/reset.  refs/heads/<b> is 40 hex chars + a newline
config             remotes (sometimes with credentials in the URL), user.name/email
COMMIT_EDITMSG     the LAST commit message typed, even if that commit was amended away
index              the staging area - DIRC binary: paths + sha1 + stat data
packed-refs        text "<sha> <refname>" per line, for refs moved into the pack
logs/HEAD          reflog: "<old> <new> <name> <email> <ts> <tz>\t<action>: <msg>"
objects/<xx>/<38>  LOOSE object: a raw zlib stream of "<type> <len>\0<content>"
objects/pack/*.pack + *.idx    PACKED objects; objects/info/packs lists the pack names
```

Four object types, all addressed by the SHA-1 of `"<type> <len>\0" + content`: **blob** (file
content, no name), **tree** (a directory: mode, name and 20 raw SHA bytes per entry), **commit**
(tree, parents, author, committer, message), **tag**. A loose object is a raw zlib stream --
no header, no magic beyond zlib's `78 01` / `78 9c` / `78 da`. `objects/info/alternates` points
at another object store, and a malicious file in `hooks/` is a persistence mechanism.

**Nothing is ever edited.** `commit --amend`, `rebase`, `reset --hard` and `filter-branch` all
create *new* objects and move a ref; the old commit and every blob it referenced stay on disk,
merely unreachable, until `git gc` prunes them (default 2 weeks, and only when triggered).

## Recovery workflow

```sh
# every object no ref can reach - the dangling commits are the deleted ones. Run it BOTH ways:
# without --no-reflogs the reflog keeps objects "reachable" and hides them from you.
git fsck --full --unreachable --dangling --lost-found --no-reflogs; git fsck --unreachable
# what type is this sha, what is in it, how big is it?
git cat-file -t <sha>; git cat-file -p <sha>; git cat-file -s <sha>
# --lost-found writes them to .git/lost-found/{commit,other}/; then show one with its diff
ls .git/lost-found/commit; git show --stat <dangling-sha>; git show <dangling-sha>
# every commit that touched a path (--diff-filter=D for deletions only)
git log --all --full-history -- path/to/secret.env
# PICKAXE: commits where the COUNT of a literal changed; -G is the regex-on-the-diff form
git log -p --all -S 'AKIA' --pickaxe-all; git log -p --all -G 'password\s*=\s*.'
# the reflog is the best record of history rewriting; read it by hand if git refuses to run
git reflog --date=iso; git reflog show --all --date=iso; cat .git/logs/HEAD
# every object in every ref with the path it was stored under, annotated by type and size:
# this is how you find the big blob someone committed and then removed
git rev-list --objects --all \
  | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' \
  | awk '$1=="blob"' | sort -k3 -n -r | head -20
# inside the packfile (3rd column = size); `rev-list --objects --all | grep <sha>` names it
git verify-pack -v .git/objects/pack/*.idx | sort -k3 -n -r | head -20
# explode a packfile into loose objects, in a throwaway repo
mkdir /tmp/u && cd /tmp/u && git init -q && git unpack-objects -r < /path/to/pack-<sha>.pack
# stashes are refs/stash plus its own reflog; a DROPPED stash becomes a dangling commit
git stash list --date=iso
# recover a dangling commit as a branch, or extract one file from it without switching
git checkout -b recovered <sha>; git show <sha>:path/to/file > recovered_file
# after `reset --hard <old>`: HEAD@{1} is where you were. After `commit --amend`: the pre-amend
# commit is the reflog entry just before the amend. After a rebase: ORIG_HEAD.
git reflog --date=iso | head; git reset --hard HEAD@{1}; git cat-file -p HEAD@{1}
cat .git/ORIG_HEAD && git log --oneline ORIG_HEAD; cat .git/COMMIT_EDITMSG
# a deleted branch's commit is simply dangling; filter-branch keeps copies in refs/original/
git show-ref | grep refs/original
```

## Secret hunting

```sh
# trufflehog and gitleaks over the whole local history (--no-git = working tree only)
gitleaks detect --source . -v --report-path leaks.json; gitleaks detect --source . --no-git -v
# brute force: grep every object reachable from any ref
git grep -n 'API_KEY' $(git rev-list --all)
git grep -nIE '(AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH) PRIVATE KEY)' $(git rev-list --all)
# git grep does NOT cover unreachable objects - loop over them by hand
git fsck --unreachable --no-reflogs | awk '{print $3}' \
  | while read -r o; do git cat-file -p "$o" 2>/dev/null | grep -Hn --label="$o" 'password'; done
# one file across two commits, its content at one commit, credentials in the remote URL
git diff <a> <b> -- .env; git show <a>:.env; git config --get-regexp 'remote\..*\.url'
# author-date != committer-date is a rewritten-history tell
git log --all --format='%H %ad | %cd | %s' --date=iso | awk -F'|' '$1!=$2' | head
```

## Exposed .git over HTTP

```sh
# the detection request: a real .git returns "ref: refs/heads/<branch>" with status 200
curl -si http://target/.git/HEAD | head -20 | grep -q '^ref: refs/heads/' && echo EXPOSED
# cheap confirmations: config, logs/HEAD and packed-refs all return plain text too
curl -s http://target/.git/config; curl -s http://target/.git/logs/HEAD
# the tool that does everything: reconstructs a tree from a non-listable .git
git-dumper http://target/.git/ ./dumped
# GitTools does it in two stages; with directory listing on, `wget -r -np` works instead
python3 gitdumper.py http://target/.git/ ./dumped && python3 extractor.py ./dumped ./out
# manual dumping, in the order that actually works - 1. the metadata that names everything else
for f in HEAD ORIG_HEAD config packed-refs COMMIT_EDITMSG index logs/HEAD \
         refs/heads/main refs/heads/master objects/info/packs objects/info/alternates; do
  curl -sf "http://target/.git/$f" -o "dumped/.git/$f" --create-dirs && echo "got $f"
done
# 2. if objects/info/packs exists, fetch every pack and its .idx
curl -s http://target/.git/objects/info/packs | awk '{print $2}' | while read -r p; do
  for f in "$p" "${p%.pack}.idx"; do
    curl -sf "http://target/.git/objects/pack/$f" -o "dumped/.git/objects/pack/$f" --create-dirs
  done
done
# 3. loose objects one sha at a time: objects/<first2>/<last38>
SHA=$(cut -c1-40 dumped/.git/refs/heads/main); O="objects/${SHA:0:2}/${SHA:2}"
curl -sf "http://target/.git/$O" -o "dumped/.git/$O" --create-dirs
# 4. cat-file walks commit -> tree -> blob and names the shas to fetch next; with enough
#    objects present, `git checkout -- .` restores the working tree
cd dumped && git cat-file -p "$SHA" && git checkout -- . 2>/dev/null; git log --oneline
# other VCS leftovers, and inflating one loose object by hand when git is unavailable
curl -s http://target/.svn/wc.db -o wc.db; curl -s http://target/.hg/store/00manifest.i
python3 -c "import sys,zlib;print(zlib.decompress(open(sys.argv[1],'rb').read())[:400])" obj
```

## Code

```python
#!/usr/bin/env python3
"""Walk .git/objects, inflate every loose object, identify its type, grep it.

A loose object is a raw zlib stream whose plaintext is "<type> <size>\\0<content>",
type in blob|tree|commit|tag. Reading them directly works on a partially dumped
.git where `git` refuses to operate, and covers unreachable objects that
`git grep $(git rev-list --all)` never sees.
Run: python3 git_loose_grep.py .git --grep 'flag\\{[^}]+\\}' --show
"""
import argparse, hashlib, os, re, sys, zlib

TYPES = (b"blob", b"tree", b"commit", b"tag")

def inflate(path: str) -> bytes:
    """Decompress a loose object; decompressobj salvages a truncated download."""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        return zlib.decompressobj().decompress(raw)
    except zlib.error:
        return b""

def split_header(data: bytes):
    """Return (type, declared_size, content) or None if it is not a git object."""
    nul = data.find(b"\x00")
    if nul == -1 or nul > 32:
        return None
    parts = data[:nul].split(b" ")
    if len(parts) != 2 or parts[0] not in TYPES:
        return None
    try:
        return parts[0], int(parts[1]), data[nul + 1:]
    except ValueError:
        return None

def object_sha(otype: bytes, content: bytes) -> str:
    """Git's own addressing: sha1 of "<type> <len>\\0<content>"."""
    return hashlib.sha1(otype + b" " + str(len(content)).encode() + b"\x00" + content).hexdigest()

def scan(gitdir: str, pattern, want_type=None, show=False):
    """Inflate every objects/<xx>/<38 hex> file and report the ones that match."""
    results = []
    objects = os.path.join(gitdir, "objects")
    for name in sorted(os.listdir(objects) if os.path.isdir(objects) else []):
        sub = os.path.join(objects, name)
        if not re.fullmatch(r"[0-9a-f]{2}", name) or not os.path.isdir(sub):
            continue
        for leaf in sorted(os.listdir(sub)):
            if not re.fullmatch(r"[0-9a-f]{38}", leaf):
                continue
            sha, parsed = name + leaf, split_header(inflate(os.path.join(sub, leaf)))
            if parsed is None:
                print(f"[!] unreadable object: {sha}", file=sys.stderr)
                continue
            otype, declared, content = parsed
            type_name = otype.decode()
            if want_type and type_name != want_type:
                continue
            hits = [m.group(0).decode("utf-8", "replace")
                    for m in pattern.finditer(content)] if pattern else []
            if pattern and not hits:
                continue
            flag = "" if object_sha(otype, content) == sha else "  [SHA MISMATCH/TRUNCATED]"
            results.append((sha, type_name, declared, hits))
            print(f"{sha}  {type_name:<6s} {declared:>10d}{flag}"
                  + "".join(f"\n    [HIT] {h}" for h in hits))
            if show:      # note: a tree body is binary, "<mode> <name>\\0<20 sha bytes>"
                print("\n".join(f"    | {l}" for l in
                                content.decode("utf-8", "replace").splitlines()[:40]))
    return results

def selftest():
    import shutil, tempfile
    root = tempfile.mkdtemp(prefix="gitobj-")
    try:
        gitdir = os.path.join(root, ".git")
        blob = b"password = 'flag{loose_object_leak}'\n"
        commit = b"tree " + b"0" * 40 + b"\nauthor a <a@x> 1700000000 +0000\n\nremove secret\n"
        for otype, content in ((b"blob", blob), (b"commit", commit)):
            header = otype + b" " + str(len(content)).encode() + b"\x00"
            sha = hashlib.sha1(header + content).hexdigest()
            os.makedirs(os.path.join(gitdir, "objects", sha[:2]), exist_ok=True)
            with open(os.path.join(gitdir, "objects", sha[:2], sha[2:]), "wb") as fh:
                fh.write(zlib.compress(header + content))
        assert split_header(b"blob 5\x00hello") == (b"blob", 5, b"hello")
        assert split_header(b"nope") is None
        assert object_sha(b"blob", b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        found = scan(gitdir, re.compile(rb"flag\{[^}]+\}"))
        assert len(found) == 1 and found[0][1] == "blob", found
        assert found[0][3] == ["flag{loose_object_leak}"] and found[0][2] == len(blob)
        assert len(scan(gitdir, None, "commit")) == 1
        print("selftest OK - loose blob and commit parsed, flag recovered")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return 0

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("gitdir", nargs="?", default=".git")
    ap.add_argument("--grep", help="regex applied to object content")
    ap.add_argument("--type", choices=["blob", "tree", "commit", "tag"])
    ap.add_argument("--show", action="store_true", help="print the object body")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not os.path.isdir(args.gitdir):
        print(f"not a directory: {args.gitdir}", file=sys.stderr)
        return 1
    n = len(scan(args.gitdir, re.compile(args.grep.encode()) if args.grep else None,
                 args.type, args.show))
    print(f"\n{n} matched; PACKED objects are NOT covered - unpack the .pack first",
          file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Parse .git/index (DIRC v2) and print paths, modes, sizes and sha1s.

Big-endian:  "DIRC" | u32 version | u32 count, then per entry u32 ctime_s ctime_ns
mtime_s mtime_ns dev ino mode uid gid size | 20 raw sha1 bytes | u16 flags
(assume_valid<<15 | extended<<14 | stage<<12 | name_len) | NUL-terminated path |
1-8 NULs padding to a multiple of 8, with mode 0o100644/0o100755/0o120000 (symlink)
/0o160000 (gitlink). The index is the most useful file from a partially dumped .git:
it names every tracked path AND the blob sha to fetch, which --urls emits as curl.
"""
import argparse, datetime as dt, struct, sys

HEADER = struct.Struct(">4sII")
ENTRY = struct.Struct(">10I20sH")   # 40 + 20 + 2 = 62 bytes

def parse(data: bytes):
    """Return (version, declared_count, entries)."""
    if len(data) < HEADER.size:
        raise ValueError("file too short to be a git index")
    magic, version, count = HEADER.unpack_from(data, 0)
    if magic != b"DIRC":
        raise ValueError(f"bad magic {magic!r}, expected b'DIRC'")
    if version == 4:
        raise ValueError("index v4 path-compresses names; use `git ls-files -s`")
    if version not in (2, 3):
        raise ValueError(f"unsupported index version {version}")
    entries, pos = [], HEADER.size
    for _ in range(count):
        if pos + ENTRY.size > len(data):
            break
        (ctime_s, _c, mtime_s, _m, dev, ino, mode, uid, gid, size,
         sha, flags) = ENTRY.unpack_from(data, pos)
        field_end, name_len = pos + ENTRY.size, flags & 0x0FFF
        if version == 3 and flags & 0x4000:
            field_end += 2                       # 16 bits of extended flags
        end = (field_end + name_len if name_len < 0x0FFF
               else data.find(b"\x00", field_end))
        pos += ((end - pos + 8) // 8) * 8         # 1-8 NUL bytes of padding
        entries.append({"path": data[field_end:end].decode("utf-8", "replace"),
                        "sha": sha.hex(), "mode": mode, "size": size, "uid": uid, "gid": gid,
                        "dev": dev, "ino": ino, "ctime": ctime_s, "mtime": mtime_s,
                        "stage": (flags >> 12) & 0x3})
    return version, count, entries

def mode_str(mode: int) -> str:
    return f"{mode:06o} " + {0o100: "file", 0o120: "symlink",
                             0o160: "gitlink"}.get(mode >> 9, "?")

def stamp(epoch: float) -> str:
    if epoch <= 0:
        return "-"
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def selftest():
    """Serialise a minimal v2 index, then parse it back and check every field."""
    fixture = [("src/app.py", "aa" * 20, 0o100644, 1234),
               ("deploy/.env", "bb" * 20, 0o100600, 57), ("link", "cc" * 20, 0o120000, 11)]
    data = bytearray(HEADER.pack(b"DIRC", 2, len(fixture)))
    for path, sha_hex, mode, size in fixture:
        raw = path.encode()
        blob = ENTRY.pack(1700000000, 0, 1700000001, 0, 2049, 4242, mode, 1000, 1000,
                          size, bytes.fromhex(sha_hex), len(raw) & 0x0FFF) + raw
        data += blob + b"\x00" * (8 - (len(blob) % 8))
    version, count, entries = parse(bytes(data))
    assert (version, count, len(entries)) == (2, 3, 3), (version, count, entries)
    assert [e["path"] for e in entries] == ["src/app.py", "deploy/.env", "link"]
    assert entries[0]["sha"] == "aa" * 20
    assert entries[1]["size"] == 57 and entries[1]["mode"] == 0o100600
    assert mode_str(0o100644).endswith("file") and mode_str(0o120000).endswith("symlink")
    assert mode_str(0o160000).endswith("gitlink") and stamp(entries[0]["mtime"])[:4] == "2023"
    try:
        parse(b"XXXX" + b"\x00" * 8)
    except ValueError as exc:
        assert "bad magic" in str(exc)
    print("selftest OK - 3 index entries round-tripped")
    return 0

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default=".git/index")
    ap.add_argument("--urls", help="base .git URL; print a fetch command per blob sha")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    try:
        with open(args.path, "rb") as fh:
            version, count, entries = parse(fh.read())
    except (FileNotFoundError, ValueError) as exc:
        print(f"{args.path}: {exc}", file=sys.stderr)
        return 1
    print(f"DIRC v{version}, {count} declared entries, {len(entries)} parsed\n")
    base = (args.urls or "").rstrip("/")
    for e in entries:
        sha = e["sha"]
        print(f"{sha}  {mode_str(e['mode']):<16s} {e['size']:>10d}  "
              f"{stamp(e['mtime'])}  {e['path']}")
        if base:
            print(f"  curl -sf {base}/objects/{sha[:2]}/{sha[2:]} "
                  f"-o .git/objects/{sha[:2]}/{sha[2:]} --create-dirs")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **The scripts above only see loose objects.** Anything in `objects/pack/*.pack` needs
  `git unpack-objects` first, and a `git gc`-ed repo has almost everything packed. `git fsck`
  **without** `--no-reflogs` treats reflog entries as roots, so deleted commits look reachable --
  run it both ways and diff.
- `git gc --prune=now` and `git reflog expire --expire=now --all` really do destroy the
  evidence, and even `git status` rewrites `.git/index` -- so work on a copy.
- A shallow clone (`.git/shallow`) does not contain older history. Commit timestamps are
  attacker-controlled; reflog timestamps are local wall-clock and far harder to fake.
- `git-dumper` cannot recover objects that only lived in a pack the server does not expose (no
  `objects/info/packs`, no listing). Fall back to `.git/index` plus per-sha fetches, which is
  what `--urls` above generates.
- A secret removed by `git rm` is still in every earlier commit; one removed with `filter-repo`
  or BFG is still on the remote until a force-push **and** the remote's GC, and fork/PR refs keep
  it alive indefinitely.
- `.git/index` v4 path-compresses names, so the parser refuses it; use `git ls-files -s
  --debug`. Check for `.git-credentials` and `.netrc` beside the repo: plaintext tokens.

## Tools and references

`git` (`fsck`, `cat-file`, `rev-list`, `verify-pack`, `unpack-objects`, `reflog`, `log -S/-G`,
`show`, `stash`, `ls-files`), `git-dumper`, `GitTools`, `trufflehog`, `gitleaks`, `dvcs-ripper`,
`BFG Repo-Cleaner`, `git-filter-repo`.
`man git-fsck`, `man git-cat-file`, `man git-rev-list`, `man git-verify-pack` and `man git-log`
(`-S`, `-G`, `--pickaxe-all`, `--full-history`) document every flag above; `gitformat-index` and
`gitformat-pack` define the DIRC and packfile layouts implemented here.
