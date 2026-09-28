---
title: "Brute Forcing Passworded Stego Tools"
category: stego
subcategory: bruteforce
type: technique
tags: [steghide, stegseek, stegcracker, outguess, openstego, jphide, silenteye, deepsound, wordlist, rockyou, bruteforce, multiprocessing, stego, passphrase]
difficulty: easy
summary: "stegseek cracks steghide against rockyou in seconds; everything else needs a scripted loop plus output validation."
when_to_use:
  - "steghide info says the file may contain embedded data"
  - "The challenge text contains a plausible passphrase (a name, a date, a word in bold)"
  - "Triage found no metadata, no appended data and no LSB, but the carrier is JPEG/BMP/WAV/AU"
  - "You have many candidate images and one password, or one image and many passwords"
tools: [stegseek, steghide, stegcracker, outguess, openstego, stegoveritas, john, crunch, cewl, python3]
related: [image-triage, jpeg-structure-attacks, audio-stego, stego-cheatsheet, archive-attacks, lsb-extraction]
---

## TL;DR

`stegseek chal.jpg rockyou.txt` finishes the whole of rockyou in a few seconds because it
attacks steghide's *seed* rather than performing a full decryption per candidate. If the
carrier is not a steghide carrier, fall back to a multi-process loop over the tool's CLI and
validate every "success" by checking the output for a file magic or printable text.

## Recognise it

- Carrier type matches a tool: **steghide** accepts JPEG, BMP, WAV and AU **only** - not PNG,
  not MP3, not GIF.
- `steghide info -p '' chal.jpg` returns "could not extract any data with that passphrase"
  rather than "the file format is not supported" - so it *is* a plausible carrier.
- The challenge description contains a single conspicuous noun, name, or date.
- `stegoveritas` or `aperisolve` already ran everything else and found nothing.
- File size is slightly larger than a re-encode of the same visible image.

## Attack

### 1. Build the candidate list before reaching for rockyou

Challenge-derived wordlists beat generic ones. In order of likelihood:

```bash
# words from the challenge page / README / image filename
cewl -d 2 -m 4 -w chal_words.txt https://ctf.example/chal   # if there is a web page
tr -cs 'A-Za-z0-9' '\n' < description.txt | sort -u > desc_words.txt

# every string in the image itself (filenames, comments, artist tags)
strings -n 4 chal.jpg | sort -u > strings_words.txt
exiftool -a -u chal.jpg | tr -cs 'A-Za-z0-9' '\n' | sort -u >> strings_words.txt

# case/leet variants of a short list
john --wordlist=chal_words.txt --rules=Jumbo --stdout > chal_mangled.txt
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule chal_words.txt > chal_rules.txt

# fixed-format guesses
crunch 6 6 -t flag%% -o pat.txt          # flag + 2 digits
```

Then the standards: `rockyou.txt`, `/usr/share/wordlists/seclists/Passwords/*`, and finally
the empty password (which many challenges use).

### 2. steghide

```bash
# free first try: the empty passphrase
steghide info -p '' chal.jpg
steghide extract -sf chal.jpg -p '' -xf out.bin

# stegseek: the right tool. -f forces overwrite, -xf names the output
stegseek --crack -f chal.jpg /usr/share/wordlists/rockyou.txt out.bin
stegseek chal.jpg rockyou.txt                     # short form, writes chal.jpg.out

# stegseek can also find the embedded-data marker without any wordlist
stegseek --seed chal.jpg

# stegcracker (much slower, shells out to steghide per candidate)
stegcracker chal.jpg rockyou.txt
```

### 3. outguess, openstego, and the rest

```bash
# outguess: no password, then with one
outguess -r chal.jpg out.txt
outguess -k 'password' -r chal.jpg out.txt

# openstego (Java) - extract with a password
openstego extract -sf chal.png -p password -xd outdir/

# jphide / jpseek (jphs) - jpseek prompts for the passphrase
jpseek chal.jpg out.bin

# stegoveritas runs many of these plus image transforms in one shot
stegoveritas chal.jpg -out results/

# steghide over a directory of carriers with one known password
for f in *.jpg; do steghide extract -sf "$f" -p "$PASS" -xf "${f%.jpg}.out" 2>/dev/null \
  && echo "HIT: $f"; done
```

### 4. Validate every hit

A tool exiting 0 is not proof. Check the extracted blob:

```bash
file out.bin
xxd out.bin | head
strings -n 6 out.bin | head
```

## Code

```python
#!/usr/bin/env python3
"""Multi-process brute forcer for CLI stego tools, with output validation.

Wraps steghide / outguess / openstego. Validates each candidate by checking the
extracted bytes for a file magic or a high printable ratio, so a tool that exits 0
with garbage does not produce a false positive.

Usage:
  python3 stego_brute.py chal.jpg wordlist.txt
  python3 stego_brute.py chal.jpg wordlist.txt --tool outguess --jobs 8
  python3 stego_brute.py --selftest
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import tempfile

MAGICS = {
    b"PK\x03\x04": "zip", b"\x89PNG": "png", b"\xff\xd8\xff": "jpeg", b"GIF8": "gif",
    b"%PDF": "pdf", b"\x1f\x8b\x08": "gzip", b"7z\xbc\xaf": "7z", b"Rar!": "rar",
    b"BZh": "bzip2", b"\x7fELF": "elf", b"-----BEGIN": "pem", b"SQLite": "sqlite",
    b"OggS": "ogg", b"RIFF": "riff", b"\xfd7zXZ": "xz",
}
PRINTABLE = set(range(32, 127)) | {9, 10, 13}

TOOLS = {
    # name: (argv template, whether the payload is written to {out})
    "steghide": ["steghide", "extract", "-sf", "{file}", "-p", "{pw}", "-xf", "{out}", "-f"],
    "outguess": ["outguess", "-k", "{pw}", "-r", "{file}", "{out}"],
    "openstego": ["openstego", "extract", "-sf", "{file}", "-p", "{pw}", "-xd", "{outdir}"],
}


def looks_like_payload(data: bytes, min_printable_ratio: float = 0.85,
                       min_len: int = 4) -> tuple[bool, str]:
    """Heuristic validator: a known magic, or mostly-printable text."""
    if len(data) < min_len:
        return False, "too short"
    for magic, name in MAGICS.items():
        if data.startswith(magic):
            return True, f"magic:{name}"
    sample = data[:4096]
    printable = sum(1 for b in sample if b in PRINTABLE)
    ratio = printable / len(sample)
    if ratio >= min_printable_ratio:
        return True, f"text({ratio:.2f})"
    return False, f"binary({ratio:.2f})"


def try_password(args: tuple[str, str, str]) -> tuple[str, bytes, str] | None:
    """Run the tool once with one candidate. Returns (pw, payload, reason) on a validated hit."""
    tool, path, pw = args
    if tool not in TOOLS:
        return None
    tmpdir = tempfile.mkdtemp(prefix="stegbrute_")
    out = os.path.join(tmpdir, "payload.bin")
    argv = [a.format(file=path, pw=pw, out=out, outdir=tmpdir) for a in TOOLS[tool]]
    try:
        p = subprocess.run(argv, capture_output=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None
    payload = b""
    if os.path.exists(out) and os.path.getsize(out) > 0:
        with open(out, "rb") as fh:
            payload = fh.read()
    else:
        for name in os.listdir(tmpdir):
            fp = os.path.join(tmpdir, name)
            if os.path.isfile(fp) and os.path.getsize(fp) > 0:
                with open(fp, "rb") as fh:
                    payload = fh.read()
                break
    shutil.rmtree(tmpdir, ignore_errors=True)
    if p.returncode != 0 or not payload:
        return None
    ok, reason = looks_like_payload(payload)
    if ok:
        return pw, payload, reason
    return None


def load_wordlist(path: str) -> list[str]:
    words: list[str] = [""]
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.rstrip("\r\n")
            if w:
                words.append(w)
    seen = set()
    out = []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def derive_wordlist(path: str, extra: list[str] | None = None) -> list[str]:
    """Candidate passwords from the file itself: strings, the filename, EXIF-ish text."""
    import re

    with open(path, "rb") as fh:
        data = fh.read()
    words = set(extra or [])
    words.add("")
    base = os.path.basename(path)
    words.add(base)
    words.add(os.path.splitext(base)[0])
    for m in re.finditer(rb"[A-Za-z0-9_@!.-]{3,24}", data[:8192] + data[-8192:]):
        words.add(m.group(0).decode("latin1"))
    return sorted(words)


def brute(path: str, words: list[str], tool: str = "steghide", jobs: int = 0) -> list[tuple[str, bytes, str]]:
    if shutil.which(TOOLS[tool][0]) is None:
        print(f"[!] {tool} is not installed", file=sys.stderr)
        return []
    jobs = jobs or (os.cpu_count() or 4)
    tasks = [(tool, path, w) for w in words]
    hits: list[tuple[str, bytes, str]] = []
    with mp.Pool(jobs) as pool:
        for i, res in enumerate(pool.imap_unordered(try_password, tasks, chunksize=32)):
            if i % 5000 == 0 and i:
                print(f"[.] {i}/{len(tasks)} tried", file=sys.stderr)
            if res:
                pw, payload, reason = res
                print(f"[+] PASSWORD {pw!r} -> {reason}, {len(payload)} bytes: {payload[:80]!r}")
                hits.append(res)
                pool.terminate()
                break
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("wordlist", nargs="?")
    ap.add_argument("--tool", default="steghide", choices=sorted(TOOLS))
    ap.add_argument("--jobs", type=int, default=0)
    ap.add_argument("--derive", action="store_true",
                    help="also try passwords derived from the carrier file itself")
    args = ap.parse_args()

    words: list[str] = []
    if args.derive or not args.wordlist:
        words += derive_wordlist(args.file)
        print(f"[i] {len(words)} candidates derived from the file", file=sys.stderr)
    if args.wordlist:
        words += load_wordlist(args.wordlist)
    seen = set()
    uniq = [w for w in words if not (w in seen or seen.add(w))]
    print(f"[i] {len(uniq)} unique candidates, tool={args.tool}", file=sys.stderr)

    hits = brute(args.file, uniq, args.tool, args.jobs)
    if not hits:
        print("[-] no validated hit. If the carrier is JPEG/BMP/WAV/AU, run: "
              "stegseek --crack -f FILE rockyou.txt")
        return 1
    for pw, payload, _reason in hits:
        out = args.file + ".out"
        with open(out, "wb") as fh:
            fh.write(payload)
        print(f"[+] wrote {out} (password {pw!r})")
    return 0


def _selftest() -> None:
    # validator behaviour
    ok, why = looks_like_payload(b"PK\x03\x04" + b"\x00" * 40)
    assert ok and why == "magic:zip", (ok, why)
    ok, why = looks_like_payload(b"flag{brute_forced}\n")
    assert ok and why.startswith("text"), (ok, why)
    ok, why = looks_like_payload(bytes(range(256)) * 4)
    assert not ok, (ok, why)
    ok, why = looks_like_payload(b"ab")
    assert not ok and why == "too short"

    # wordlist loading keeps order, de-duplicates, and always tries the empty password
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("alpha\nbeta\nalpha\n\ngamma\n")
        wl = fh.name
    words = load_wordlist(wl)
    os.unlink(wl)
    assert words[0] == "" and words[1:] == ["alpha", "beta", "gamma"], words

    # derived wordlist picks strings out of the carrier
    with tempfile.NamedTemporaryFile("wb", suffix=".jpg", delete=False) as fh:
        fh.write(b"\xff\xd8\xff\xe0" + b"SuperSecretKey" + b"\x00" * 100 + b"\xff\xd9")
        carrier = fh.name
    derived = derive_wordlist(carrier)
    assert "SuperSecretKey" in derived, derived[:20]
    assert "" in derived
    assert os.path.splitext(os.path.basename(carrier))[0] in derived
    os.unlink(carrier)

    # try_password must fail closed when the tool is absent or unknown
    assert try_password(("not_a_tool", "/nonexistent", "x")) is None
    print(f"selftest ok: validator, wordlist loader, {len(derived)} derived candidates")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        sys.exit(main())
```

## Variants and pitfalls

- **steghide only accepts JPEG, BMP, WAV and AU.** Running it on a PNG wastes hours. Check the
  carrier type first.
- **`stegseek` beats `stegcracker` by orders of magnitude.** stegcracker spawns a steghide
  process per candidate (~1k/s); stegseek attacks the seed derivation directly (millions/s).
- **Try the empty passphrase first**, then the filename, then words from the challenge text.
  Generic rockyou is the *last* resort, not the first.
- **A zero exit code is not success.** outguess in particular will happily produce garbage.
  Always validate with `file`/magic/printable ratio, as the code above does.
- **openstego is Java** and slow to start (~0.5 s per invocation). Batch it or accept the cost.
- **Case and whitespace matter.** If the hint is `My dog Rex`, try `Rex`, `rex`, `MyDogRex`,
  `my dog rex`; generate the variants with john rules rather than by hand.
- **Multiple layers.** The extracted payload is often another stego file. Re-run triage on it.
- **Do not paralellise beyond your cores.** Each worker spawns a process; oversubscribing makes
  it slower, not faster.
- **DeepSound** (WAV/FLAC) needs DeepSound itself or a compatible reimplementation; its
  container starts with a recognisable `DSCF` signature.
- **If nothing cracks**, reconsider the premise: maybe there is no password and the payload is
  in a place triage did not cover (a second image to diff against, a video frame, the alpha
  channel).

## Tools

`stegseek`, `steghide`, `stegcracker`, `outguess`, `openstego`, `jphs` (`jpseek`/`jphide`),
`stegoveritas`, `aperisolve` (web), `john` (rules/`--stdout`), `hashcat --stdout`, `crunch`,
`cewl`.

## References

- `steghide` manual page: the supported carrier formats and the `info`/`extract` subcommands.
- `stegseek` project README documents the `--crack` and `--seed` modes.
- `outguess` manual page for `-k` (key) and `-r` (retrieve).
