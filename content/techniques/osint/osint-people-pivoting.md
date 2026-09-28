---
title: "Username, Email and People Pivoting"
category: osint
subcategory: people
type: technique
tags: [osint, username-enumeration, sherlock, maigret, whatsmyname, holehe, epieos, gravatar, email-permutation, profile-pivot, timezone-correlation, people-search, socmint]
difficulty: medium
summary: "One handle is a seed: enumerate it across platforms, derive candidate emails, hash it for gravatar, and correlate what each profile leaks."
when_to_use:
  - "You are given a username, a display name or an email and asked for something else"
  - "A profile links to another platform and you need the full set"
  - "You must find an author's other accounts to locate the planted flag"
  - "You need to confirm two accounts belong to the same person"
tools: [sherlock, maigret, holehe, epieos, whatsmyname, python3, exiftool]
related: [osint-methodology, osint-social-and-archives, osint-documents-and-code, osint-infrastructure, osint-tools-cheatsheet]
---

## TL;DR

People reuse handles. Take the seed handle, check it on every platform, and read *every field*
of every hit: bio, location, join date, pinned post, linked sites, avatar. Each field is a new
seed. Derive candidate emails from the name and the domain, and check which ones exist through
account-recovery signals - never by contacting anyone.

## Recognise it

- The challenge gives a handle, a display name, an avatar, or an email address.
- A profile bio contains a second handle, a personal domain, or a shortened link.
- A GitHub commit shows an email you were not given.
- Two accounts have the same avatar, the same unusual phrasing, or the same posting hours.

## Step 1 - enumerate the handle

```bash
# sherlock: checks a username against hundreds of sites
sherlock exampleuser
sherlock exampleuser --timeout 10 --print-found
sherlock user1 user2 --output-folder ./results

# maigret: broader site list, produces an HTML/PDF report and extracts profile data
maigret exampleuser
maigret exampleuser --html --pdf
maigret exampleuser -a                     # all sites, including the slow ones

# whatsmyname is the underlying data set many tools use; the web UI takes a username
# and runs the same checks in the browser
```

Then **check the hits by hand**. Automated enumerators produce false positives (a site that
returns 200 for every username) and false negatives (a site behind Cloudflare). A hit is only
real when you load the profile and it exists.

### Handle variations worth trying

```text
exampleuser        example.user       example_user      example-user
exampleuser1       exampleuser2026    theexampleuser    exampleuser_
exuser             e_user             euser             example.u
firstlast          flast              first.last        f.last
lastfirst          firstl             first_l           first-last
```

If the seed is a real name, generate these mechanically (the code below does).

## Step 2 - email discovery and validation

```bash
# holehe: which sites have an account registered to this address
holehe user@example.com
holehe --only-used user@example.com

# epieos (web): given an email, shows linked Google services and other public signals
# (paste the address into the site; there is no offline equivalent)

# GitHub leaks commit emails in the API and in patch files
curl -s https://api.github.com/users/exampleuser/events/public | \
  grep -oE '"email": "[^"]+"' | sort -u
curl -s https://github.com/owner/repo/commit/<sha>.patch | grep '^From:'
git log --format='%ae %an' | sort -u        # in a cloned repo

# gravatar: an md5 of the lowercased, trimmed email is the avatar URL
python3 -c "import hashlib;print('https://www.gravatar.com/avatar/'+hashlib.md5(b'user@example.com').hexdigest())"
# the JSON profile, when the user made one
python3 -c "import hashlib;print('https://www.gravatar.com/'+hashlib.md5(b'user@example.com').hexdigest()+'.json')"
```

**Gravatar is the highest-value email check in CTF**: it is a pure hash lookup, needs no
account, and a hit proves the address exists and often gives you a name, a location and links.

Because it is an unsalted MD5, you can also go the other way: hash a list of candidate
addresses and look for the one whose avatar matches a profile picture you already have.

## Step 3 - email permutations

Given a first name, last name and a domain, the plausible formats are a short, fixed list:

```text
first@            flast@            first.last@       firstl@
last@             lfirst@           last.first@       f.last@
firstlast@        first_last@       first-last@       f-last@
lastf@            fl@               firstl@           first.l@
```

Ten to fifteen candidates cover almost every corporate convention. Confirm which one is real
using a **passive** signal: a published document's metadata, a commit email, a mailing list
archive, a gravatar hit, or a press release - never by sending mail.

## Step 4 - correlate

Once you have several accounts, prove (or disprove) that they are the same person:

| Signal | How to use it |
| --- | --- |
| Avatar | identical file, or the same image at a different size; hash it, or reverse-search it |
| Bio phrasing | an unusual phrase repeated verbatim is strong evidence |
| Join dates | accounts created within minutes of each other |
| Posting hours | histogram the timestamps -> the author's waking hours -> timezone |
| Language and typos | consistent misspellings, keyboard layout artefacts |
| Linked domains | a personal site referenced from several profiles |
| Follower overlap | the same small set of followers across platforms |
| Commit metadata | `git log` name+email pairs tie a code account to an identity |

### Timezone from posting times

Collect the UTC timestamps of a person's public posts and histogram them by hour. The gap -
usually 6 to 8 consecutive hours with almost no activity - is their night. The centre of the
gap is roughly 03:00 local, which gives the UTC offset. The code below does this.

## Step 5 - other identifiers

- **Phone numbers**: country code plus the national format tells you the country and often the
  carrier or region. `phoneinfoga` automates the public lookups.
- **Profile pictures**: reverse image search them; many are stock photos, and the stock source
  is sometimes itself the clue.
- **Display names in different scripts**: a transliterated name narrows the origin.
- **Keybase-style identity proofs** and GPG key UIDs tie a handle to an email publicly.
- **Public code forge profiles** (GitHub, GitLab, Codeberg) expose join date, starred repos,
  organisations and contribution calendars.

## Code

```python
#!/usr/bin/env python3
"""People-pivoting helpers: handle variants, email permutations, gravatar URLs,
profile URL construction and timezone inference from posting times.

  python3 people_pivot.py handles "John Mendel"
  python3 people_pivot.py emails John Mendel example.com
  python3 people_pivot.py gravatar user@example.com
  python3 people_pivot.py urls exampleuser
  python3 people_pivot.py --selftest
"""
from __future__ import annotations

import hashlib
import re
import sys
from collections import Counter

# Platforms whose public profile URL is a simple template. Only sites whose URL
# structure is stable and well known are listed.
PROFILE_TEMPLATES = {
    "github": "https://github.com/{u}",
    "gitlab": "https://gitlab.com/{u}",
    "codeberg": "https://codeberg.org/{u}",
    "reddit": "https://www.reddit.com/user/{u}",
    "hackernews": "https://news.ycombinator.com/user?id={u}",
    "keybase": "https://keybase.io/{u}",
    "medium": "https://medium.com/@{u}",
    "dev.to": "https://dev.to/{u}",
    "stackoverflow": "https://stackoverflow.com/users?tab=Reputation&filter=all&search={u}",
    "pypi": "https://pypi.org/user/{u}/",
    "npm": "https://www.npmjs.com/~{u}",
    "dockerhub": "https://hub.docker.com/u/{u}",
    "tryhackme": "https://tryhackme.com/p/{u}",
    "hackthebox": "https://app.hackthebox.com/users/{u}",
    "ctftime": "https://ctftime.org/user/{u}",
    "pastebin": "https://pastebin.com/u/{u}",
    "soundcloud": "https://soundcloud.com/{u}",
    "twitch": "https://www.twitch.tv/{u}",
    "youtube": "https://www.youtube.com/@{u}",
    "mastodon.social": "https://mastodon.social/@{u}",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def normalise(name: str) -> tuple[str, str]:
    """Split a display name into (first, last), lowercased and stripped of punctuation."""
    parts = [re.sub(r"[^a-z0-9]", "", p.lower()) for p in name.split()]
    parts = [p for p in parts if p]
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[-1]


def handle_variants(name: str, extra: list[str] | None = None) -> list[str]:
    """Plausible usernames for a person, ordered roughly by likelihood."""
    first, last = normalise(name)
    out: list[str] = []
    if first and last:
        f, l = first[0], last[0]
        out += [
            f"{first}{last}", f"{first}.{last}", f"{first}_{last}", f"{first}-{last}",
            f"{f}{last}", f"{f}.{last}", f"{f}_{last}",
            f"{first}{l}", f"{first}.{l}",
            f"{last}{first}", f"{last}.{first}", f"{last}{f}",
            first, last, f"{f}{l}",
        ]
    elif first:
        out += [first, f"{first}1", f"the{first}", f"{first}_"]
    for base in list(out):
        out.append(f"{base}1")
        out.append(f"the{base}")
    for e in extra or []:
        out.append(e)
    seen: set[str] = set()
    uniq = []
    for h in out:
        if h and h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def email_permutations(first: str, last: str, domain: str) -> list[str]:
    """The standard corporate address formats."""
    first, last = first.lower(), last.lower()
    f, l = (first[:1], last[:1]) if first and last else ("", "")
    locals_ = [
        first, last, f"{first}{last}", f"{first}.{last}", f"{first}_{last}",
        f"{first}-{last}", f"{f}{last}", f"{f}.{last}", f"{f}_{last}",
        f"{first}{l}", f"{first}.{l}", f"{last}{first}", f"{last}.{first}",
        f"{last}{f}", f"{f}{l}",
    ]
    seen: set[str] = set()
    out = []
    for loc in locals_:
        loc = loc.strip("._-")
        if loc and loc not in seen:
            seen.add(loc)
            out.append(f"{loc}@{domain}")
    return out


def gravatar_urls(email: str, size: int = 256) -> dict[str, str]:
    """Gravatar avatar and profile URLs. The hash is md5 of the trimmed, lowercased address."""
    digest = hashlib.md5(email.strip().lower().encode()).hexdigest()
    return {
        "md5": digest,
        "avatar": f"https://www.gravatar.com/avatar/{digest}?s={size}&d=404",
        "profile_json": f"https://www.gravatar.com/{digest}.json",
        "profile_page": f"https://www.gravatar.com/{digest}",
    }


def match_gravatar(candidates: list[str], target_md5: str) -> str | None:
    """Which candidate address produces this gravatar hash? (unsalted md5, so this works)"""
    target = target_md5.strip().lower()
    for addr in candidates:
        if hashlib.md5(addr.strip().lower().encode()).hexdigest() == target:
            return addr
    return None


def profile_urls(handle: str) -> dict[str, str]:
    return {site: tmpl.format(u=handle) for site, tmpl in PROFILE_TEMPLATES.items()}


def emails_in_text(text: str) -> list[str]:
    """Every address in a blob of text - run this over commit logs, pages, PDFs."""
    return sorted(set(m.group(0).lower() for m in EMAIL_RE.finditer(text)))


def infer_timezone(utc_hours: list[int]) -> tuple[int, str]:
    """Guess a UTC offset from the hours (0-23, UTC) at which someone posts.

    Finds the longest run of consecutive low-activity hours (their night) and assumes
    its centre is 03:00 local time.
    """
    counts = Counter(h % 24 for h in utc_hours)
    if not counts:
        return 0, "no data"
    total = sum(counts.values())
    threshold = total / 24 * 0.4
    quiet = [h for h in range(24) if counts.get(h, 0) <= threshold]
    if not quiet or len(quiet) == 24:
        return 0, "activity is uniform; no usable night gap"

    # longest circular run of quiet hours
    best_start, best_len = 0, 0
    for start in quiet:
        length = 0
        while (start + length) % 24 in quiet and length < 24:
            length += 1
        if length > best_len:
            best_start, best_len = start, length
    centre = (best_start + best_len / 2 - 0.5) % 24
    offset = int(round((3 - centre) % 24))
    if offset > 12:
        offset -= 24
    return offset, (f"quiet {best_start:02d}:00-{(best_start + best_len) % 24:02d}:00 UTC "
                    f"({best_len} h) -> local night centred on 03:00 -> UTC{offset:+d}")


def same_person_score(a: dict, b: dict) -> tuple[int, list[str]]:
    """Crude corroboration score between two profile dicts."""
    score = 0
    reasons = []
    for key, weight, label in (
        ("avatar_md5", 4, "identical avatar"),
        ("email", 4, "same email"),
        ("website", 3, "same linked website"),
        ("location", 1, "same stated location"),
        ("display_name", 2, "same display name"),
        ("bio", 3, "identical bio text"),
    ):
        va, vb = a.get(key), b.get(key)
        if va and vb and str(va).strip().lower() == str(vb).strip().lower():
            score += weight
            reasons.append(label)
    if a.get("timezone") is not None and a.get("timezone") == b.get("timezone"):
        score += 1
        reasons.append("same inferred timezone")
    return score, reasons


def main(argv: list[str]) -> int:
    if not argv or argv[0] == "--selftest":
        _selftest()
        return 0
    cmd = argv[0]
    if cmd == "handles":
        for h in handle_variants(" ".join(argv[1:])):
            print(h)
    elif cmd == "emails":
        for e in email_permutations(argv[1], argv[2], argv[3]):
            print(e)
    elif cmd == "gravatar":
        for k, v in gravatar_urls(argv[1]).items():
            print(f"{k:<13} {v}")
    elif cmd == "urls":
        for site, url in profile_urls(argv[1]).items():
            print(f"{site:<16} {url}")
    elif cmd == "tz":
        hours = [int(x) for x in argv[1:]]
        off, why = infer_timezone(hours)
        print(f"UTC{off:+d}  ({why})")
    else:
        print(__doc__)
        return 1
    return 0


def _selftest() -> None:
    # handle variants
    hs = handle_variants("John Mendel")
    assert "johnmendel" in hs and "john.mendel" in hs and "jmendel" in hs, hs[:10]
    assert "mendeljohn" in hs and "jm" in hs, hs
    assert len(hs) == len(set(hs)), "variants must be de-duplicated"
    single = handle_variants("Madonna")
    assert "madonna" in single and "themadonna" in single, single

    # normalisation strips punctuation and handles middle names
    assert normalise("Jean-Luc  Picard!") == ("jeanluc", "picard")
    assert normalise("Ada Byron Lovelace") == ("ada", "lovelace")
    assert normalise("") == ("", "")

    # email permutations
    es = email_permutations("John", "Mendel", "example.com")
    for want in ("john.mendel@example.com", "jmendel@example.com",
                 "john@example.com", "johnm@example.com"):
        assert want in es, (want, es)
    assert len(es) == len(set(es))
    assert all(e.count("@") == 1 for e in es)

    # gravatar: the documented hash of the canonical test address
    g = gravatar_urls("user@example.com")
    assert g["md5"] == hashlib.md5(b"user@example.com").hexdigest()
    assert gravatar_urls("  USER@Example.COM ")["md5"] == g["md5"], "must trim and lowercase"
    assert g["avatar"].startswith("https://www.gravatar.com/avatar/")
    assert match_gravatar(["a@b.c", "user@example.com"], g["md5"]) == "user@example.com"
    assert match_gravatar(["a@b.c"], g["md5"]) is None

    # profile URLs
    urls = profile_urls("exampleuser")
    assert urls["github"] == "https://github.com/exampleuser"
    assert urls["reddit"] == "https://www.reddit.com/user/exampleuser"
    assert all(u.startswith("https://") for u in urls.values())
    assert len(urls) >= 15

    # email extraction
    text = "From: John Mendel <john.mendel@example.com>\nCc: OTHER@Example.COM, x@y"
    found = emails_in_text(text)
    assert "john.mendel@example.com" in found and "other@example.com" in found, found

    # timezone inference: someone quiet 00:00-07:00 UTC is around UTC+0
    hours = [h for h in range(8, 24) for _ in range(10)]
    off, why = infer_timezone(hours)
    assert -2 <= off <= 2, (off, why)
    # shift the same pattern 8 hours later in UTC -> the offset moves by -8
    shifted = [(h + 8) % 24 for h in hours]
    off2, _ = infer_timezone(shifted)
    assert -10 <= off2 <= -6, off2
    assert infer_timezone([])[1] == "no data"
    assert infer_timezone(list(range(24)) * 5)[0] == 0

    # corroboration scoring
    a = {"avatar_md5": "abc", "display_name": "J. Mendel", "bio": "hacker", "timezone": 1}
    b = {"avatar_md5": "abc", "display_name": "j. mendel", "bio": "hacker", "timezone": 1}
    score, reasons = same_person_score(a, b)
    assert score >= 9 and "identical avatar" in reasons, (score, reasons)
    c = {"avatar_md5": "zzz", "display_name": "someone else"}
    assert same_person_score(a, c)[0] == 0

    print(f"selftest ok: {len(hs)} handle variants, {len(es)} email formats, gravatar hash "
          f"{g['md5'][:8]}..., {len(urls)} profile templates, timezone UTC{off2:+d}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

## Variants and pitfalls

- **Automated enumerators lie in both directions.** Verify every hit by loading the profile.
- **A common handle is not a pivot.** If `admin` or `john` is your seed, you need a second,
  rarer identifier before enumeration is meaningful.
- **Never contact anyone.** No messages, no friend requests, no emails, no phone calls. A CTF
  answer is never behind an interaction.
- **Do not use breach databases.** They are ethically and often legally problematic, and no
  well-designed challenge requires one.
- **Gravatar hashes are unsalted MD5**, which is exactly why you can test candidate addresses
  offline - and also why you should not publish the hashes you find.
- **Commit emails are the most reliable identity link** in developer-themed challenges. Clone
  the repo and run `git log --format='%ae %an' | sort -u`.
- **`noreply` addresses** (for example GitHub's per-user noreply form) still encode the account
  id and username - that is a pivot, not a dead end.
- **Timezone inference needs at least a few dozen timestamps** and fails for people who post on
  a schedule or through a scheduler.
- **Display names change; numeric ids do not.** Where a platform exposes a numeric or snowflake
  id, record it - it survives renames.
- **Redact real personal data in your writeup.** The challenge author's planted persona is fair
  game; anything that leaked about a real person is not.

## Tools

`sherlock`, `maigret`, WhatsMyName (the data set behind several of these), `holehe`, Epieos
(web), `theHarvester` for domain-scoped address collection, `phoneinfoga` for phone numbers,
`GHunt` for Google-account artefacts, `exiftool` for document authorship, `git log` for commit
identities.

## References

- Sherlock project: https://github.com/sherlock-project/sherlock
- Maigret project: https://github.com/soxoj/maigret
- holehe project: https://github.com/megadose/holehe
- Gravatar's documented avatar URL scheme (MD5 of the trimmed, lowercased address):
  https://docs.gravatar.com/
