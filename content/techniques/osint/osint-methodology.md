---
title: "OSINT Methodology for CTF"
category: osint
subcategory: methodology
type: technique
tags: [osint, methodology, pivoting, seed, question-types, scoping, verification, note-taking, link-graph, ethics, rules-of-engagement, attribution, open-source-intelligence]
difficulty: easy
summary: "Classify the question, bound the search to what the author could have planted, then run a disciplined seed-and-pivot loop with two-source verification."
when_to_use:
  - "A challenge gives you a name, a photo, a handle or a domain and one question"
  - "You are drowning in search results and not converging"
  - "You found an answer but are not sure it is the intended one"
  - "You need to decide when to stop digging and move on"
tools: [browser, exiftool, sherlock, whois, wayback]
related: [osint-geolocation, osint-people-pivoting, osint-infrastructure, osint-social-and-archives, osint-documents-and-code, osint-tools-cheatsheet]
---

## TL;DR

CTF OSINT is not real-world OSINT. The author **planted** the answer, recently, in a place a
solver can reach for free. That single fact bounds the search enormously: prefer artifacts the
author created (a fresh account, a new repository, a specific photo) over the vast pre-existing
internet. Classify the question, enumerate the plantable locations, pivot, verify twice, stop.

## Recognise the question type

| Question shape | What you are really being asked | Go to |
| --- | --- | --- |
| "Who is this person?" / "What is their email?" | pivot a handle or a name across platforms | `osint-people-pivoting` |
| "Where was this taken?" | geolocate an image | `osint-geolocation` |
| "What is the IP / subdomain / server?" | infrastructure enumeration | `osint-infrastructure` |
| "What did they post before deleting it?" | archive recovery | `osint-social-and-archives` |
| "Who wrote this document?" / "What is in their repo?" | metadata and code leaks | `osint-documents-and-code` |
| "When did X happen?" | timestamp forensics (EXIF, post IDs, archives) | `osint-social-and-archives` |
| "What is the flag hidden in this profile?" | read every field of every artifact the author made | all of the above |

A challenge usually chains two or three of these: a photo gives a location, the location gives
a business, the business gives a website, the website gives a person, the person gives the flag.

## Bounding the search

Ask these five questions before you start clicking:

1. **What artifact did the author have to create?** A GitHub account, a Twitter/X profile, a
   Pastebin, a domain, an uploaded photo. That artifact is young, sparse and unusual - which
   makes it findable.
2. **What must be free and public?** Challenges cannot require a paid data broker, a private
   API key, or a subpoena. If your lead requires one, it is the wrong lead.
3. **What is the flag format?** If the flag is `flag{...}`, the answer is a string somewhere,
   not a conclusion. If the answer is "the name of the street", it is a fact.
4. **How old is the challenge?** An event from 2019 may reference content that is now only in
   the Wayback Machine.
5. **What is explicitly out of scope?** Real people who are not the author, actual companies,
   anything requiring authentication to someone else's account.

## The seed-and-pivot loop

```text
seed  ->  expand  ->  filter  ->  new seed
```

- **Seed**: the one unique string you were given (a handle, an email, a domain, a phrase).
- **Expand**: search it verbatim, in quotes, on several engines; run it through the
  platform-specific enumerators; look for it in archives.
- **Filter**: keep only results that are plausibly the author's artifact - created recently,
  low follower count, references the CTF or a related word, has the same avatar.
- **New seed**: every result gives new strings (a second handle, a real name, an email, a
  repository, a location). Feed them back in.

Stop expanding a branch when it produces only pre-existing, unrelated content.

### Uniqueness is everything

Search the **most unusual string** you have, not the most descriptive one. `"j.mendel.1987"`
beats `"john mendel photographer"` every time. Quote it. If a string appears in fewer than
about twenty results, it is a good pivot; if it appears in millions, it is not a pivot at all.

## Note-taking

Keep a single file per challenge with four sections. This is not bureaucracy - it is how you
avoid re-searching the same thing at 3am.

```text
# chal: <name>
## question
one sentence: exactly what has to be produced, and in what format

## seeds
handle:  @exampleuser          (given)
email:   user@example.com      (from the profile bio)
domain:  example.ctf           (from the email)

## findings                      (fact, source URL, timestamp, confidence)
- GitHub user exampleuser created 2026-03-02   https://...   high
- commit email user@example.com                 https://...   high
- photo EXIF GPS 48.8583, 2.2945                local file    high

## dead ends
- LinkedIn: no account with this name (checked, do not repeat)
- reverse image search on the avatar: only stock photo results
```

Record dead ends explicitly. Half of a long OSINT challenge is not repeating work.

## Verification

Before you submit, get **two independent confirmations** of the answer:

- Two different sources that do not derive from each other (a profile bio and a commit email
  are independent; a profile bio and a site that scraped that profile are not).
- An internal consistency check: do the timestamps, timezone, language and location agree?
- A negative check: is there another candidate that fits equally well? If yes, you have not
  finished.

For CTF specifically, a third check: **does the answer look like something an author would
plant?** A flag-shaped string, a deliberately odd name, a repository with one commit.

## Knowing when to stop

You are going in circles when:

- Three consecutive pivots produce only pre-existing, unrelated content.
- You are relying on a paid service, a private database, or guessing.
- You are trying to identify a real person who is not the challenge author.

Then: re-read the challenge text word by word (the constraint you missed is there), check the
artifact itself for metadata you skipped, and look at the challenge from the author's side -
where would *you* have hidden it?

## Ethics and rules of engagement

- **Never interact with people.** Do not message, friend-request, phone, or email anyone. OSINT
  in a CTF is passive by definition.
- **Never log in to an account that is not yours**, and never attempt to.
- **Do not attack the infrastructure** you discover unless the challenge scope says to. Finding
  a subdomain is OSINT; exploiting it may be out of scope and against the rules.
- **Real third parties are off limits.** If a search leads to a private individual unconnected
  to the challenge, stop - you took a wrong turn.
- **Do not use leaked-credential databases** for a CTF. Beyond the legal and ethical issues, no
  well-designed challenge requires one.
- **Respect rate limits and robots.txt.** Hammering a service to enumerate it is noisy and may
  be against the event rules.
- **Do not publish what you found about people** in a writeup without redacting it.

## Worked example (structure, not a real challenge)

```text
given:    a photo, and "our engineer posted this on his way to the office"
question: the name of the company

1. exiftool photo.jpg              -> no GPS (stripped), but Software = "Pixel 7"
2. read the image                  -> a bus stop sign, partial text, left-hand traffic,
                                      a language with a distinctive script
3. narrow the country              -> script + left-hand traffic + bus livery
4. reverse image search the sign   -> the transit operator's site, a specific line
5. line + "office park"            -> a business district
6. street view sweep of the line   -> the building in the photo
7. the building's tenant list      -> candidate companies
8. cross-check with step 1         -> the company whose engineers post on the platform
                                      the challenge mentioned
verify: the company's careers page mentions the role the challenge named (source 2)
```

Every step turns one fact into a *narrower* fact. If a step widens the search instead, it was
the wrong step.

## Code

A small link-graph notebook: record seeds, facts and dead ends, see which seeds are unexplored,
and export the graph so you can look at it when you are stuck.

```python
#!/usr/bin/env python3
"""OSINT case notebook: seeds, facts, dead ends and an explore-next queue.

  python3 osint_case.py new mychal "who owns example.ctf"
  python3 osint_case.py seed mychal handle @exampleuser given
  python3 osint_case.py fact mychal "github user created 2026-03-02" https://... high
  python3 osint_case.py dead mychal "linkedin: no such account"
  python3 osint_case.py next mychal
  python3 osint_case.py report mychal
  python3 osint_case.py --selftest
"""
from __future__ import annotations

import json
import os
import sys
import time

CONFIDENCE = ("low", "medium", "high")
SEED_KINDS = ("handle", "email", "name", "domain", "ip", "phone", "image",
              "phrase", "repo", "url", "other")


class Case:
    def __init__(self, name: str, question: str = ""):
        self.name = name
        self.question = question
        self.seeds: list[dict] = []
        self.facts: list[dict] = []
        self.dead_ends: list[str] = []

    # -- mutation ---------------------------------------------------------
    def add_seed(self, kind: str, value: str, origin: str = "given") -> bool:
        if kind not in SEED_KINDS:
            raise ValueError(f"kind must be one of {SEED_KINDS}")
        if any(s["value"] == value for s in self.seeds):
            return False
        self.seeds.append({"kind": kind, "value": value, "origin": origin,
                           "explored": False, "added": time.time()})
        return True

    def add_fact(self, text: str, source: str, confidence: str = "medium") -> None:
        if confidence not in CONFIDENCE:
            raise ValueError(f"confidence must be one of {CONFIDENCE}")
        self.facts.append({"text": text, "source": source,
                           "confidence": confidence, "added": time.time()})

    def add_dead_end(self, text: str) -> None:
        if text not in self.dead_ends:
            self.dead_ends.append(text)

    def mark_explored(self, value: str) -> bool:
        for s in self.seeds:
            if s["value"] == value:
                s["explored"] = True
                return True
        return False

    # -- queries ----------------------------------------------------------
    def unexplored(self) -> list[dict]:
        return [s for s in self.seeds if not s["explored"]]

    def corroborated(self, min_sources: int = 2) -> list[str]:
        """Facts backed by at least `min_sources` DISTINCT sources."""
        by_text: dict[str, set[str]] = {}
        for f in self.facts:
            by_text.setdefault(f["text"], set()).add(f["source"])
        return [t for t, srcs in by_text.items() if len(srcs) >= min_sources]

    def uncorroborated(self) -> list[str]:
        by_text: dict[str, set[str]] = {}
        for f in self.facts:
            by_text.setdefault(f["text"], set()).add(f["source"])
        return [t for t, srcs in by_text.items() if len(srcs) < 2]

    def stalled(self, branch_limit: int = 3) -> bool:
        """No new fact since the last `branch_limit` seeds were explored."""
        explored = [s for s in self.seeds if s["explored"]]
        if len(explored) < branch_limit or not self.facts:
            return False
        last_fact = max(f["added"] for f in self.facts)
        recent = sorted(s["added"] for s in explored)[-branch_limit:]
        return all(t > last_fact for t in recent)

    # -- persistence ------------------------------------------------------
    def to_dict(self) -> dict:
        return {"name": self.name, "question": self.question, "seeds": self.seeds,
                "facts": self.facts, "dead_ends": self.dead_ends}

    @classmethod
    def from_dict(cls, d: dict) -> "Case":
        c = cls(d["name"], d.get("question", ""))
        c.seeds = d.get("seeds", [])
        c.facts = d.get("facts", [])
        c.dead_ends = d.get("dead_ends", [])
        return c

    def save(self, directory: str = ".") -> str:
        path = os.path.join(directory, f"osint_{self.name}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
        return path

    @classmethod
    def load(cls, name: str, directory: str = ".") -> "Case":
        with open(os.path.join(directory, f"osint_{name}.json"), encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    # -- output -----------------------------------------------------------
    def report(self) -> str:
        lines = [f"# case: {self.name}", f"## question\n{self.question or '(not set)'}",
                 "\n## seeds"]
        for s in self.seeds:
            mark = "x" if s["explored"] else " "
            lines.append(f"[{mark}] {s['kind']:<7} {s['value']}   (from {s['origin']})")
        lines.append("\n## facts")
        for f in sorted(self.facts, key=lambda f: -CONFIDENCE.index(f["confidence"])):
            lines.append(f"- [{f['confidence']:<6}] {f['text']}   <{f['source']}>")
        lines.append("\n## corroborated (>=2 independent sources)")
        lines += [f"- {t}" for t in self.corroborated()] or ["  (none yet)"]
        lines.append("\n## needs a second source")
        lines += [f"- {t}" for t in self.uncorroborated()] or ["  (none)"]
        lines.append("\n## dead ends")
        lines += [f"- {d}" for d in self.dead_ends] or ["  (none)"]
        if self.stalled():
            lines.append("\n!! STALLED: re-read the challenge text and re-examine the "
                         "original artifact before opening another branch")
        return "\n".join(lines)


def main(argv: list[str]) -> int:
    if not argv or argv[0] == "--selftest":
        _selftest()
        return 0
    cmd = argv[0]
    if cmd == "new":
        c = Case(argv[1], " ".join(argv[2:]))
        print(f"[+] {c.save()}")
        return 0
    c = Case.load(argv[1])
    if cmd == "seed":
        added = c.add_seed(argv[2], argv[3], argv[4] if len(argv) > 4 else "derived")
        print("[+] added" if added else "[=] already present")
    elif cmd == "fact":
        c.add_fact(argv[2], argv[3], argv[4] if len(argv) > 4 else "medium")
        print("[+] fact recorded")
    elif cmd == "dead":
        c.add_dead_end(" ".join(argv[2:]))
        print("[+] dead end recorded")
    elif cmd == "explored":
        print("[+] marked" if c.mark_explored(argv[2]) else "[-] no such seed")
    elif cmd == "next":
        for s in c.unexplored():
            print(f"{s['kind']:<7} {s['value']}")
        return 0
    elif cmd == "report":
        print(c.report())
        return 0
    else:
        print(__doc__)
        return 1
    c.save()
    return 0


def _selftest() -> None:
    import tempfile

    tmp = tempfile.mkdtemp()
    c = Case("demo", "who owns example.ctf")
    assert c.add_seed("handle", "@exampleuser", "given") is True
    assert c.add_seed("handle", "@exampleuser") is False       # de-duplicated
    c.add_seed("domain", "example.ctf", "derived from the bio")
    assert len(c.unexplored()) == 2

    c.add_fact("github user created 2026-03-02", "https://github.com/exampleuser", "high")
    c.add_fact("commit email user@example.com", "https://api.github.com/...", "high")
    c.add_fact("commit email user@example.com", "https://gitlab.com/...", "high")
    assert c.corroborated() == ["commit email user@example.com"], c.corroborated()
    assert "github user created 2026-03-02" in c.uncorroborated()

    assert c.mark_explored("@exampleuser") is True
    assert c.mark_explored("@nobody") is False
    assert [s["value"] for s in c.unexplored()] == ["example.ctf"]

    c.add_dead_end("linkedin: no such account")
    c.add_dead_end("linkedin: no such account")
    assert c.dead_ends == ["linkedin: no such account"]

    try:
        c.add_seed("nonsense", "x")
    except ValueError:
        pass
    else:
        raise AssertionError("bad seed kind should be rejected")
    try:
        c.add_fact("x", "y", "certain")
    except ValueError:
        pass
    else:
        raise AssertionError("bad confidence should be rejected")

    path = c.save(tmp)
    loaded = Case.from_dict(json.load(open(path, encoding="utf-8")))
    assert loaded.question == c.question
    assert len(loaded.facts) == 3 and len(loaded.seeds) == 2

    rep = c.report()
    assert "corroborated" in rep and "example.ctf" in rep and "dead ends" in rep

    # stall detection: explore more seeds without adding facts
    for i in range(3):
        c.add_seed("phrase", f"lead{i}", "derived")
        c.mark_explored(f"lead{i}")
        c.seeds[-1]["added"] = time.time() + 10 + i
    assert c.stalled() is True

    print(f"selftest ok: {len(c.seeds)} seeds, {len(c.facts)} facts, "
          f"corroboration and stall detection work")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

## Variants and pitfalls

- **The answer is usually in the artifact you were given**, not on the wider internet. Run
  `exiftool`, read every profile field, view source, check the archive - before searching.
- **Search engines disagree.** Run the same query on at least two; their indexes differ
  substantially for small, recent pages.
- **Quotation marks matter.** Unquoted searches get "helpfully" broadened and you lose the
  exact-match behaviour you need.
- **Recency filters** are your friend: a challenge artifact created last month is trivially
  isolated by restricting the date range.
- **Do not trust aggregators.** People-search sites mostly contain recycled, stale scrapes and
  will happily invent confident-looking nonsense.
- **Time-box each branch.** Twenty minutes with no new fact means the branch is dead.
- **Language and script are strong filters.** A single non-Latin character narrows the world
  faster than any tool.
- **Check whether the challenge is actually solvable offline.** Some "OSINT" challenges are
  really stego or forensics with an OSINT-flavoured description.

## Tools

A browser with multiple search engines, `exiftool`, the Wayback Machine, `sherlock`/`maigret`
for handles, `whois`/`dig`/`crt.sh` for infrastructure, and a plain text file for notes.
See `osint-tools-cheatsheet` for the full list with exact invocations.

## References

- The Wayback Machine and its CDX API (Internet Archive): https://web.archive.org/
- ExifTool documentation: https://exiftool.org/
- OSINT Framework (a directory of categories and tools): https://osintframework.com/
