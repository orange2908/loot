---
title: "Mirrored reference corpora - provenance and licences"
category: misc
subcategory: provenance
type: reference
tags: [provenance, licence, license, attribution, corpora, mirror, ctf-wiki, hacktricks, payloadsallthethings, owasp-wstg, awesome-ctf, trail-of-bits, sources, offline, reference]
summary: "Every external reference corpus mirrored into CTF-Brain: repo, commit, licence and page count (973 pages)."
---

# Mirrored reference corpora

Every `content/**/ext-*.md` page in CTF-Brain is a mirror of one document from one
of the corpora below. Nothing here is CTF-Brain's own work: the text belongs to the
original authors and is redistributed under the licence shown, with a `source:` link
back to the exact file at the exact commit in every page's frontmatter.

Regenerate with `python3 ingest/reference_corpora.py all`.

| Corpus | Repository | Commit | Licence | Pages | What was taken |
|---|---|---|---|---|---|
| CTF Wiki | [ctf-wiki/ctf-wiki](https://github.com/ctf-wiki/ctf-wiki) | `e225ddfcd420` | CC BY-NC-SA 4.0 | 254 | docs/en/docs (all English pages) + docs/zh/docs where no English page exists |
| HackTricks | [HackTricks-wiki/hacktricks](https://github.com/HackTricks-wiki/hacktricks) | `6df9a3d76fe6` | CC BY-NC 4.0 | 494 | src/{pentesting-web, binary-exploitation, crypto, stego, reversing, blockchain, mobile-pentesting, hardware-physical-access, generic-methodologies-and-resources (incl. basic-forensic-methodology), generic-hacking} |
| PayloadsAllTheThings | [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | `3ac27901c711` | MIT | 67 | every per-vulnerability README.md. 'Methodology and Resources/*.md' is collected too but is almost all pointer stubs upstream now -- that content moved to swisskyrepo/InternalAllTheThings, which has no licence and is not mirrored |
| OWASP WSTG | [OWASP/wstg](https://github.com/OWASP/wstg) | `ea174034f914` | CC BY-SA 4.0 | 125 | document/4-Web_Application_Security_Testing/**/*.md (the test pages) |
| Trail of Bits CTF Field Guide | [trailofbits/ctf](https://github.com/trailofbits/ctf) | `72f462533d13` | CC BY-SA 4.0 | 12 | the whole field guide (intro, vulnerabilities, exploits, web, forensics, toolkits, tradecraft) |
| ctfs/resources | [ctfs/resources](https://github.com/ctfs/resources) | `68c4287943f5` | CC0 1.0 | 5 | topics/**/*.md and tools/**/*.md |
| Awesome CTF | [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf) | `eb504b242be3` | CC0 1.0 | 16 | README.md, exploded into one reference page per tool-list section |

**Total mirrored pages: 973**

## Licence notes

### CTF Wiki - CC BY-NC-SA 4.0

- Repository: <https://github.com/ctf-wiki/ctf-wiki>
- Licence file read: `LICENSE`
- LICENSE at the repository root is the full text of 'Attribution-NonCommercial-ShareAlike 4.0 International'. The GitHub API reports NOASSERTION; the file itself is unambiguous CC BY-NC-SA 4.0.

### HackTricks - CC BY-NC 4.0

- Repository: <https://github.com/HackTricks-wiki/hacktricks>
- Licence file read: `src/LICENSE.md`
- src/LICENSE.md is the full text of 'Attribution-NonCommercial 4.0 International', Copyright (C) Carlos Polop 2021. The GitHub API reports no licence because the file is not at the repository root. carlospolop/hacktricks now redirects to HackTricks-wiki/hacktricks, which is the current canonical repo.

### PayloadsAllTheThings - MIT

- Repository: <https://github.com/swisskyrepo/PayloadsAllTheThings>
- Licence file read: `LICENSE`
- LICENSE is the MIT licence, Copyright (c) 2019 Swissky.

### OWASP WSTG - CC BY-SA 4.0

- Repository: <https://github.com/OWASP/wstg>
- Licence file read: `LICENSE`
- LICENSE is the full text of Creative Commons Attribution-ShareAlike 4.0 International.

### Trail of Bits CTF Field Guide - CC BY-SA 4.0

- Repository: <https://github.com/trailofbits/ctf>
- Licence file read: `LICENSE`
- LICENSE is the full text of Creative Commons Attribution-ShareAlike 4.0 International.

### ctfs/resources - CC0 1.0

- Repository: <https://github.com/ctfs/resources>
- Licence file read: `LICENSE`
- LICENSE is the full text of the CC0 1.0 Universal public-domain dedication.

### Awesome CTF - CC0 1.0

- Repository: <https://github.com/apsdehal/awesome-ctf>
- Licence file read: `LICENSE`
- LICENSE is the full text of the CC0 1.0 Universal public-domain dedication.

## What the non-commercial licences mean here

CTF Wiki is CC BY-NC-SA 4.0 and HackTricks is CC BY-NC 4.0. Both permit copying and
redistribution with attribution for non-commercial use; CTF Wiki additionally
requires ShareAlike on adaptations. This mirror is a personal, offline, non-commercial
knowledge base and attributes every page to its source, which is within those terms.
**Do not redistribute this mirror commercially.** The remaining corpora (MIT,
CC BY-SA 4.0, CC0 1.0) carry no such restriction.

## Per-corpus page counts by category

- **CTF Wiki** (254): pwn 102, crypto 49, rev 43, blockchain 16, misc 11, mobile 9, forensics 8, web 6, stego 5, hardware 4, osint 1
- **HackTricks** (494): web 163, pwn 102, mobile 67, forensics 49, hardware 40, misc 29, osint 14, rev 9, blockchain 8, crypto 7, stego 6
- **PayloadsAllTheThings** (67): web 54, misc 11, crypto 1, stego 1
- **OWASP WSTG** (125): web 120, crypto 4, rev 1
- **Trail of Bits CTF Field Guide** (12): pwn 5, misc 4, web 1, forensics 1, rev 1
- **ctfs/resources** (5): misc 3, rev 1, stego 1
- **Awesome CTF** (16): forensics 3, web 3, pwn 3, crypto 2, misc 2, rev 1, stego 1, mobile 1

## Pages that were deliberately dropped

| Corpus | Reason | Count |
|---|---|---|
| CTF Wiki | `nav-stub` | 135 |
| CTF Wiki | `skipped-meta-page` | 10 |
| CTF Wiki | `too-short` | 1 |
| HackTricks | `nav-stub` | 14 |
| HackTricks | `skipped-meta-page` | 1 |
| PayloadsAllTheThings | `nav-stub` | 28 |
| PayloadsAllTheThings | `scraper-bait:ignore previous instructions` | 1 |
| OWASP WSTG | `nav-stub` | 22 |
| OWASP WSTG | `skipped-meta-page` | 1 |
| Trail of Bits CTF Field Guide | `nav-stub` | 6 |
| Trail of Bits CTF Field Guide | `skipped-meta-page` | 1 |
| ctfs/resources | `nav-stub` | 20 |

`nav-stub` is a page with fewer than 20 lines of real content (a table of contents).
`skipped-meta-page` is repository housekeeping (contributing guides, licences, nav).
`scraper-bait` and `too-short` come from `ingest/ctftime.py::looks_like_bait`:
a handful of mirrored pages contain text addressed at automated scrapers. Those pages
are dropped rather than mirrored, and no instruction found inside any mirrored
document is ever acted on -- mirrored text is data.

### Pages the bait filter dropped

- `payloads` / `Prompt Injection/README.md` -- scraper-bait:ignore previous instructions

A page can trip this filter innocently: a page *about* prompt injection quotes
the same strings an attacker would plant. The filter does not try to tell the two
apart, because a mirror has no need to carry either.

## Corpora verified but not mirrored, on licence grounds

These repositories exist and are useful, but carry no licence granting
redistribution. Nothing from them is copied here -- clone them yourself.

- [swisskyrepo/InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) -- No LICENSE file in the repository and no licence statement in the README. This is where PayloadsAllTheThings' 'Methodology and Resources' pages were moved to, so those pages are pointer stubs upstream and are not mirrored here either.
- [w181496/Web-CTF-Cheatsheet](https://github.com/w181496/Web-CTF-Cheatsheet) -- No LICENSE file (the GitHub API reports NONE). An excellent web-CTF cheatsheet; clone it yourself if you want it offline.
- [JohnHammond/ctf-katana](https://github.com/JohnHammond/ctf-katana) -- No LICENSE file (the GitHub API reports NONE); the repository is a personal note dump with no redistribution grant.
- [Naetw/CTF-pwn-tips](https://github.com/Naetw/CTF-pwn-tips) -- No LICENSE file (the GitHub API reports NONE).
- [ctf-wiki/ctf-tools](https://github.com/ctf-wiki/ctf-tools) -- No LICENSE file (the GitHub API reports NONE); the tool index is covered by Awesome CTF (CC0) instead.

## Removing something

If you are an author and want your work out of this mirror, delete the matching
`content/**/ext-<corpus>-*.md` files and re-run `ctfbrain index`.
