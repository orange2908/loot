# CTF-Brain Content Specification (v1)

Every piece of knowledge in CTF-Brain is **one Markdown file with YAML frontmatter**.
The indexer (`ctfbrain/index.py`) parses these files into a SQLite FTS5 index.
**If a file does not follow this spec exactly, it will not be indexed correctly.**

---

## 1. File layout

```
content/
  cheatsheets/<category>/<slug>.md    # dense command/payload reference, grep-friendly
  techniques/<category>/<slug>.md     # one attack/technique explained + working code
  scripts/<category>/<slug>.md        # a ready-to-run script, wrapped in a md file
  writeups/<category>/<slug>.md       # a solved challenge, normalized
  playbooks/<slug>.md                 # "I have X, what do I do" decision flows
  tools/<slug>.md                     # a tool's install + usage + flags
  reference/<slug>.md                 # tables, constants, formats, magic bytes
```

`<category>` is exactly one of:
`crypto`, `web`, `pwn`, `rev`, `forensics`, `stego`, `misc`, `osint`, `mobile`, `hardware`, `blockchain`, `cloud`, `sherlocks`

`<slug>` is lowercase-kebab-case, no spaces, ends in `.md`. Example: `rsa-common-modulus.md`.

---

## 2. Frontmatter schema

```yaml
---
title: "RSA - Common Modulus Attack"        # REQUIRED. Human title. Use a plain hyphen, never an em dash.
category: crypto                             # REQUIRED. One of the 13 above.
subcategory: rsa                             # REQUIRED. free-form, lowercase-kebab (rsa, ecc, heap, xss, pcap...)
type: technique                              # REQUIRED. cheatsheet|technique|script|writeup|playbook|tool|reference
tags: [rsa, common-modulus, gcd, bezout, extended-euclidean, coppersmith]
                                             # REQUIRED. 5-20 lowercase-kebab tags. THIS IS THE PRIMARY SEARCH SURFACE.
                                             # Include: the attack name, the math/primitive, aliases, tool names,
                                             # symbols spelled out (gcd, phi, lcm, xor, lsb), and common typos/short forms.
difficulty: medium                           # REQUIRED for technique/writeup. trivial|easy|medium|hard|insane
summary: "One sentence. Same n, two e, coprime -> recover m without factoring."
                                             # REQUIRED. <=200 chars. Shown in search results.
when_to_use:                                 # REQUIRED for technique/playbook. 2-6 bullet trigger conditions.
  - "Two ciphertexts of the same plaintext under the same modulus n"
  - "gcd(e1, e2) == 1"
tools: [sympy, RsaCtfTool, sage]             # optional
cves: []                                     # optional, e.g. [CVE-2021-44228]
source:                                      # optional but STRONGLY preferred - always attribute
  name: "CTF Wiki"
  url: "https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/"
ctf:                                         # only for type: writeup
  name: "AlpacaHack Round 42"
  year: 2026
  challenge: "reused_n"
related: [rsa-common-factor, rsa-wiener]     # optional, other slugs (no .md)
---
```

### Tag rules (critical, because this is how the user finds things)
- Always spell out symbols: `gcd`, `lcm`, `phi`, `xor`, `modulo`, `lsb`, `msb`, `nth-root`.
- Include aliases: `lll` AND `lattice` AND `lattice-reduction`; `fsb` AND `format-string`.
- Include tool names that solve it: `rsactftool`, `sage`, `pwntools`, `volatility3`.
- Include the vulnerable-function name if there is one: `strcpy`, `eval`, `pickle-loads`, `_.merge`.
- Never use spaces in a tag. Never use uppercase.

---

## 3. Body structure

Use `##` headings. Recommended skeleton for `type: technique`:

```markdown
## TL;DR
2-4 lines. What it is, when it fires, what you get.

## Recognise it
Bullet list of concrete signals in the challenge source/output.

## Theory
The math/mechanism. Keep it tight but correct. Inline LaTeX with $...$ is fine.

## Attack
Step-by-step.

## Code
```python
#!/usr/bin/env python3
"""Fully runnable. No pseudocode. Imports at top. A __main__ demo with a self-test."""
```

## Variants & pitfalls
## Tools
## References
```

For `type: cheatsheet`: skip prose. Dense `## Section` blocks of copy-pasteable commands
with a one-line `# comment` above each. Aim for 60-200 commands/payloads per cheatsheet.

For `type: writeup`: `## Challenge` / `## Files` / `## Recon` / `## Vulnerability` / `## Exploit` (full script) / `## Flag` / `## Takeaway` (the reusable lesson, which is the most valuable part).

---

## 4. Code quality bar (NON-NEGOTIABLE)

- Every code block is **complete and runnable**. No `...`, no `# TODO`, no `<REDACTED>`.
- Python: target 3.11+, imports at top, `if __name__ == "__main__":` demo block.
- Prefer stdlib + `pycryptodome` / `pwntools` / `sympy` / `requests`. Note when SageMath is required.
- If a script needs a target host, take it from `argv` with a sane default, don't hardcode.
- Self-test: where cheap, the `__main__` block should generate its own test case and assert the attack works.
- Shell: POSIX-ish, comment above each command explaining the flag choices.

## 5. Hard rules
- **Never fabricate a citation.** If you are not certain a URL exists, omit `source:` rather than inventing it.
- Do not invent CTF challenge names/years for writeups. Only write `type: writeup` files for challenges
  you actually have the source material for. Otherwise write a `technique` with a generic name.
- ASCII only outside of code blocks, except standard math symbols.
- Use a plain hyphen `-`. Never an em dash or en dash, anywhere.
- Do not create files outside your assigned directories.
- Do not modify `ctfbrain/`, `docs/`, `Makefile`, `Dockerfile`, or any file another agent owns.
