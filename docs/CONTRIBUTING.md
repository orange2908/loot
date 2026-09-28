# Contributing

Mostly this means *you, adding what you just learned*. The conventions exist so the
search index stays good.

## Adding a document

1. Pick the directory by **type**, then category:
   `content/<playbooks|cheatsheets|techniques|scripts|writeups|tools|reference>/<category>/`
2. Follow [CONTENT_SPEC.md](CONTENT_SPEC.md) exactly: frontmatter schema, body skeleton, tag rules.
3. `ctfbrain lint` then `make index`.
4. `ctfbrain search "<the word you would actually type>"` and confirm your page comes back.
   If it does not, the tags are wrong. Fix the tags, not the ranking.

## The tag rule

Tags are the primary search surface and get the largest ranking bonus. For each document,
8-20 lowercase-kebab tags that include:

- the attack name and its aliases (`lll`, `lattice`, `lattice-reduction`)
- symbols spelled out (`gcd`, `phi`, `xor`, `lsb`, `nth-root`)
- the tool that solves it (`rsactftool`, `pwntools`, `volatility3`)
- the vulnerable function, if there is one (`strcpy`, `eval`, `pickle-loads`, `_.merge`)
- the words you would type at 3am, not the formal name

No spaces, no uppercase.

## Code

Every code block must be complete and runnable. No `...`, no `# TODO`, no placeholders.

- Python 3.11+, imports at the top, a `if __name__ == "__main__":` demo.
- Prefer stdlib plus `pycryptodome` / `pwntools` / `sympy` / `requests`. Mark SageMath
  blocks `# SageMath` and give a pure-Python fallback where one exists.
- **Self-test where it is cheap**: the `__main__` block should build its own vulnerable
  instance and assert the attack recovers the secret. A technique that proves itself is
  worth several that merely claim to work.
- Targets come from `argv` with a sane default, never hardcoded.

## Review checklist

- [ ] Frontmatter parses; `ctfbrain lint` is clean for this file
- [ ] `summary` is one sentence that would tell you whether to open it
- [ ] `when_to_use` lists real, observable trigger conditions
- [ ] 8-20 tags, including aliases and tool names
- [ ] Every code block is complete and `python3 -m py_compile` passes
- [ ] `source:` is a URL that actually exists. **Never invent a citation**
- [ ] For `writeup`: real CTF name and year, or the field omitted
- [ ] It is findable: search the obvious word and it comes back

## Platform code

```bash
make check     # index + lint + tests
```

Keep the dependency list short and the UI build-step-free. Both are load-bearing for
"works offline in five years".

## Things not to do

- Do not invent URLs, CTF names, years, or tool flags. Omit the field instead.
- Do not strip author names or licence headers from vendored code.
- Do not add a client-side CDN dependency to the UI.
- Do not lower the code bar to cover more topics. One working exploit beats five sketches.
