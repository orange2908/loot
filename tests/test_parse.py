"""Frontmatter parsing, including the salvage paths for malformed YAML."""
import textwrap

import pytest

from ctfbrain.parse import Doc, parse_file, parse_frontmatter, make_slug

GOOD = textwrap.dedent('''\
    ---
    title: "RSA - Common Modulus Attack"
    category: crypto
    subcategory: rsa
    type: technique
    tags: [rsa, common-modulus, gcd, bezout]
    difficulty: medium
    summary: "Same n, two coprime e -> recover m without factoring."
    when_to_use:
      - "Two ciphertexts of the same plaintext under the same modulus"
      - "gcd(e1, e2) == 1"
    tools: [sympy, gmpy2]
    source:
      name: "CTF Wiki"
      url: "https://ctf-wiki.org/crypto/"
    ---

    ## TL;DR
    Use Bezout.

    ```python
    from math import gcd
    print(gcd(4, 6))
    ```
    ''')


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_parses_a_well_formed_document(tmp_path):
    doc = parse_file(write(tmp_path, "rsa-common-modulus.md", GOOD))
    assert doc.title == "RSA - Common Modulus Attack"
    assert doc.category == "crypto"
    assert doc.type == "technique"
    assert doc.subcategory == "rsa"
    assert doc.difficulty == "medium"
    assert "common-modulus" in doc.tags and "gcd" in doc.tags
    assert doc.tools == ["sympy", "gmpy2"]
    assert len(doc.when_to_use) == 2
    assert doc.source_url.startswith("https://")
    assert doc.headings == ["TL;DR"]
    assert doc.languages == ["python"]
    assert doc.n_code_blocks == 1
    assert "from math import gcd" in doc.code
    assert doc.problems == []


def test_tags_are_normalised_from_a_bare_string(tmp_path):
    text = GOOD.replace("tags: [rsa, common-modulus, gcd, bezout]",
                        "tags: RSA, Common-Modulus, GCD")
    doc = parse_file(write(tmp_path, "x.md", text))
    assert doc.tags == ["rsa", "common-modulus", "gcd"]


def test_missing_frontmatter_is_reported_not_fatal(tmp_path):
    doc = parse_file(write(tmp_path, "crypto/no-fm.md".replace("/", "-"),
                           "# Just a heading\n\nSome text.\n"))
    assert "no-frontmatter" in doc.problems
    assert doc.title == "Just a heading"          # recovered from the H1
    assert doc.summary == "Some text."            # recovered from the first prose line


def test_category_falls_back_to_the_directory(tmp_path):
    d = tmp_path / "content" / "techniques" / "pwn"
    d.mkdir(parents=True)
    p = d / "thing.md"
    p.write_text("---\ntitle: T\ntype: technique\ntags: [a,b,c]\n---\nbody\n", encoding="utf-8")
    doc = parse_file(p)
    assert doc.category == "pwn"
    assert any("category" in problem for problem in doc.problems)


def test_broken_yaml_is_salvaged(tmp_path):
    broken = textwrap.dedent('''\
        ---
        title: Bad: unquoted colon breaks yaml
        category: web
        type: technique
        tags: [xss, dom]
        ---
        body
        ''')
    doc = parse_file(write(tmp_path, "bad.md", broken))
    assert doc.category == "web"
    assert doc.problems, "a salvaged document must report why"
    assert any("yaml" in p or "salvaged" in p for p in doc.problems)


def test_invalid_difficulty_is_dropped_and_flagged(tmp_path):
    doc = parse_file(write(tmp_path, "d.md", GOOD.replace("difficulty: medium",
                                                          "difficulty: impossible")))
    assert doc.difficulty == ""
    assert any("bad-difficulty" in p for p in doc.problems)


def test_frontmatter_helper_returns_body_unchanged():
    fm, body, problems = parse_frontmatter(GOOD)
    assert fm["category"] == "crypto"
    assert body.lstrip().startswith("## TL;DR")
    assert problems == []
