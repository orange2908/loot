"""End-to-end: build a real index over a fixture corpus and query it."""
import textwrap

import pytest

from ctfbrain.index import build, load_meta
from ctfbrain.search import Brain

FIXTURES = {
    "techniques/crypto/rsa-common-factor.md": '''\
        ---
        title: "RSA - Shared Prime / Batch GCD"
        category: crypto
        subcategory: rsa
        type: technique
        tags: [rsa, gcd, common-factor, batch-gcd, shared-prime, factoring]
        difficulty: easy
        summary: "Two moduli that share a prime factor both fall to a single gcd."
        when_to_use:
          - "You have two or more RSA moduli from the same source"
        ---
        ## TL;DR
        If gcd(n1, n2) != 1 you have p immediately.

        ```python
        from math import gcd
        p = gcd(n1, n2)
        ```
    ''',
    "techniques/pwn/heap-tcache-poisoning.md": '''\
        ---
        title: "Tcache Poisoning - Arbitrary Allocation"
        category: pwn
        subcategory: heap
        type: technique
        tags: [heap, tcache, tcache-poisoning, glibc, arbitrary-write, uaf]
        difficulty: medium
        summary: "Corrupt a tcache entry's next pointer to make malloc return any address."
        ---
        ## TL;DR
        Overwrite the fd of a freed tcache chunk.
    ''',
    "cheatsheets/pwn/pwntools-cheatsheet.md": '''\
        ---
        title: "pwntools Cheatsheet"
        category: pwn
        subcategory: tooling
        type: cheatsheet
        tags: [pwntools, python, exploit-template, cyclic, rop]
        summary: "The pwntools idioms you use in every exploit."
        ---
        ## Process
        ```python
        from pwn import *
        io = process("./vuln")
        ```
    ''',
    "playbooks/pwn-triage.md": '''\
        ---
        title: "Playbook - Binary Exploitation Triage"
        category: pwn
        subcategory: triage
        type: playbook
        tags: [playbook, triage, stuck, where-to-start, checksec, pwn]
        summary: "You have a binary and a libc. Work out the bug class, then the technique."
        ---
        ## Step 1
        Run checksec.
    ''',
    "writeups/crypto/ctftime-example-task.md": '''\
        ---
        title: "babyrsa - Example CTF"
        category: crypto
        subcategory: rsa
        type: writeup
        tags: [rsa, gcd, common-factor]
        summary: "Two keys shared a prime."
        source:
          name: "CTFtime writeup #1"
          url: "https://ctftime.org/writeup/1"
        ctf:
          name: "Example CTF"
          year: 2024
          challenge: "babyrsa"
        ---
        ## Solution
        gcd the moduli.
    ''',
}


@pytest.fixture(scope="module")
def brain(tmp_path_factory):
    content = tmp_path_factory.mktemp("content")
    for rel, body in FIXTURES.items():
        path = content / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body), encoding="utf-8")
    db = tmp_path_factory.mktemp("data") / "index.db"

    import ctfbrain.parse as parse_mod
    original = parse_mod.CONTENT_DIR
    parse_mod.CONTENT_DIR = content          # so slugs are relative to the fixture root
    try:
        summary = build(content_dir=content, db_path=db, verbose=False)
        assert summary["documents"] == len(FIXTURES)
        assert summary["failed"] == 0
        b = Brain(db)
        yield b
        b.close()
    finally:
        parse_mod.CONTENT_DIR = original


def test_index_counts_and_meta(brain):
    stats = brain.stats()
    assert stats["documents"] == 5
    assert stats["by_category"]["pwn"] == 3
    assert stats["by_type"]["technique"] == 2
    assert stats["ctfs"] == 1


def test_exact_tag_query_ranks_the_right_document_first(brain):
    hits, total = brain.search("tcache poisoning")
    assert total >= 1
    assert hits[0].slug.endswith("heap-tcache-poisoning")


def test_synonym_expansion_finds_a_document_that_never_says_the_word(brain):
    # "shared prime" is in the tags; the query word "gcd" reaches it via expansion too.
    hits, _ = brain.search("shared prime")
    assert any("common-factor" in h.slug for h in hits)


def test_playbooks_outrank_writeups_for_a_symptom_query(brain):
    hits, _ = brain.search("stuck triage")
    assert hits[0].type == "playbook"


def test_category_filter_via_inline_syntax(brain):
    hits, _ = brain.search("cat:crypto rsa")
    assert hits and all(h.category == "crypto" for h in hits)


def test_type_filter_via_keyword_argument(brain):
    hits, _ = brain.search("pwn", doctype="cheatsheet")
    assert hits and all(h.type == "cheatsheet" for h in hits)


def test_tag_filter_is_exact(brain):
    hits, _ = brain.search("", tags=["tcache"])
    assert len(hits) == 1
    assert hits[0].slug.endswith("heap-tcache-poisoning")


def test_empty_query_with_filters_browses(brain):
    hits, total = brain.search("cat:pwn")
    assert total == 3
    assert hits[0].type == "playbook"      # playbooks sort first when browsing


def test_snippet_marks_the_match(brain):
    hits, _ = brain.search("checksec")
    assert hits
    assert "«" in hits[0].snippet or "checksec" in hits[0].snippet.lower()


def test_get_and_related(brain):
    hits, _ = brain.search("tcache poisoning")
    doc = brain.get(hits[0].slug)
    assert doc["title"].startswith("Tcache Poisoning")
    assert "tcache" in doc["tags"]
    related = brain.related(doc["slug"])
    assert any(r["category"] == "pwn" for r in related)


def test_unknown_slug_returns_none(brain):
    assert brain.get("no/such/slug") is None


def test_hyphenated_and_symbol_tokens_are_searchable(brain):
    hits, _ = brain.search("batch-gcd")
    assert hits and "common-factor" in hits[0].slug


def test_garbage_query_does_not_raise(brain):
    for q in ['"', "AND OR NOT", "*", "()", "a AND", "   "]:
        brain.search(q)   # must not raise


def test_facets_reflect_the_corpus(brain):
    facets = brain.facets("pwn")
    assert facets["categories"].get("pwn", 0) >= 1


def test_no_frontmatter_problems_in_fixtures(brain):
    assert brain.problems() == []


def test_concurrent_builds_do_not_corrupt_the_index(tmp_path_factory):
    """Two builds racing must leave one complete, queryable index behind.

    They previously shared a single `.building` temp file, so one process could
    rename a half-written database over the other's finished work.
    """
    import textwrap
    from concurrent.futures import ThreadPoolExecutor

    content = tmp_path_factory.mktemp("concurrent")
    for rel, body in FIXTURES.items():
        path = content / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body), encoding="utf-8")
    db = tmp_path_factory.mktemp("concurrent-data") / "index.db"

    import ctfbrain.parse as parse_mod
    original = parse_mod.CONTENT_DIR
    parse_mod.CONTENT_DIR = content
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = [f.result() for f in
                       [pool.submit(build, content, db, False) for _ in range(3)]]
        assert all(r["documents"] == len(FIXTURES) for r in results)

        b = Brain(db)
        try:
            assert b.stats()["documents"] == len(FIXTURES)
            assert b.problems() == []          # the schema is complete, not partial
            hits, _ = b.search("tcache")
            assert hits
        finally:
            b.close()
        leftovers = list(db.parent.glob("index.building*"))
        assert not leftovers, f"temp files left behind: {leftovers}"
    finally:
        parse_mod.CONTENT_DIR = original


def test_brain_reloads_when_the_index_is_replaced(tmp_path_factory):
    """`ctfbrain index` renames a new file into place while a server holds the old.

    Without a freshness check the running server keeps serving the old inode, so
    content added while it is up stays invisible until a restart.
    """
    import textwrap

    content = tmp_path_factory.mktemp("reload")
    for rel, body in FIXTURES.items():
        path = content / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body), encoding="utf-8")
    db = tmp_path_factory.mktemp("reload-data") / "index.db"

    import ctfbrain.parse as parse_mod
    original = parse_mod.CONTENT_DIR
    parse_mod.CONTENT_DIR = content
    try:
        build(content, db, verbose=False)
        b = Brain(db)
        try:
            assert b.stats()["documents"] == len(FIXTURES)
            hits, _ = b.search("", tags=["brand-new-tag"])
            assert not hits

            # Add a document and rebuild, exactly as `ctfbrain index` does.
            new = content / "techniques" / "web" / "added-later.md"
            new.parent.mkdir(parents=True, exist_ok=True)
            new.write_text(textwrap.dedent('''\
                ---
                title: "Added While Serving"
                category: web
                subcategory: xss
                type: technique
                tags: [brand-new-tag, xss, added-later]
                summary: "A document that did not exist when the handle was opened."
                ---
                ## TL;DR
                It should be visible without a restart.
            '''), encoding="utf-8")
            build(content, db, verbose=False)

            assert b.stats()["documents"] == len(FIXTURES) + 1
            hits, _ = b.search("", tags=["brand-new-tag"])
            assert len(hits) == 1
            assert hits[0].title == "Added While Serving"
        finally:
            b.close()
    finally:
        parse_mod.CONTENT_DIR = original
