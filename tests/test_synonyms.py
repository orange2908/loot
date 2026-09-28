"""The synonym layer is what makes one-word symptom queries work."""
from ctfbrain.synonyms import PHRASES, SYNONYMS, expand, normalise


def test_normalise_collapses_separators():
    assert normalise("common-modulus") == normalise("common modulus") == "commonmodulus"
    assert normalise("MT19937") == "mt19937"


def test_gcd_reaches_the_factoring_vocabulary():
    out = expand("gcd")
    assert "common-factor" in out
    assert "batch-gcd" in out


def test_phrases_expand_as_a_unit():
    assert "padding-oracle" in expand("padding oracle")
    assert "vaudenay" in expand("padding oracle")


def test_expansion_never_repeats_the_query_terms():
    assert "rsa" not in expand("rsa")
    assert "tcache" not in expand("tcache")


def test_symptom_words_route_to_playbooks():
    assert "playbook" in expand("i am stuck")


def test_every_expansion_value_is_a_clean_token():
    for key, values in {**SYNONYMS, **PHRASES}.items():
        for value in values:
            assert value == value.lower(), f"{key} -> {value} is not lowercase"
            assert '"' not in value and "*" not in value, f"{key} -> {value} breaks FTS syntax"
