"""The leak test — the one that decides whether this plugin is worth running.

Every other test checks a mechanism. This one checks the property the whole
thing exists for: after redaction, no real value from a realistic French
document survives in the text that would be sent to a model.
"""

from __future__ import annotations

import pytest

from fixtures import ALL_FIXTURES, PUNCTUATED_CASES, Fixture
from piiredact.rules import TOKEN_RE, audit_patterns


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.name)
def test_no_real_value_survives_redaction(redactor, fixture: Fixture) -> None:
    """No declared secret appears verbatim in the redacted text."""
    result = redactor.redact(fixture.text)
    leaked = [secret for secret in fixture.secrets if secret in result.text]
    assert not leaked, (
        f"{fixture.name}: {len(leaked)} value(s) reached the model: {leaked}\n"
        f"--- redacted ---\n{result.text}"
    )


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.name)
def test_redaction_actually_produced_tokens(redactor, fixture: Fixture) -> None:
    """Guard against a vacuous pass — e.g. an exception swallowed upstream."""
    result = redactor.redact(fixture.text)
    assert TOKEN_RE.search(result.text), "no token emitted at all"
    assert len(result.spans) >= 5


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.name)
def test_roundtrip_restores_the_original(redactor, fixture: Fixture) -> None:
    """restore(redact(x)) == x — the functionality half of the contract."""
    result = redactor.redact(fixture.text)
    assert redactor.restore(result.text) == fixture.text


@pytest.mark.parametrize(
    ("text", "secret"),
    PUNCTUATED_CASES,
    ids=[secret for _text, secret in PUNCTUATED_CASES],
)
def test_values_with_trailing_punctuation_are_redacted(strict_redactor, text, secret) -> None:
    """Regression for the ``\\b``-tail trap.

    A pattern ending in ``\\b`` fails when its last character is itself a
    non-word character (``€``), because there is no word boundary between
    ``€`` and ``.`` — and the value escapes to the model. Amounts are only
    detected in the strict profile, hence ``strict_redactor``.
    """
    result = strict_redactor.redact(text)
    assert secret not in result.text, f"{secret!r} leaked from {text!r} -> {result.text!r}"


def test_no_rule_pattern_ends_with_word_boundary() -> None:
    """Encode the lesson in the rule set itself, not only in the cases above."""
    assert audit_patterns() == []


def test_multiline_document_with_mixed_punctuation(strict_redactor) -> None:
    """Values glued to ``)``, ``;`` and end-of-line in one pass."""
    text = (
        "Virement (IBAN FR76 3000 4000 0512 3456 7890 143);\n"
        "montant 1 234,56 €;\n"
        "contact (jean@example.fr)\n"
        "tel 06 12 34 56 78\n"
    )
    result = strict_redactor.redact(text)
    for secret in (
        "FR76 3000 4000 0512 3456 7890 143",
        "1 234,56 €",
        "jean@example.fr",
        "06 12 34 56 78",
    ):
        assert secret not in result.text


def test_known_limitations_are_explicit(redactor) -> None:
    """Document what the deterministic layers do *not* catch on their own.

    A bare name with no civility, no field label and no prior vault entry is
    invisible to a rule engine — that is the gap the optional NER pass and the
    terms file exist to fill. The test asserts the gap so it stays a known,
    reviewable property instead of a surprise.
    """
    result = redactor.redact("Le dossier a été validé par Bertrand Fauchier hier.")
    assert "Bertrand Fauchier" in result.text

    # ...and closing it takes one call, after which the value is caught
    # everywhere, forever — including mid-sentence and with no anchor.
    redactor.learn("PERSON", "Bertrand Fauchier")
    second = redactor.redact("Le dossier a été validé par Bertrand Fauchier hier.")
    assert "Bertrand Fauchier" not in second.text


def test_learned_value_is_caught_in_later_unrelated_text(redactor) -> None:
    """The gazetteer is what turns one detection into permanent coverage."""
    first = redactor.redact("Titulaire : Amélie Roux")
    assert "Amélie Roux" not in first.text

    later = redactor.redact("j'ai croisé amélie roux au marché, sans contexte")
    assert "amélie roux" not in later.text.lower()
