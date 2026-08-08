"""Core invariants: determinism, idempotence, profiles, the vault, the cache."""

from __future__ import annotations

import dataclasses
import threading
from pathlib import Path

import pytest

from fixtures import FACTURE
from piiredact import Redactor
from piiredact.rules import TOKEN_RE
from piiredact.types import ClaimSet, EntityType, Span, resolve_overlaps
from piiredact.vault import Vault


# -- determinism -------------------------------------------------------------


def test_same_value_yields_same_token_within_a_run(redactor) -> None:
    first = redactor.redact("Écrire à jean@example.fr")
    second = redactor.redact("Relancer jean@example.fr demain")
    token = TOKEN_RE.search(first.text).group(0)
    assert token in second.text


def test_same_value_yields_same_token_across_processes(settings) -> None:
    """A fresh Redactor over the same DB must reproduce the same tokens.

    This is what keeps the prompt prefix byte-identical across sessions, and
    therefore the provider's prompt cache warm.
    """
    first = Redactor(settings)
    out_a = first.redact(FACTURE.text).text
    first.vault.close()

    second = Redactor(settings)
    out_b = second.redact(FACTURE.text).text
    second.vault.close()

    assert out_a == out_b


def test_formatting_variants_collapse_to_one_token(redactor) -> None:
    """+33 and 0-prefixed forms of one number must not burn two tokens."""
    a = redactor.redact("Tel : 06 12 34 56 78").text
    b = redactor.redact("Tel : +33 6 12 34 56 78").text
    assert TOKEN_RE.search(a).group(0) == TOKEN_RE.search(b).group(0)


def test_email_case_variants_collapse(redactor) -> None:
    a = redactor.redact("Jean@Example.FR").text
    b = redactor.redact("jean@example.fr").text
    assert TOKEN_RE.search(a).group(0) == TOKEN_RE.search(b).group(0)


# -- idempotence -------------------------------------------------------------


def test_redaction_is_idempotent(redactor) -> None:
    once = redactor.redact(FACTURE.text).text
    twice = redactor.redact(once).text
    assert once == twice


def test_tokens_are_never_re_detected_as_pii(redactor) -> None:
    """A token like ``[POSTAL_10000]`` must not be eaten by the 5-digit rule."""
    text = "code [POSTAL_10000] et [PERSON_0001] restent intacts"
    assert redactor.redact(text).text == text


def test_restore_is_a_no_op_on_unknown_tokens(redactor) -> None:
    assert redactor.restore("garde [PERSON_9999]") == "garde [PERSON_9999]"


def test_restore_handles_tokens_stripped_of_brackets(redactor) -> None:
    redacted = redactor.redact("Écrire à jean@example.fr").text
    token = TOKEN_RE.search(redacted).group(0)
    bare = token.strip("[]")
    assert redactor.restore(f"envoyer à {bare}") == "envoyer à jean@example.fr"


# -- profiles ----------------------------------------------------------------


def test_balanced_profile_keeps_amounts_and_dates_readable(redactor) -> None:
    """The model must keep the ability to add up and to reason about dates."""
    result = redactor.redact("Facture de 1 234,56 € émise le 12/03/2025 pour Mme Roux")
    assert "1 234,56 €" in result.text
    assert "12/03/2025" in result.text
    assert "Roux" not in result.text


def test_strict_profile_redacts_amounts_and_dates(strict_redactor) -> None:
    result = strict_redactor.redact("Facture de 1 234,56 € émise le 12/03/2025")
    assert "1 234,56 €" not in result.text
    assert "12/03/2025" not in result.text


def test_type_selection_is_honoured(settings) -> None:
    only_email = dataclasses.replace(settings, types=frozenset({EntityType.EMAIL}))
    red = Redactor(only_email)
    result = red.redact("jean@example.fr et 06 12 34 56 78")
    assert "jean@example.fr" not in result.text
    assert "06 12 34 56 78" in result.text
    red.vault.close()


def test_disabled_plugin_is_a_pure_no_op(settings) -> None:
    off = dataclasses.replace(settings, enabled=False)
    red = Redactor(off)
    assert red.redact(FACTURE.text).text == FACTURE.text
    assert red.restore("[PERSON_0001]") == "[PERSON_0001]"
    red.vault.close()


# -- vault -------------------------------------------------------------------


def test_vault_file_is_owner_only(redactor) -> None:
    mode = Path(redactor.vault.path).stat().st_mode & 0o777
    assert mode == 0o600, f"vault is {oct(mode)}, expected 0600"


def test_vault_is_shared_between_instances(settings) -> None:
    a = Vault(settings.db_path)
    token = a.token_for(EntityType.PERSON, "Amélie Roux")
    a.close()
    b = Vault(settings.db_path)
    assert b.token_for(EntityType.PERSON, "Amélie Roux") == token
    assert b.value_for(token) == "Amélie Roux"
    b.close()


def test_concurrent_token_allocation_is_consistent(settings) -> None:
    """Two threads racing on a new value must converge on one token."""
    vault = Vault(settings.db_path)
    results: list = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        results.append(vault.token_for(EntityType.PERSON, "Amélie Roux"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(set(results)) == 1, results
    assert vault.count() == 1
    vault.close()


def test_forget_removes_the_mapping(redactor) -> None:
    token = redactor.learn(EntityType.PERSON, "Amélie Roux")
    assert redactor.restore(token) == "Amélie Roux"
    assert redactor.vault.forget(token) is True
    assert redactor.restore(token) == token


def test_learned_literal_is_matched_immediately(redactor) -> None:
    redactor.learn(EntityType.PERSON, "Bertrand Fauchier")
    assert "Bertrand Fauchier" not in redactor.redact("vu Bertrand Fauchier hier").text


# -- structural helpers ------------------------------------------------------


def test_claimset_detects_every_kind_of_overlap() -> None:
    claims = ClaimSet()
    claims.add(10, 20)
    claims.add(30, 40)
    assert claims.overlaps(15, 18)     # inside
    assert claims.overlaps(5, 12)      # straddles the left edge
    assert claims.overlaps(18, 35)     # spans both
    assert claims.overlaps(35, 45)     # straddles the right edge
    assert not claims.overlaps(20, 30)  # exactly between
    assert not claims.overlaps(0, 10)   # touching, not overlapping
    assert not claims.overlaps(40, 50)


def test_resolve_overlaps_prefers_earliest_then_longest() -> None:
    spans = [
        Span(10, 20, EntityType.PERSON, "b"),
        Span(0, 15, EntityType.ADDR, "a"),
        Span(0, 5, EntityType.POSTAL, "c"),
        Span(20, 25, EntityType.EMAIL, "d"),
    ]
    kept = resolve_overlaps(spans)
    assert [(s.start, s.end) for s in kept] == [(0, 15), (20, 25)]


def test_cache_returns_identical_output(redactor) -> None:
    first = redactor.redact(FACTURE.text)
    second = redactor.redact(FACTURE.text)
    assert second.cached is True
    assert second.text == first.text


def test_cache_is_invalidated_when_a_value_is_learned(redactor) -> None:
    text = "réunion avec Bertrand Fauchier"
    assert "Bertrand Fauchier" in redactor.redact(text).text
    redactor.learn(EntityType.PERSON, "Bertrand Fauchier")
    assert "Bertrand Fauchier" not in redactor.redact(text).text


# -- fail-closed guards ------------------------------------------------------


def test_oversized_content_is_cut_not_passed_through(settings) -> None:
    small = dataclasses.replace(settings, max_bytes=200)
    red = Redactor(small)
    text = "x" * 500 + " IBAN FR76 3000 4000 0512 3456 7890 143"
    result = red.redact(text)
    assert result.truncated is True
    assert "FR76 3000 4000 0512 3456 7890 143" not in result.text
    assert "tronqué" in result.text
    red.vault.close()


def test_json_tool_result_stays_parseable(redactor) -> None:
    import json

    payload = json.dumps(
        {"path": "/tmp/a.txt", "content": "Amélie Roux, 12 bis rue des Lilas, 69007 Lyon"},
        ensure_ascii=False,
    )
    redacted, count = redactor.redact_payload(payload)
    assert count > 0
    parsed = json.loads(redacted)  # must not raise
    assert "12 bis rue des Lilas" not in parsed["content"]
    assert parsed["path"] == "/tmp/a.txt"


def test_non_json_payload_falls_back_to_raw_text(redactor) -> None:
    redacted, count = redactor.redact_payload("plain text jean@example.fr")
    assert count == 1
    assert "jean@example.fr" not in redacted


@pytest.mark.parametrize("empty", ["", None])
def test_empty_input_is_handled(redactor, empty) -> None:
    assert redactor.redact(empty or "").text == ""
    assert redactor.restore(empty or "") == ""
