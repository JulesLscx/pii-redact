"""Latency budget: a tool call must not become noticeably slower.

The product constraint is "at most ~300 ms of added cost per tool use". These
tests hold the engine to it on realistic payload sizes and pin the two
properties that make it hold in practice: the deterministic layers are linear,
and repeated content is answered from cache.

Thresholds are deliberately generous relative to measured values (a typical
50 KB document scans in ~40 ms here) so the suite reports a real regression
rather than CI jitter.
"""

from __future__ import annotations

import time
from statistics import median

import pytest

from fixtures import ALL_FIXTURES, FACTURE

BUDGET_MS = 300


def _percentile(values, fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction) - 1))
    return ordered[index]


def _timed(redactor, text: str) -> float:
    started = time.perf_counter()
    redactor.redact(text)
    return (time.perf_counter() - started) * 1000


def test_typical_tool_result_is_well_inside_budget(redactor) -> None:
    """~8 KB — the size of a file read or a command's output."""
    document = "\n".join(f.text for f in ALL_FIXTURES) * 2
    redactor.redact(document)  # warm
    timings = [_timed(redactor, f"{document}\n#{i}") for i in range(15)]
    assert _percentile(timings, 0.95) < BUDGET_MS, timings


def test_large_document_stays_inside_budget(redactor) -> None:
    """~50 KB of dense PII — a long PDF extraction, worst realistic case."""
    document = FACTURE.text * 60
    redactor.redact(document)
    timings = [_timed(redactor, f"{document}\n#{i}") for i in range(5)]
    assert _percentile(timings, 0.95) < BUDGET_MS, (len(document), timings)


def test_repeated_content_is_essentially_free(redactor) -> None:
    """The provider payload is re-scanned before every API call; it must be
    the cache answering, not the rule set."""
    document = FACTURE.text * 10
    redactor.redact(document)
    redactor.redact(document)  # settle the generation counter
    timings = [_timed(redactor, document) for _ in range(20)]
    assert median(timings) < 2.0, timings


def test_cost_grows_linearly_not_quadratically(redactor) -> None:
    """Regression guard for the overlap check.

    Comparing each candidate span against a growing list made this O(n²): a
    200 KB document took minutes. Ten times the input must cost roughly ten
    times the time, not a hundred.
    """
    small = FACTURE.text * 5
    large = FACTURE.text * 50
    redactor.redact("warm")

    small_ms = median([_timed(redactor, f"{small}\n#{i}") for i in range(5)])
    large_ms = median([_timed(redactor, f"{large}\n#{i}") for i in range(5)])

    assert large_ms < small_ms * 25, (small_ms, large_ms)


def test_restore_is_cheap_on_a_long_answer(redactor) -> None:
    """Restoration runs on every assistant turn; keep it off the critical path."""
    redacted = redactor.redact(FACTURE.text).text
    long_answer = redacted * 20
    started = time.perf_counter()
    redactor.restore(long_answer)
    assert (time.perf_counter() - started) * 1000 < BUDGET_MS


@pytest.mark.parametrize("size", [1, 10, 40])
def test_budget_reported_in_the_result(redactor, size: int) -> None:
    result = redactor.redact(FACTURE.text * size)
    assert result.elapsed_ms >= 0.0
    assert result.elapsed_ms < BUDGET_MS * 2
