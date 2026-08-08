"""The telemetry connector: it must measure the redaction, never carry it.

Two properties matter here and the rest is plumbing:

* a record is counters and timings only — replaying the whole leak corpus
  through the connector must not put a single real value into anything a sink
  receives (the metrics pipeline is a network path like any other);
* a broken collector is invisible — a sink that raises must not cost a
  redaction, and above all must not cost a *restoration*, which sits on the
  path the user reads.
"""

from __future__ import annotations

import dataclasses
import io
import json
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Iterator, List

import pytest

from fixtures import ALL_FIXTURES, FACTURE
from piiredact.adapters.telemetry import (
    EVENT_FIELDS,
    HttpSink,
    JsonLinesSink,
    MemorySink,
    TelemetryConnector,
    TelemetryError,
    is_safe_record,
)
from piiredact.rules import TOKEN_RE


@pytest.fixture
def sink() -> MemorySink:
    return MemorySink()


@pytest.fixture
def probe(redactor, sink: MemorySink) -> TelemetryConnector:
    """Connector on the throwaway vault from ``conftest``."""
    return TelemetryConnector([sink], redactor=redactor, source="test")


class ExplodingSink:
    """A collector having a bad day."""

    def __init__(self) -> None:
        self.calls = 0

    def emit(self, record: Dict[str, Any]) -> None:
        self.calls += 1
        raise RuntimeError("collector unreachable")

    def flush(self) -> None:
        raise RuntimeError("collector unreachable")

    def close(self) -> None:
        raise RuntimeError("collector unreachable")


# -- the leak-free invariant -------------------------------------------------


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.name)
def test_no_real_value_reaches_telemetry(probe, sink: MemorySink, fixture) -> None:
    """The whole leak corpus, observed: nothing personal in any record.

    This is ``test_leak.py``'s assertion pointed at the metrics path instead of
    the model path, because a collector is just another remote endpoint.
    """
    probe.redact(fixture.text, source=fixture.name)
    shipped = json.dumps(sink.as_list() + [probe.summary()], ensure_ascii=False)
    leaked = [secret for secret in fixture.secrets if secret in shipped]
    assert not leaked, f"{fixture.name}: {leaked} reached the telemetry stream"


def test_records_only_ever_carry_declared_fields(probe, sink: MemorySink) -> None:
    probe.redact(FACTURE.text)
    probe.restore("rien à restaurer ici")
    assert sink.as_list(), "no record emitted"
    for record in sink.as_list():
        assert is_safe_record(record), record
        assert set(record) == set(EVENT_FIELDS)


def test_is_safe_record_rejects_a_smuggled_field() -> None:
    """The guard is only useful if it actually says no."""
    assert is_safe_record({"at": "now", "op": "redact", "text": "IBAN FR76..."}) is False


# -- measuring the outbound path ---------------------------------------------


def test_one_record_per_call_with_the_core_counts(probe, sink: MemorySink) -> None:
    result = probe.redact(FACTURE.text, source="facture")
    assert len(sink.as_list()) == 1
    record = sink.as_list()[0]
    assert record["op"] == "redact"
    assert record["source"] == "facture"
    assert record["counts"] == result.counts()
    assert record["spans"] == len(result.spans) > 0
    assert record["chars_in"] == len(FACTURE.text)
    assert record["elapsed_ms"] >= 0.0


def test_redact_returns_the_core_result_untouched(probe, redactor) -> None:
    """Observing must not change what the caller gets."""
    observed = probe.redact(FACTURE.text)
    assert observed.text == redactor.redact(FACTURE.text).text
    assert "amelie.roux@example.fr" not in observed.text


def test_cache_hits_are_visible(probe, sink: MemorySink) -> None:
    probe.redact(FACTURE.text)
    probe.redact(FACTURE.text)
    assert sink.as_list()[0]["cached"] is False
    assert sink.as_list()[1]["cached"] is True
    assert probe.summary()["cached"] == 1


def test_truncation_is_reported(redactor, sink: MemorySink, monkeypatch) -> None:
    """The size guard firing is exactly what an operator needs to see."""
    monkeypatch.setattr(
        redactor, "settings", dataclasses.replace(redactor.settings, max_bytes=128)
    )
    probe = TelemetryConnector([sink], redactor=redactor)
    probe.redact(FACTURE.text * 4)
    assert sink.as_list()[0]["truncated"] is True
    assert probe.summary()["truncated"] == 1


def test_observe_accepts_an_already_computed_result(redactor, sink: MemorySink) -> None:
    """The seam for a host that already calls the core itself."""
    probe = TelemetryConnector([sink], redactor=redactor)
    result = redactor.redact("mail jean@example.fr")
    record = probe.observe(result, source="hermes:read_file")
    assert record["source"] == "hermes:read_file"
    assert sink.as_list() == [record]


# -- the closed loop ---------------------------------------------------------


def test_restore_is_measured_and_still_returns_real_values(probe, redactor) -> None:
    token = TOKEN_RE.search(redactor.redact("mail jean@example.fr").text).group(0)
    assert probe.restore(f"écrire à {token}") == "écrire à jean@example.fr"
    record = probe.sinks[0].as_list()[-1]
    assert record["op"] == "restore"
    assert record["counts"] == {"EMAIL": 1}


def test_unknown_tokens_are_not_counted_as_restored(probe) -> None:
    assert probe.restore("voir [EMAIL_9999]") == "voir [EMAIL_9999]"
    assert probe.sinks[0].as_list()[-1]["spans"] == 0


def test_summary_aggregates_across_calls(probe) -> None:
    probe.redact(FACTURE.text)
    probe.redact("mail jean@example.fr")
    summary = probe.summary()
    assert summary["calls"] == 2
    assert summary["spans"] > 0
    assert summary["counts"]["EMAIL"] >= 1
    assert summary["p95_ms"] >= summary["p50_ms"] >= 0.0
    assert summary["dropped"] == 0


def test_summary_keeps_the_two_directions_apart(probe, redactor) -> None:
    """One value masked then restored is one protected value, not two."""
    safe = probe.redact("mail jean@example.fr").text
    probe.restore(safe)
    summary = probe.summary()
    assert summary["spans"] == 1
    assert summary["restored"] == 1
    assert summary["counts"] == {"EMAIL": 1}  # outbound only


# -- fail-safe ---------------------------------------------------------------


def test_a_broken_sink_never_costs_a_redaction(redactor) -> None:
    broken = ExplodingSink()
    probe = TelemetryConnector([broken], redactor=redactor)
    result = probe.redact("mail jean@example.fr")
    assert "jean@example.fr" not in result.text
    assert broken.calls == 1
    assert probe.dropped == 1


def test_a_broken_sink_never_costs_a_restoration(redactor) -> None:
    """The critical direction: the user reads this output."""
    token = TOKEN_RE.search(redactor.redact("mail jean@example.fr").text).group(0)
    probe = TelemetryConnector([ExplodingSink()], redactor=redactor)
    assert probe.restore(f"écrire à {token}") == "écrire à jean@example.fr"
    assert probe.dropped == 1


def test_flush_and_close_absorb_sink_failures(redactor) -> None:
    probe = TelemetryConnector([ExplodingSink()], redactor=redactor)
    probe.flush()
    probe.close()
    assert probe.dropped == 2


# -- sinks -------------------------------------------------------------------


def test_jsonlines_sink_writes_one_object_per_line(redactor) -> None:
    stream = io.StringIO()
    probe = TelemetryConnector([JsonLinesSink(stream)], redactor=redactor)
    probe.redact(FACTURE.text)
    probe.redact("mail jean@example.fr")
    lines = stream.getvalue().splitlines()
    assert len(lines) == 2
    for line in lines:
        assert is_safe_record(json.loads(line))


def test_http_sink_batches_before_posting(redactor) -> None:
    posted: List[Dict[str, Any]] = []

    def transport(url: str, body: bytes, headers: Dict[str, str], timeout: float) -> None:
        assert url == "http://collector.invalid/v1/records"
        assert headers["Content-Type"] == "application/json"
        posted.append(json.loads(body.decode("utf-8")))

    sink = HttpSink("http://collector.invalid/v1/records", batch_size=2, transport=transport)
    probe = TelemetryConnector([sink], redactor=redactor)
    probe.redact("mail jean@example.fr")
    assert posted == []  # still batching
    probe.redact("mail marie@example.fr")
    assert len(posted) == 1 and len(posted[0]["records"]) == 2
    assert sink.sent == 2 and probe.dropped == 0


def test_http_sink_ships_the_tail_on_close(redactor) -> None:
    posted: List[Dict[str, Any]] = []
    sink = HttpSink(
        "http://collector.invalid/v1",
        batch_size=50,
        transport=lambda u, b, h, t: posted.append(json.loads(b.decode("utf-8"))),
    )
    with TelemetryConnector([sink], redactor=redactor) as probe:
        probe.redact("mail jean@example.fr")
    assert len(posted) == 1 and len(posted[0]["records"]) == 1


def test_http_sink_failure_is_counted_not_raised(redactor) -> None:
    def transport(url: str, body: bytes, headers: Dict[str, str], timeout: float) -> None:
        raise urllib.error.URLError("connection refused")

    sink = HttpSink("http://collector.invalid/v1", batch_size=1, transport=transport)
    probe = TelemetryConnector([sink], redactor=redactor)
    result = probe.redact("mail jean@example.fr")
    assert "jean@example.fr" not in result.text
    assert sink.failed == 1 and sink.sent == 0 and probe.dropped == 1
    with pytest.raises(TelemetryError):
        sink._pending.append({"op": "redact"})
        sink.flush()


# -- the real wire, against a local endpoint ---------------------------------


class _CaptureHandler(BaseHTTPRequestHandler):
    """Collector stand-in: records every body it is given."""

    bodies: List[bytes] = []

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        length = int(self.headers.get("Content-Length", "0"))
        type(self).bodies.append(self.rfile.read(length))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args: Any) -> None:  # keep the test output clean
        return None


@pytest.fixture
def collector() -> Iterator[str]:
    """A throwaway HTTP collector on loopback — never the public network."""
    _CaptureHandler.bodies = []
    server = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1/records"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_sink_posts_over_a_real_socket(redactor, collector: str) -> None:
    """The default urllib transport, exercised end to end on loopback."""
    sink = HttpSink(collector, batch_size=1, timeout=5.0)
    probe = TelemetryConnector([sink], redactor=redactor, source="loopback")
    probe.redact(FACTURE.text)

    assert sink.sent == 1 and sink.failed == 0
    assert len(_CaptureHandler.bodies) == 1
    payload = json.loads(_CaptureHandler.bodies[0].decode("utf-8"))
    record = payload["records"][0]
    assert is_safe_record(record) and record["source"] == "loopback"
    for secret in FACTURE.secrets:
        assert secret not in _CaptureHandler.bodies[0].decode("utf-8")
