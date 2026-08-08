"""Telemetry connector — observability for the outbound half of the contract.

The three other adapters translate a *host protocol* into ``redact`` /
``restore``. This one translates the **result** of those calls into something an
operator can watch: how much was masked, of which type, how long it took,
whether the size guard fired. It is the reference example for a read-only,
outbound connector — a host that consumes the engine's output rather than
feeding it.

The governing constraint is that telemetry must be **leak-free by
construction**, not by review. A record is a fixed set of counters and timings
(:data:`EVENT_FIELDS`); the redacted text, the original text, the detected spans
and the vault are never reachable from it. :func:`is_safe_record` states that
invariant as code, and a test replays the leak corpus through the connector and
asserts that no real value survives into any emitted record.

Three sinks ship those records, and adding a fourth is a ten-line class:

* :class:`JsonLinesSink` — one JSON object per line, for a log shipper
  (Vector, Fluent Bit, Loki) or plain ``tail -f``;
* :class:`MemorySink` — keeps them in a list, for tests and for the
  "aggregate now, ship once at the end of the session" pattern;
* :class:`HttpSink` — batched ``POST`` to a collector, with an injectable
  transport so a test never touches the network.

Usage::

    from piiredact.adapters.telemetry import JsonLinesSink, TelemetryConnector

    with open("/var/log/pii-redact.jsonl", "a", encoding="utf-8") as handle:
        probe = TelemetryConnector([JsonLinesSink(handle)], source="ingest")
        safe = probe.redact(document).text      # -> model, and one record out
        print(probe.summary())

Every sink call is fail-safe: a collector that is down, slow or misconfigured
increments :attr:`TelemetryConnector.dropped` and is otherwise invisible.
Losing a metric is acceptable; losing a redaction, or an exception escaping into
the agent's hot path, is not.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, IO, List, Optional, Sequence, Tuple

from .. import get_redactor
from ..redactor import Redactor
from ..rules import TOKEN_RE
from ..types import RedactionResult

logger = logging.getLogger(__name__)

#: Every key a telemetry record may carry. Counters, sizes and timings only:
#: there is deliberately no field able to hold document text, a detected value
#: or a token, so no amount of downstream mishandling can turn the metrics
#: pipeline into an exfiltration path.
EVENT_FIELDS: Tuple[str, ...] = (
    "at",          # ISO-8601 UTC timestamp
    "op",          # "redact" or "restore"
    "source",      # caller-supplied label (host, tool, corpus id)
    "spans",       # values masked, or tokens resolved
    "counts",      # {entity_type: n}
    "chars_in",    # input length
    "chars_out",   # output length
    "elapsed_ms",  # wall-clock cost of the core call
    "truncated",   # the size guard fired
    "cached",      # served by the content-hash cache
)

#: How many timings to keep for the percentile summary. Bounded so a long-lived
#: gateway does not grow a list for the lifetime of the process.
DEFAULT_SAMPLE_WINDOW = 512


def is_safe_record(record: Dict[str, Any]) -> bool:
    """True when *record* can only carry counters — never personal data.

    Checked by tests, and worth calling in a host that forwards records to a
    third-party collector: it is the one assertion standing between "we ship
    metrics" and "we ship documents".
    """
    if not isinstance(record, dict) or set(record) - set(EVENT_FIELDS):
        return False
    counts = record.get("counts")
    if not isinstance(counts, dict):
        return False
    if not all(isinstance(key, str) and isinstance(value, int) for key, value in counts.items()):
        return False
    for key in ("spans", "chars_in", "chars_out"):
        if not isinstance(record.get(key), int):
            return False
    return isinstance(record.get("elapsed_ms"), (int, float))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------


class TelemetryError(RuntimeError):
    """A sink could not ship its records.

    Raised by a sink, absorbed by :class:`TelemetryConnector` — which is the
    whole convention: a sink is free to report failure loudly, the connector
    turns it into a counter so nothing reaches the agent's hot path.
    """


class JsonLinesSink:
    """Write one JSON object per line to an open text stream.

    The stream is not owned: closing the sink flushes it and leaves it open, so
    passing ``sys.stderr`` is safe.
    """

    def __init__(self, stream: IO[str], flush_each: bool = True) -> None:
        self._stream = stream
        self._flush_each = flush_each

    def emit(self, record: Dict[str, Any]) -> None:
        self._stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        if self._flush_each:
            self._stream.flush()

    def flush(self) -> None:
        self._stream.flush()

    def close(self) -> None:
        self.flush()


class MemorySink:
    """Accumulate records in memory. Bounded, so it cannot grow without limit."""

    def __init__(self, max_records: int = 10_000) -> None:
        self.records: Deque[Dict[str, Any]] = deque(maxlen=max_records)

    def emit(self, record: Dict[str, Any]) -> None:
        self.records.append(record)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None

    def as_list(self) -> List[Dict[str, Any]]:
        return list(self.records)


#: Signature of an :class:`HttpSink` transport: ``(url, body, headers, timeout)``.
Transport = Callable[[str, bytes, Dict[str, str], float], None]


def _urllib_post(url: str, body: bytes, headers: Dict[str, str], timeout: float) -> None:
    """Default transport — stdlib only, like the rest of the package."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        response.read()


class HttpSink:
    """Batched ``POST`` of records to a collector.

    Batching is what makes this usable on an agent's hot path: one request per
    ``batch_size`` events rather than one per redaction. Call :meth:`flush` (or
    use the connector as a context manager) to ship the tail.

    *transport* is injectable so tests can assert on the wire format without a
    socket, and so a host that already has an HTTP client with retries and auth
    can plug it in instead of ``urllib``.
    """

    def __init__(
        self,
        url: str,
        timeout: float = 2.0,
        batch_size: int = 20,
        headers: Optional[Dict[str, str]] = None,
        transport: Optional[Transport] = None,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.batch_size = max(1, batch_size)
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self._transport: Transport = transport or _urllib_post
        self._pending: List[Dict[str, Any]] = []
        self.sent = 0
        self.failed = 0

    def emit(self, record: Dict[str, Any]) -> None:
        self._pending.append(record)
        if len(self._pending) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        """Ship the pending batch, raising :class:`TelemetryError` if it fails.

        A failed batch is dropped, never retried: retrying would mean holding a
        growing buffer and re-entering a failing collector on every subsequent
        call. The counters are cheap to lose and the agent is not.
        """
        if not self._pending:
            return
        batch, self._pending = self._pending, []
        body = json.dumps({"records": batch}, ensure_ascii=False).encode("utf-8")
        try:
            self._transport(self.url, body, dict(self.headers), self.timeout)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.failed += len(batch)
            logger.warning("pii-redact telemetry: dropped %d record(s): %s", len(batch), exc)
            raise TelemetryError(str(exc)) from exc
        self.sent += len(batch)

    def close(self) -> None:
        try:
            self.flush()
        except TelemetryError:
            pass


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class TelemetryConnector:
    """Wrap the two core calls and emit one record per call.

    The engine itself is untouched: this class calls :meth:`Redactor.redact` /
    :meth:`Redactor.restore` exactly as any other caller would and returns their
    results unchanged, so it can be dropped into an existing path without
    altering behaviour. A host that already calls the core elsewhere can skip
    the wrappers entirely and feed results in through :meth:`observe`.
    """

    def __init__(
        self,
        sinks: Sequence[Any] = (),
        redactor: Optional[Redactor] = None,
        source: str = "",
        clock: Callable[[], str] = _utc_now,
        sample_window: int = DEFAULT_SAMPLE_WINDOW,
    ) -> None:
        self.sinks = list(sinks)
        self.source = source
        self._redactor = redactor
        self._clock = clock
        self._samples: Deque[float] = deque(maxlen=max(1, sample_window))
        self.calls = 0
        self.spans = 0
        self.restored = 0
        self.truncated = 0
        self.cached = 0
        self.dropped = 0
        self.total_ms = 0.0
        self.counts: Dict[str, int] = {}

    # -- core wrappers -------------------------------------------------------

    def redactor(self) -> Redactor:
        """The redactor in use — the injected one, or the process-wide singleton."""
        return self._redactor if self._redactor is not None else get_redactor()

    def redact(self, text: str, source: str = "") -> RedactionResult:
        """Pseudonymise *text* and emit one record. Returns the core's result."""
        result = self.redactor().redact(text)
        self.observe(result, source=source, chars_in=len(text))
        return result

    def restore(self, text: str, source: str = "") -> str:
        """De-pseudonymise *text* and emit one record.

        Restoration happens first and is returned even if the metrics path
        raises: on a closed loop, the answer the user reads must never depend on
        whether a collector is reachable.
        """
        started = time.perf_counter()
        restored = self.redactor().restore(text)
        elapsed_ms = (time.perf_counter() - started) * 1000
        counts = self._resolved_token_counts(text)
        self._record(
            {
                "at": self._clock(),
                "op": "restore",
                "source": source or self.source,
                "spans": sum(counts.values()),
                "counts": counts,
                "chars_in": len(text),
                "chars_out": len(restored),
                "elapsed_ms": round(elapsed_ms, 3),
                "truncated": False,
                "cached": False,
            }
        )
        return restored

    def observe(
        self,
        result: RedactionResult,
        source: str = "",
        op: str = "redact",
        chars_in: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Emit a record for an *already computed* redaction.

        This is the seam for a host that calls the core on its own — a Hermes
        hook, the stdio server — and only wants the observability half.
        """
        counts = result.counts()
        record = {
            "at": self._clock(),
            "op": op,
            "source": source or self.source,
            "spans": len(result.spans),
            "counts": counts,
            "chars_in": len(result.text) if chars_in is None else chars_in,
            "chars_out": len(result.text),
            "elapsed_ms": round(result.elapsed_ms, 3),
            "truncated": bool(result.truncated),
            "cached": bool(result.cached),
        }
        self._record(record)
        return record

    # -- reporting -----------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """Roll-up of everything seen so far. Safe to log or ship as-is.

        ``spans``/``counts`` cover the outbound direction only; tokens resolved
        on the way back are reported separately as ``restored``. Summing the two
        would produce a number that means nothing — the same value masked once
        and restored once is one protected value, not two.
        """
        samples = sorted(self._samples)
        return {
            "calls": self.calls,
            "spans": self.spans,
            "counts": dict(sorted(self.counts.items())),
            "restored": self.restored,
            "truncated": self.truncated,
            "cached": self.cached,
            "dropped": self.dropped,
            "total_ms": round(self.total_ms, 3),
            "p50_ms": _percentile(samples, 0.50),
            "p95_ms": _percentile(samples, 0.95),
        }

    def flush(self) -> None:
        """Ship whatever the sinks are still holding. Failures are counted."""
        for sink in self.sinks:
            flush = getattr(sink, "flush", None)
            if flush is None:
                continue
            try:
                flush()
            except Exception as exc:  # a collector must never break the caller
                self.dropped += 1
                logger.warning("pii-redact telemetry: flush failed: %s", exc)

    def close(self) -> None:
        for sink in self.sinks:
            close = getattr(sink, "close", None)
            if close is None:
                continue
            try:
                close()
            except Exception as exc:
                self.dropped += 1
                logger.warning("pii-redact telemetry: close failed: %s", exc)

    def __enter__(self) -> "TelemetryConnector":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals -----------------------------------------------------------

    def _record(self, record: Dict[str, Any]) -> None:
        """Update the roll-up, then fan the record out to every sink."""
        self.calls += 1
        self.total_ms += record["elapsed_ms"]
        self._samples.append(record["elapsed_ms"])
        if record["truncated"]:
            self.truncated += 1
        if record["cached"]:
            self.cached += 1
        if record["op"] == "restore":
            self.restored += record["spans"]
        else:
            self.spans += record["spans"]
            for entity_type, count in record["counts"].items():
                self.counts[entity_type] = self.counts.get(entity_type, 0) + count
        for sink in self.sinks:
            try:
                sink.emit(record)
            except Exception as exc:  # includes TelemetryError from HttpSink
                self.dropped += 1
                logger.warning("pii-redact telemetry: sink %s failed: %s", type(sink).__name__, exc)

    def _resolved_token_counts(self, text: str) -> Dict[str, int]:
        """Count the bracketed tokens in *text* that the vault can resolve.

        Bare tokens (``EMAIL_0001``, brackets stripped by the model) are
        restored by the core but not counted here: reproducing that heuristic
        in a metrics path would be a second place to keep in sync, and an
        undercount is the harmless direction.
        """
        vault = self.redactor().vault
        counts: Dict[str, int] = {}
        for match in TOKEN_RE.finditer(text):
            if vault.value_for(match.group(0)) is None:
                continue
            entity_type = match.group(1)
            counts[entity_type] = counts.get(entity_type, 0) + 1
        return counts


def _percentile(sorted_values: Sequence[float], quantile: float) -> float:
    """Nearest-rank percentile. Returns ``0.0`` on an empty sample."""
    if not sorted_values:
        return 0.0
    index = max(0, min(len(sorted_values) - 1, int(round(quantile * len(sorted_values))) - 1))
    return round(sorted_values[index], 3)
