# Add a connector

This document explains how to wire `pii-redact` into a host that is not yet
supported. It targets people writing a new adapter, not people changing the
core engine. That separation is intentional: **connectors must not contain
detection logic**.

## 1. Minimal contract

The core intentionally exposes two entry points:

```python
from piiredact import redact, restore

result = redact(text)   # -> RedactionResult: .text, .counts(), .truncated, .elapsed_ms
real   = restore(text)  # -> str
```

Writing a connector means answering only two questions:

| Question | Required answer |
|---|---|
| **Where does text leave the machine?** | Run that path through `redact()` before sending. |
| **Where does text come back to the user or a local tool?** | Run that path through `restore()` before rendering/executing. |

Everything else (SQLite vault, compiled rules, literal directory, hash cache)
lives behind `get_redactor()`. A connector should call
`piiredact.redact` / `piiredact.restore`, or `get_redactor()` only when it
needs lower-level methods (`redact_obj`, `redact_payload`, `restore_obj`,
`learn`).

> Practical consequence: keep the process warm. Spawning `python -m piiredact
> redact` per event pays interpreter startup every time.

## 2. Which connector to build

- If the host can load Python and provides callbacks/hooks: build a dedicated
  in-process adapter (model: `piiredact/adapters/hermes.py`).
- If the host can spawn a subprocess: reuse
  `piiredact/adapters/stdio.py` (`python3 -m piiredact serve`).
- If the host only speaks HTTP: wrap the stdio request handler (see below).
- If you only want observability and no interception: model
  `piiredact/adapters/telemetry.py`.

## 3. Common integration cases

### (a) Outbound-only redaction

```python
from piiredact import redact


def on_outbound(text: str) -> str:
    return redact(text).text
```

If content is JSON, prefer `get_redactor().redact_payload(payload)` so JSON
structure stays valid.

If you process a full provider payload (messages, tools, correlation IDs), use
`piiredact.payloads.redact_request()` instead of custom traversal.

### (b) Closed loop (redact + restore)

```python
from piiredact import redact, restore


def ask(model, question: str, document: str) -> str:
    reply = model(redact(document).text, redact(question).text)
    return restore(reply)
```

Core guarantees that make this safe:

- **Idempotence**: `redact(redact(x)) == redact(x)`
- **Unknown token passthrough**: `restore()` leaves unknown tokens unchanged

### (c) Restoring local tool arguments

Do not re-implement policy; use `piiredact.policy.should_restore_args()`.

- Local tools: restore args before execution.
- Egress tools (web/fetch/browser): keep tokens to avoid third-party leakage.

## 4. Pitfalls

- **Never postpone restoration on critical inbound paths.**
- **Use asymmetric fail-safe behavior**:
  - Outbound (`redact`) error: never let clear text pass.
  - Inbound (`restore`) error: token can remain as inert marker.
- **Respect `PII_REDACT_BLOCK`** via `settings.block`; do not invent custom
  blocking policy.
- **Do not break prompt caching**: outbound payload bytes must be deterministic
  for identical history.
- **Do not add rule ordering in adapters**: priorities and overlap resolution
  already exist in the core.
- **Never log values**: only counters/sizes/timings.
- **Never expose vault reads to the agent**.

## 5. HTTP server variant

For HTTP-only hosts, wrap `piiredact.adapters.stdio.handle_request()` and keep
transport concerns isolated from core logic.

Always bind to `127.0.0.1`, not `0.0.0.0`, unless you add proper
authentication/authorization and treat the service as sensitive as the vault.

## 6. Reference connector: telemetry

`piiredact/adapters/telemetry.py` is the reference for outbound observability.
It emits only safe metrics fields (counts, sizes, timings, booleans), never raw
text, spans, or token values.

Available sinks:

- `JsonLinesSink(stream)`
- `MemorySink()`
- `HttpSink(url, batch_size=..., transport=...)`

A failed telemetry batch is dropped by design to preserve agent latency and
memory bounds.

## 7. Completion checklist

- [ ] All outbound paths pass through `redact()`.
- [ ] All inbound render/execute paths pass through `restore()`.
- [ ] Egress/local tool policy uses `should_restore_args()`.
- [ ] Outbound failures are fail-safe (no clear-text leakage).
- [ ] `settings.block` is honored.
- [ ] Output is deterministic for identical history.
- [ ] Logs contain counters only.
- [ ] A leak test replays `tests/fixtures.py::ALL_FIXTURES` through the connector
      and asserts no declared secret survives.
