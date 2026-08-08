"""Host adapters.

Each module here is a thin translation layer between one host's extension
protocol and the two core calls (:func:`piiredact.redact` /
:func:`piiredact.restore`). Adapters hold no detection logic of their own, so
adding a host is a small, low-risk file — and a bug fixed in the core is fixed
for every host at once.

* :mod:`.hermes` — in-process Hermes plugin (hooks + middleware).
* :mod:`.stdio` — line-delimited JSON over stdin/stdout, for any host that can
  spawn a subprocess (OpenCode, Codex, editors, shell pipelines).
* :mod:`.claude_code` — Claude Code hook events on stdin, decisions on stdout.
* :mod:`.telemetry` — outbound direction: turns redaction *results* into
  counters for a log shipper, a collector or an evaluation report.

``docs/connectors.md`` walks through writing a fourth one.
"""

from __future__ import annotations

__all__ = ["claude_code", "hermes", "stdio", "telemetry"]
