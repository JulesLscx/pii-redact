"""Line-delimited JSON adapter — the universal integration path.

One JSON object per line in, one per line out. No framing, no dependencies, no
assumptions about the host: OpenCode, Codex, an editor extension or a shell
script can all drive the engine through this.

Request::

    {"op": "redact",  "text": "IBAN FR76 ..."}
    {"op": "restore", "text": "écris à [EMAIL_0001]"}
    {"op": "redact_args", "tool": "web_search", "args": {...}}
    {"op": "restore_args", "tool": "write_file", "args": {...}}
    {"op": "learn", "type": "PERSON", "value": "Amélie"}
    {"op": "status"}

Response::

    {"ok": true, "text": "IBAN [IBAN_0001]", "counts": {"IBAN": 1}, "ms": 1.2}
    {"ok": false, "error": "unknown op: frobnicate"}

Keeping one process warm amortises interpreter startup and keeps the vault,
the compiled rules and the gazetteer in memory — which is the difference
between a ~1 ms call and a ~100 ms one.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any, Dict, IO, Optional

from .. import get_redactor
from ..payloads import restore_args as _restore_args
from ..policy import should_restore_args


def handle_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """Execute one request object and return the response object."""
    op = str(request.get("op") or "").strip().lower()
    red = get_redactor()
    started = time.perf_counter()

    if op == "redact":
        result = red.redact(str(request.get("text") or ""))
        return {
            "ok": True,
            "text": result.text,
            "counts": result.counts(),
            "truncated": result.truncated,
            "ms": round(result.elapsed_ms, 3),
        }

    if op == "restore":
        text = red.restore(str(request.get("text") or ""))
        return {"ok": True, "text": text, "ms": _ms(started)}

    if op == "redact_args":
        new_args, count = red.redact_obj(request.get("args") or {})
        return {"ok": True, "args": new_args, "count": count, "ms": _ms(started)}

    if op == "restore_args":
        tool = str(request.get("tool") or "")
        settings = red.settings
        if not should_restore_args(tool, settings.egress_extra, settings.local_extra):
            return {
                "ok": True,
                "args": request.get("args") or {},
                "changed": False,
                "reason": "egress tool — arguments intentionally left tokenised",
                "ms": _ms(started),
            }
        new_args, changed = _restore_args(red, request.get("args") or {})
        return {"ok": True, "args": new_args, "changed": changed, "ms": _ms(started)}

    if op == "learn":
        token = red.learn(
            str(request.get("type") or "PERSON").upper(),
            str(request.get("value") or ""),
        )
        return {"ok": True, "token": token, "ms": _ms(started)}

    if op == "status":
        settings = red.settings
        return {
            "ok": True,
            "enabled": settings.enabled,
            "profile": settings.profile,
            "types": sorted(settings.types),
            "mappings": red.vault.count(),
            "ms": _ms(started),
        }

    return {"ok": False, "error": f"unknown op: {op or '(missing)'}"}


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


def serve(stream_in: Optional[IO[str]] = None, stream_out: Optional[IO[str]] = None) -> None:
    """Read requests until EOF. Malformed lines answer with an error, not a crash."""
    source = stream_in if stream_in is not None else sys.stdin
    sink = stream_out if stream_out is not None else sys.stdout
    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError as exc:
            response: Dict[str, Any] = {"ok": False, "error": f"invalid JSON: {exc}"}
        else:
            try:
                response = handle_request(request)
            except Exception as exc:  # never let one bad request kill the server
                response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        sink.write(json.dumps(response, ensure_ascii=False) + "\n")
        sink.flush()
