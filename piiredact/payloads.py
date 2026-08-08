"""Provider-payload surgery — the last-mile guarantee.

Redacting tool results covers the main leak path, but not all of it: the user
can paste an IBAN into the chat, a memory plugin can inject a recalled note, a
system prompt can carry a profile. The only place where *everything* destined
for the model converges is the provider request itself, so that is where the
final pass runs.

Two rules govern this module:

* **Only text fields.** Ids (``tool_call_id``), tool schemas and control fields
  are left byte-identical — a five-digit substring inside a call id must never
  be mistaken for a postal code, or the host's tool-call bookkeeping breaks.
* **Deterministic output.** The same conversation must serialise to the same
  bytes on every call, otherwise the provider's prompt cache misses on every
  turn and the user pays for it twice (latency and tokens). Token allocation is
  content-addressed precisely so this holds.

The shapes handled cover the OpenAI chat/responses families and the Anthropic
messages family, which is also what OpenCode, Codex and Claude Code speak — so
this module is reusable outside Hermes as-is.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .policy import PROTECTED_ARG_KEYS

#: Top-level request keys that carry conversation text.
TEXT_BEARING_KEYS = ("messages", "input", "system", "prompt", "instructions")

#: Top-level keys that must never be touched (schemas, routing, transport).
FROZEN_KEYS = frozenset(
    {
        "tools",
        "tool_choice",
        "functions",
        "function_call",
        "response_format",
        "extra_headers",
        "extra_body",
        "extra_query",
        "metadata",
        "model",
        "stream",
        "stream_options",
        "temperature",
        "top_p",
        "max_tokens",
        "max_completion_tokens",
        "stop",
        "seed",
        "user",
        "reasoning",
        "reasoning_effort",
        "logit_bias",
    }
)

#: Message-level keys holding text.
_CONTENT_KEYS = ("content", "text", "input_text", "output_text", "thinking")


def redact_request(redactor: Any, request: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    """Return ``(new_request, span_count)`` with every text field redacted.

    The input dict is not mutated; the host decides whether to adopt the copy.
    """
    if not isinstance(request, dict):
        return request, 0
    out = dict(request)
    total = 0
    for key in TEXT_BEARING_KEYS:
        if key not in out or key in FROZEN_KEYS:
            continue
        new_value, count = _redact_node(redactor, out[key])
        out[key] = new_value
        total += count
    return (out, total) if total else (request, 0)


def _redact_node(redactor: Any, node: Any) -> Tuple[Any, int]:
    """Recursively redact the text-bearing parts of a message tree."""
    if isinstance(node, str):
        result = redactor.redact(node)
        return result.text, len(result.spans)
    if isinstance(node, list):
        items: List[Any] = []
        total = 0
        for item in node:
            new_item, count = _redact_node(redactor, item)
            items.append(new_item)
            total += count
        return items, total
    if isinstance(node, dict):
        out: Dict[str, Any] = {}
        total = 0
        for key, value in node.items():
            if key in PROTECTED_ARG_KEYS or key in FROZEN_KEYS:
                out[key] = value
                continue
            if key in _CONTENT_KEYS or isinstance(value, (list, dict)):
                new_value, count = _redact_node(redactor, value)
                out[key] = new_value
                total += count
                continue
            if key == "arguments" and isinstance(value, str):
                # Assistant tool-call arguments: JSON-encoded, so go through
                # the structured path to keep the envelope parseable.
                new_value, count = redactor.redact_payload(value)
                out[key] = new_value
                total += count
                continue
            out[key] = value
        return out, total
    return node, 0


def restore_args(
    redactor: Any,
    args: Any,
    protected: Optional[frozenset] = None,
) -> Tuple[Any, bool]:
    """De-pseudonymise tool arguments, skipping correlation/control keys.

    Returns ``(new_args, changed)``.
    """
    guard = PROTECTED_ARG_KEYS if protected is None else protected
    if isinstance(args, str):
        restored = redactor.restore(args)
        return restored, restored != args
    if isinstance(args, list):
        out_list: List[Any] = []
        changed = False
        for item in args:
            new_item, item_changed = restore_args(redactor, item, guard)
            out_list.append(new_item)
            changed = changed or item_changed
        return out_list, changed
    if isinstance(args, dict):
        out: Dict[str, Any] = {}
        changed = False
        for key, value in args.items():
            if key in guard:
                out[key] = value
                continue
            new_value, value_changed = restore_args(redactor, value, guard)
            out[key] = new_value
            changed = changed or value_changed
        return out, changed
    return args, False


def contains_token(redactor: Any, value: Any) -> bool:
    """True when *value* still holds a token that maps to a real value."""
    from .rules import TOKEN_RE

    if isinstance(value, str):
        return any(
            redactor.vault.value_for(match.group(0)) is not None
            for match in TOKEN_RE.finditer(value)
        )
    if isinstance(value, dict):
        return any(contains_token(redactor, item) for item in value.values())
    if isinstance(value, list):
        return any(contains_token(redactor, item) for item in value)
    return False
