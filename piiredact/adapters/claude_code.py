"""Claude Code adapter — one hook event in, one decision out.

Claude Code runs hooks as subprocesses: the event arrives as JSON on stdin and
the hook answers with JSON on stdout. Two of its events give us exactly the
seams we need:

* ``PreToolUse`` accepts ``updatedInput``, so tokens are swapped back to real
  values before a *local* tool runs — the same "no functionality loss" contract
  as the Hermes ``tool_request`` middleware. It also accepts
  ``permissionDecision: "deny"``, which is how block mode stops an egress tool
  from carrying personal data to a third party.
* ``PostToolUse`` accepts ``updatedToolOutput``, so a file read or a command's
  output is redacted before the model sees it.

Known gap, stated plainly: ``UserPromptSubmit`` **cannot** rewrite the prompt
(the event only accepts ``additionalContext`` or a hard block), so PII the user
types directly into Claude Code cannot be tokenised in flight the way the
Hermes ``llm_request`` middleware does it. Block mode turns that into a refusal
with an explanation instead of a silent leak; the default profile lets it
through and says so here rather than pretending otherwise.

Wiring (``~/.claude/settings.json``)::

    {"hooks": {
      "PreToolUse":  [{"hooks": [{"type": "command",
                                  "command": "python -m piiredact hook"}]}],
      "PostToolUse": [{"hooks": [{"type": "command",
                                  "command": "python -m piiredact hook"}]}]
    }}
"""

from __future__ import annotations

from typing import Any, Dict

from .. import get_redactor
from ..payloads import contains_token, restore_args
from ..policy import should_restore_args

_DENY_REASON = (
    "pii-redact: cet appel transmettrait des données personnelles à un service "
    "tiers. Reformule sans les valeurs personnelles."
)

_PROMPT_WARNING = (
    "pii-redact: des données personnelles ont été détectées dans ce message. "
    "Claude Code ne permet pas de les remplacer avant envoi — elles ont donc "
    "été transmises telles quelles."
)


def _hook_output(event_name: str, **fields: Any) -> Dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": event_name, **fields}}


def handle_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Route one hook event. Unknown events answer with an empty decision."""
    name = str(event.get("hook_event_name") or event.get("hookEventName") or "")
    if name == "PreToolUse":
        return _pre_tool_use(event)
    if name == "PostToolUse":
        return _post_tool_use(event)
    if name == "UserPromptSubmit":
        return _user_prompt_submit(event)
    return {}


def _pre_tool_use(event: Dict[str, Any]) -> Dict[str, Any]:
    red = get_redactor()
    settings = red.settings
    tool = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input")
    if not settings.enabled or not isinstance(tool_input, dict):
        return {}

    if not should_restore_args(tool, settings.egress_extra, settings.local_extra):
        if settings.block:
            _, count = red.redact_obj(tool_input)
            if count > 0 or contains_token(red, tool_input):
                return _hook_output(
                    "PreToolUse",
                    permissionDecision="deny",
                    permissionDecisionReason=_DENY_REASON,
                )
        return {}

    if not settings.restore_tool_args:
        return {}
    new_input, changed = restore_args(red, tool_input)
    if not changed:
        return {}
    return _hook_output("PreToolUse", updatedInput=new_input)


def _post_tool_use(event: Dict[str, Any]) -> Dict[str, Any]:
    red = get_redactor()
    if not red.settings.enabled or not red.settings.guard_tool_results:
        return {}
    response = event.get("tool_response")
    if isinstance(response, str):
        redacted, count = red.redact_payload(response)
    elif isinstance(response, (dict, list)):
        redacted_obj, count = red.redact_obj(response)
        redacted = redacted_obj  # type: ignore[assignment]
    else:
        return {}
    if count == 0:
        return {}
    return _hook_output("PostToolUse", updatedToolOutput=redacted)


def _user_prompt_submit(event: Dict[str, Any]) -> Dict[str, Any]:
    """Warn (or block) — this event cannot rewrite the prompt text."""
    red = get_redactor()
    settings = red.settings
    prompt = str(event.get("prompt") or "")
    if not settings.enabled or not prompt:
        return {}
    result = red.redact(prompt)
    if not result.spans:
        return {}
    if settings.block:
        return {
            "decision": "block",
            "reason": (
                "pii-redact: ce message contient des données personnelles "
                f"({', '.join(sorted(result.counts()))}). Reformule avec des "
                "jetons ou désactive PII_REDACT_BLOCK."
            ),
        }
    return {"systemMessage": _PROMPT_WARNING}
