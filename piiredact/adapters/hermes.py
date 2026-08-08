"""Hermes Agent adapter — four seams, each with one job.

======================  ==================================================
Seam                    Job
======================  ==================================================
``transform_tool_result``  Redact what tools bring *in* (file reads, document
                           extraction, shell output) before the model sees it.
``llm_request`` mw         Last-mile pass over the provider payload — catches
                           anything that reached the context another way
                           (pasted text, recalled memory, injected profile).
``tool_request`` mw        Put real values *back* into local tool arguments,
                           so the agent keeps working on real data.
``transform_llm_output``   Put real values back into the answer the user reads.
======================  ==================================================

Read together they form a closed loop: real values exist on disk, in tools and
on the user's screen; only the span between "leaving the machine" and "coming
back" is tokenised. That is what lets the user still ask "quelle est l'adresse
de facturation ?" and get a real answer from a model that never saw it.

Every callback is fail-safe in the direction that matters: an unexpected error
in the *outbound* path (redaction) is re-raised into a hard failure only in
block mode — otherwise the result is dropped rather than passed through raw.
Errors in the *inbound* path (restoration) degrade to "the token stays", which
is inert.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
from typing import Any, Dict, List, Optional

from .. import get_redactor, reset_redactor
from ..config import Settings, load_settings
from ..payloads import contains_token, redact_request, restore_args
from ..policy import should_restore_args
from ..redactor import Redactor

logger = logging.getLogger(__name__)

#: Sentinel returned to the model when block mode refuses an operation.
_BLOCK_PREFIX = "pii-redact a bloqué cette opération"


# ---------------------------------------------------------------------------
# Settings / singleton
# ---------------------------------------------------------------------------


def _resolve_settings() -> Settings:
    """Build settings, letting Hermes decide where state lives.

    ``PII_REDACT_DB`` wins when set. Otherwise the vault follows the *active*
    Hermes home — which is a context-local value under profiles and kanban
    workers, so it is resolved through the host rather than read from the
    environment.
    """
    settings = load_settings()
    if os.environ.get("PII_REDACT_DB", "").strip():
        return settings
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        home = get_hermes_home()
    except Exception:
        return settings
    return dataclasses.replace(settings, db_path=home / "pii-redact" / "mapping.db")


def _build_redactor() -> Redactor:
    return Redactor(_resolve_settings())


try:  # Prefer the host's thread-safe primitive when it is importable.
    from plugins.plugin_utils import lazy_singleton  # type: ignore

    _get_redactor = lazy_singleton(_build_redactor)
except Exception:  # standalone / test import of this module
    _get_redactor = None  # type: ignore[assignment]


def redactor() -> Redactor:
    """Return the process-wide redactor."""
    if _get_redactor is not None:
        return _get_redactor()
    return get_redactor(_resolve_settings())


def reset() -> None:
    """Drop the singleton — used by tests and by ``on_session_reset``."""
    if _get_redactor is not None and hasattr(_get_redactor, "reset"):
        _get_redactor.reset()  # type: ignore[attr-defined]
    reset_redactor()


def _settings() -> Settings:
    return redactor().settings


# ---------------------------------------------------------------------------
# Outbound: what the model is allowed to see
# ---------------------------------------------------------------------------


def on_transform_tool_result(
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    **_: Any,
) -> Optional[str]:
    """Redact a tool result before it re-enters the conversation."""
    red = redactor()
    settings = red.settings
    if not settings.enabled or not settings.guard_tool_results:
        return None
    if not isinstance(result, str) or not result:
        return None
    try:
        redacted, count = red.redact_payload(result)
    except Exception as exc:
        logger.warning("pii-redact: tool-result pass failed for %s: %s", tool_name, exc)
        if settings.block:
            return json.dumps(
                {"error": f"{_BLOCK_PREFIX} : échec de la pseudonymisation du résultat."},
                ensure_ascii=False,
            )
        return None
    if count == 0:
        return None
    if settings.log_counts:
        logger.info("pii-redact: %s result — %d value(s) tokenised", tool_name, count)
    return redacted


def on_llm_request(request: Any = None, **_: Any) -> Optional[Dict[str, Any]]:
    """Final pass over the provider payload. Returns ``{"request": ...}``.

    Deterministic by construction: the same history yields the same tokens and
    therefore the same bytes, so the provider's prompt cache still hits. The
    content-hash cache in the core is what keeps this pass cheap even though it
    runs on the whole conversation before every single API call.
    """
    red = redactor()
    settings = red.settings
    if not settings.enabled or not settings.guard_payload:
        return None
    if not isinstance(request, dict):
        return None
    try:
        new_request, count = redact_request(red, request)
    except Exception as exc:
        logger.warning("pii-redact: payload pass failed: %s", exc)
        return None
    if count == 0:
        return None
    if settings.log_counts:
        logger.info("pii-redact: payload — %d value(s) tokenised before send", count)
    return {"request": new_request, "source": "pii-redact"}


# ---------------------------------------------------------------------------
# Inbound: giving the real values back
# ---------------------------------------------------------------------------


def on_tool_request(
    tool_name: str = "",
    args: Any = None,
    **_: Any,
) -> Optional[Dict[str, Any]]:
    """De-pseudonymise arguments for local tools. Returns ``{"args": ...}``.

    Egress tools are deliberately left on tokens (see :mod:`piiredact.policy`):
    restoring there would trade a leak to the model for a leak to a third
    party, which is not an improvement.
    """
    red = redactor()
    settings = red.settings
    if not settings.enabled or not settings.restore_tool_args:
        return None
    if not isinstance(args, dict) or not args:
        return None
    if not should_restore_args(tool_name, settings.egress_extra, settings.local_extra):
        return None
    try:
        new_args, changed = restore_args(red, args)
    except Exception as exc:
        logger.warning("pii-redact: arg restore failed for %s: %s", tool_name, exc)
        return None
    if not changed:
        return None
    return {"args": new_args, "source": "pii-redact"}


def on_transform_llm_output(response_text: str = "", **_: Any) -> Optional[str]:
    """Restore tokens in the final answer so the user reads real values."""
    red = redactor()
    if not red.settings.enabled or not response_text:
        return None
    try:
        restored = red.restore(response_text)
    except Exception as exc:
        logger.warning("pii-redact: output restore failed: %s", exc)
        return None
    return restored if restored != response_text else None


# ---------------------------------------------------------------------------
# Block mode + lifecycle
# ---------------------------------------------------------------------------


def on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    **_: Any,
) -> Optional[Dict[str, str]]:
    """Block mode: refuse to let identified data reach a third-party tool.

    Off by default. When on, a web search / fetch / browser call whose
    arguments still carry real PII (or a token that would resolve to it) is
    refused with an explanation the model can act on, rather than being
    silently rewritten.
    """
    red = redactor()
    settings = red.settings
    if not settings.enabled or not settings.block:
        return None
    if should_restore_args(tool_name, settings.egress_extra, settings.local_extra):
        return None  # local tool: nothing leaves the machine
    if not isinstance(args, dict) or not args:
        return None
    try:
        _, count = red.redact_obj(args)
        risky = count > 0 or contains_token(red, args)
    except Exception as exc:
        logger.warning("pii-redact: block-mode scan failed for %s: %s", tool_name, exc)
        return None
    if not risky:
        return None
    return {
        "action": "block",
        "message": (
            f"{_BLOCK_PREFIX} : l'appel `{tool_name}` transmettrait des données "
            "personnelles à un service tiers. Reformule la requête sans les "
            "valeurs personnelles (les jetons [TYPE_NNNN] ne sont pas "
            "résolus vers un outil externe). Pour lever le blocage : "
            "PII_REDACT_BLOCK=0."
        ),
    }


def on_session_start(**_: Any) -> None:
    """Warm everything expensive off the latency-critical path.

    The gazetteer compiles in-line (milliseconds); the spaCy model, when
    enabled, loads on a background thread because a cold load costs seconds and
    must never land inside a tool call.
    """
    try:
        red = redactor()
        red._ensure_matcher(red.settings.types)  # noqa: SLF001 - deliberate warm-up
        if red.settings.use_ner:
            red.ner.prewarm()
    except Exception as exc:
        logger.debug("pii-redact: warm-up skipped: %s", exc)


def on_session_reset(**_: Any) -> None:
    reset()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(ctx: Any) -> None:
    """Wire every seam. Called by the plugin's ``register(ctx)``."""
    ctx.register_hook("transform_tool_result", on_transform_tool_result)
    ctx.register_hook("transform_llm_output", on_transform_llm_output)
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("on_session_reset", on_session_reset)
    ctx.register_middleware("llm_request", on_llm_request)
    ctx.register_middleware("tool_request", on_tool_request)

    settings = _resolve_settings()
    logger.info(
        "pii-redact active — profile=%s types=%d ner=%s block=%s db=%s",
        settings.profile,
        len(settings.types),
        settings.use_ner,
        settings.block,
        settings.db_path,
    )


#: Hooks and middleware this adapter installs — mirrored in ``plugin.yaml``.
HOOKS: List[str] = [
    "transform_tool_result",
    "transform_llm_output",
    "pre_tool_call",
    "on_session_start",
    "on_session_reset",
]
MIDDLEWARE: List[str] = ["llm_request", "tool_request"]
