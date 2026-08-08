"""piiredact — local, deterministic PII pseudonymisation for LLM agents.

Host-agnostic by construction: this package imports nothing but the standard
library, so the same core runs inside a Hermes plugin, a Claude Code hook
subprocess, an OpenCode/Codex integration, or a shell pipe.

Two calls carry the whole contract::

    from piiredact import redact, restore

    safe = redact(open("facture.pdf.txt").read()).text  # -> model
    real = restore(model_answer)                        # -> user / tool

Everything else (vault, rules, gazetteer, optional NER) is an implementation
detail of those two, and every host adapter is a thin wrapper around them.
"""

from __future__ import annotations

import threading
from typing import Optional

from .config import Settings, load_settings
from .lang import available as available_languages
from .redactor import Redactor
from .types import (
    ALL_TYPES,
    CORE_IDENTIFIERS,
    PROFILES,
    QUASI_IDENTIFIERS,
    EntityType,
    RedactionResult,
    Span,
    resolve_type,
    resolve_types,
)
from .vault import Vault

__all__ = [
    "ALL_TYPES",
    "CORE_IDENTIFIERS",
    "PROFILES",
    "QUASI_IDENTIFIERS",
    "available_languages",
    "resolve_type",
    "resolve_types",
    "EntityType",
    "RedactionResult",
    "Redactor",
    "Settings",
    "Span",
    "Vault",
    "get_redactor",
    "load_settings",
    "redact",
    "reset_redactor",
    "restore",
]

__version__ = "0.1.0"

_lock = threading.Lock()
_redactor: Optional[Redactor] = None


def get_redactor(settings: Optional[Settings] = None) -> Redactor:
    """Return the process-wide :class:`Redactor` (built on first use).

    Double-checked locking rather than a bare ``if _redactor is None``: agent
    sessions are multi-threaded, and two threads racing here would open two
    SQLite connections and two spaCy pipelines, then leak one of each.
    """
    global _redactor
    if _redactor is not None:
        return _redactor
    with _lock:
        if _redactor is None:
            _redactor = Redactor(settings)
        return _redactor


def reset_redactor() -> None:
    """Drop the singleton (tests, and config changes that need a rebuild)."""
    global _redactor
    with _lock:
        if _redactor is not None:
            try:
                _redactor.vault.close()
            except Exception:
                pass
        _redactor = None


def redact(text: str, settings: Optional[Settings] = None) -> RedactionResult:
    """Pseudonymise *text*. See :meth:`Redactor.redact`."""
    return get_redactor(settings).redact(text)


def restore(text: str, settings: Optional[Settings] = None) -> str:
    """Reverse :func:`redact`. See :meth:`Redactor.restore`."""
    return get_redactor(settings).restore(text)
