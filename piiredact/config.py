"""Environment-driven configuration.

Every knob is an env var so the same core behaves identically whether it is
loaded in-process by a Hermes plugin or spawned as a one-shot subprocess by a
host that only speaks stdin/stdout (Claude Code hooks, OpenCode, Codex).

The host may also pass an explicit :class:`Settings` instance — nothing in the
core reads ``os.environ`` outside this module.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, Optional, Tuple

from .types import ALL_TYPES, DIRECT_IDENTIFIERS, QUASI_IDENTIFIERS

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}

ENV_PREFIX = "PII_REDACT_"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(ENV_PREFIX + name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name).lower()
    if raw in _TRUTHY:
        return True
    if raw in _FALSY:
        return False
    return default


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _split_types(raw: str) -> Tuple[str, ...]:
    return tuple(
        part.strip().upper()
        for part in raw.replace(";", ",").split(",")
        if part.strip()
    )


def default_data_dir() -> Path:
    """Resolve the state directory without hardcoding any host layout.

    Order: ``PII_REDACT_HOME`` → ``HERMES_HOME/pii-redact`` (set by Hermes for
    every profile, including ``~/.hermes/profiles/<name>``) → XDG state dir.
    """
    explicit = _env("HOME")
    if explicit:
        return Path(explicit).expanduser()
    hermes_home = os.environ.get("HERMES_HOME", "").strip()
    if hermes_home:
        return Path(hermes_home).expanduser() / "pii-redact"
    xdg = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "state"
    return base / "pii-redact"


@dataclass(frozen=True)
class Settings:
    """Immutable snapshot of the plugin configuration."""

    enabled: bool = True
    """``PII_REDACT_DISABLE=1`` turns the whole pipeline into a no-op."""

    block: bool = False
    """Block mode: refuse the operation instead of silently redacting it.

    Off by default — redacting is non-destructive and keeps the agent moving,
    which is the same trade-off ``security-guidance`` makes for its warnings.
    """

    profile: str = "balanced"
    """``balanced`` (direct identifiers only) or ``strict`` (+ amounts/dates)."""

    types: FrozenSet[str] = field(default_factory=lambda: frozenset(DIRECT_IDENTIFIERS))

    db_path: Path = field(default_factory=lambda: default_data_dir() / "mapping.db")

    terms_path: Optional[Path] = None
    """Optional newline-delimited ``TYPE:value`` seed list of literals."""

    use_ner: bool = False
    """Opt-in spaCy NER. Off by default: it costs 30-150 ms per document,
    which alone would eat the whole per-tool-call latency budget."""

    ner_model: str = "fr_core_news_sm"

    ner_max_chars: int = 20_000
    """Skip NER above this size — the deterministic layers still run."""

    budget_ms: int = 300
    """Soft deadline for one redact call. Exceeding it trips the fail-closed
    tail guard rather than letting a pathological input stall the agent."""

    max_bytes: int = 4 * 1024 * 1024
    """Hard cap on scanned content. Beyond it the tail is dropped, never passed
    through — an oversized document must not become a leak."""

    cache_entries: int = 4096
    """Content-hash LRU size. The provider payload is re-scanned on every API
    call, so cache hits are what keep the steady-state cost near zero."""

    restore_bare_tokens: bool = True
    """Also restore ``EMAIL_0001`` when the model drops the brackets."""

    log_counts: bool = False
    """Log per-type hit counts (never values) at INFO."""

    @property
    def redacts(self) -> FrozenSet[str]:
        return self.types

    def wants(self, entity_type: str) -> bool:
        return entity_type in self.types


def _resolve_types(profile: str) -> FrozenSet[str]:
    """Compute the active type set from profile + include/exclude overrides."""
    if profile == "strict":
        active = set(DIRECT_IDENTIFIERS) | set(QUASI_IDENTIFIERS)
    else:
        active = set(DIRECT_IDENTIFIERS)

    only = _split_types(_env("TYPES"))
    if only:
        active = {t for t in only if t in ALL_TYPES}
    for extra in _split_types(_env("ADD_TYPES")):
        if extra in ALL_TYPES:
            active.add(extra)
    for dropped in _split_types(_env("SKIP_TYPES")):
        active.discard(dropped)
    return frozenset(active)


def load_settings() -> Settings:
    """Build a :class:`Settings` from the current environment.

    Read fresh on demand rather than cached at import time so tests (and a
    long-lived gateway process whose env is updated between sessions) see
    changes without a restart.
    """
    profile = (_env("PROFILE", "balanced") or "balanced").lower()
    if profile not in {"balanced", "strict"}:
        profile = "balanced"

    db_override = _env("DB")
    db_path = (
        Path(db_override).expanduser()
        if db_override
        else default_data_dir() / "mapping.db"
    )

    terms_override = _env("TERMS")

    return Settings(
        enabled=not _env_bool("DISABLE", False),
        block=_env_bool("BLOCK", False),
        profile=profile,
        types=_resolve_types(profile),
        db_path=db_path,
        terms_path=Path(terms_override).expanduser() if terms_override else None,
        use_ner=_env_bool("NER", False),
        ner_model=_env("NER_MODEL", "fr_core_news_sm") or "fr_core_news_sm",
        ner_max_chars=_env_int("NER_MAX_CHARS", 20_000),
        budget_ms=_env_int("BUDGET_MS", 300),
        max_bytes=_env_int("MAX_BYTES", 4 * 1024 * 1024),
        cache_entries=_env_int("CACHE_ENTRIES", 4096),
        restore_bare_tokens=_env_bool("RESTORE_BARE_TOKENS", True),
        log_counts=_env_bool("LOG_COUNTS", False),
    )
