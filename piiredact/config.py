"""Configuration: a TOML file, overridable by environment variables.

Precedence, highest first:

1. ``PII_REDACT_*`` environment variables — for one-off runs, CI, and hosts
   that only know how to set env vars (``~/.hermes/.env``);
2. the config file — ``config.toml``, the place to express a durable policy;
3. built-in defaults — French, ``balanced`` profile, no NER.

Nothing else in the core reads ``os.environ`` or touches the filesystem for
configuration, so a host can bypass both layers entirely by constructing a
:class:`Settings` and passing it in.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

from .lang import DEFAULT_LANGUAGE, default_ner_model, normalise_languages
from .types import DEFAULT_PROFILE, PROFILES, resolve_types

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}

ENV_PREFIX = "PII_REDACT_"

CONFIG_FILENAME = "config.toml"


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


def _env(name: str, default: str = "") -> str:
    return os.environ.get(ENV_PREFIX + name, default).strip()


def _env_bool(name: str) -> Optional[bool]:
    raw = _env(name).lower()
    if raw in _TRUTHY:
        return True
    if raw in _FALSY:
        return False
    return None


def _env_int(name: str) -> Optional[int]:
    raw = _env(name)
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _split_list(raw: str) -> Tuple[str, ...]:
    return tuple(
        part.strip()
        for part in raw.replace(";", ",").split(",")
        if part.strip()
    )


def _as_list(value: Any) -> Tuple[str, ...]:
    """Accept both ``["en", "fr"]`` and ``"en, fr"`` in the config file."""
    if value is None:
        return ()
    if isinstance(value, str):
        return _split_list(value)
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


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


def default_config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "piiredact"


def config_search_paths() -> List[Path]:
    """Every location consulted for a config file, in order."""
    explicit = _env("CONFIG")
    paths: List[Path] = []
    if explicit:
        paths.append(Path(explicit).expanduser())
    paths.append(default_data_dir() / CONFIG_FILENAME)
    paths.append(default_config_dir() / CONFIG_FILENAME)
    return paths


def find_config_file() -> Optional[Path]:
    """Return the first config file that exists, or ``None``."""
    for path in config_search_paths():
        if path.is_file():
            return path
    return None


def load_config_file(path: Optional[Path] = None) -> Tuple[Dict[str, Any], Optional[Path]]:
    """Read and parse the config file. Returns ``({}, None)`` when there is none.

    A malformed file raises: silently falling back to defaults would leave the
    user believing a policy is enforced when it is not.
    """
    target = path or find_config_file()
    if target is None:
        return {}, None
    with open(target, "rb") as handle:
        data = tomllib.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{target}: expected a table at the top level")
    # Tolerate a wrapping [pii-redact] / [piiredact] table.
    for wrapper in ("pii-redact", "piiredact", "tool"):
        inner = data.get(wrapper)
        if isinstance(inner, dict):
            nested = inner.get("piiredact") if wrapper == "tool" else inner
            if isinstance(nested, dict):
                data = {**{k: v for k, v in data.items() if k != wrapper}, **nested}
    return data, target


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Settings:
    """Immutable snapshot of the effective configuration."""

    enabled: bool = True
    """``PII_REDACT_DISABLE=1`` turns the whole pipeline into a no-op."""

    block: bool = False
    """Block mode: refuse the operation instead of silently redacting it.

    Off by default — redacting is non-destructive and keeps the agent moving.
    """

    languages: Tuple[str, ...] = (DEFAULT_LANGUAGE,)
    """Active language packs, most important first."""

    profile: str = DEFAULT_PROFILE
    """``minimal``, ``balanced`` (default) or ``strict``."""

    types: FrozenSet[str] = field(
        default_factory=lambda: frozenset(PROFILES[DEFAULT_PROFILE])
    )
    """The entity types actually redacted, after profile + add/skip overrides."""

    db_path: Path = field(default_factory=lambda: default_data_dir() / "mapping.db")

    terms_path: Optional[Path] = None
    """Optional ``TYPE:value`` seed list of literals to always redact."""

    config_path: Optional[Path] = None
    """Which config file produced these settings (``None`` = defaults + env)."""

    use_ner: bool = False
    """Opt-in spaCy NER. Off by default: it costs 30-150 ms per document, and a
    cold model load costs seconds."""

    ner_model: str = ""
    """spaCy model. Empty means "derive it from the first language"."""

    ner_max_chars: int = 20_000
    """Skip NER above this size — the deterministic layers still run."""

    budget_ms: int = 300
    """Soft deadline for one redact call."""

    max_bytes: int = 4 * 1024 * 1024
    """Hard cap on scanned content. Beyond it the tail is dropped, never passed
    through — an oversized document must not become a leak."""

    cache_entries: int = 4096
    """Content-hash LRU size."""

    restore_bare_tokens: bool = True
    """Also restore ``EMAIL_0001`` when the model drops the brackets."""

    guard_tool_results: bool = True
    """Redact tool results (file reads, document extraction, shell output)."""

    guard_payload: bool = True
    """Last-mile pass over the provider request."""

    restore_tool_args: bool = True
    """Put real values back into local tool arguments."""

    egress_extra: FrozenSet[str] = frozenset()
    """Extra tool names to treat as third-party egress (never restored)."""

    local_extra: FrozenSet[str] = frozenset()
    """Tool names to force back to "local" despite matching an egress marker."""

    log_counts: bool = False
    """Log per-type hit counts (never values) at INFO."""

    def wants(self, entity_type: str) -> bool:
        return entity_type in self.types

    @property
    def effective_ner_model(self) -> str:
        """The model that will actually be loaded."""
        return self.ner_model or default_ner_model(self.languages)

    def describe(self) -> Dict[str, Any]:
        """A JSON-friendly summary — never includes any personal value."""
        return {
            "enabled": self.enabled,
            "languages": list(self.languages),
            "profile": self.profile,
            "types": sorted(self.types),
            "block": self.block,
            "ner": {
                "enabled": self.use_ner,
                "model": self.effective_ner_model,
                "max_chars": self.ner_max_chars,
            },
            "vault": {
                "path": str(self.db_path),
                "terms": str(self.terms_path) if self.terms_path else None,
            },
            "budget_ms": self.budget_ms,
            "max_bytes": self.max_bytes,
            "config_file": str(self.config_path) if self.config_path else None,
        }


def _resolve_type_set(
    profile: str,
    only: Iterable[str],
    add: Iterable[str],
    skip: Iterable[str],
) -> FrozenSet[str]:
    """Apply profile then the explicit include/exclude lists.

    Unknown names raise (via :func:`resolve_types`) rather than being ignored:
    a typo in ``skip_types`` that silently does nothing is a policy the user
    believes is in force but is not.
    """
    base = set(PROFILES.get(profile, PROFILES[DEFAULT_PROFILE]))
    explicit = resolve_types(only)
    if explicit:
        base = set(explicit)
    base.update(resolve_types(add))
    for entity_type in resolve_types(skip):
        base.discard(entity_type)
    return frozenset(base)


def load_settings(
    config: Optional[Dict[str, Any]] = None,
    config_path: Optional[Path] = None,
    use_env: bool = True,
) -> Settings:
    """Build :class:`Settings` from the config file and the environment.

    Read fresh on demand rather than cached at import time so tests — and a
    long-lived gateway whose env is updated between sessions — see changes
    without a restart.
    """
    if config is None:
        config, config_path = load_config_file(config_path)

    ner_section = config.get("ner") if isinstance(config.get("ner"), dict) else {}
    tools_section = config.get("tools") if isinstance(config.get("tools"), dict) else {}
    vault_section = config.get("vault") if isinstance(config.get("vault"), dict) else {}

    def pick(env_name: str, file_value: Any, fallback: Any) -> Any:
        if use_env:
            raw = _env(env_name)
            if raw:
                return raw
        return file_value if file_value not in (None, "", [], ()) else fallback

    def pick_bool(env_name: str, file_value: Any, fallback: bool) -> bool:
        if use_env:
            from_env = _env_bool(env_name)
            if from_env is not None:
                return from_env
        if isinstance(file_value, bool):
            return file_value
        return fallback

    def pick_int(env_name: str, file_value: Any, fallback: int) -> int:
        if use_env:
            from_env = _env_int(env_name)
            if from_env is not None:
                return from_env
        if isinstance(file_value, int) and not isinstance(file_value, bool):
            return file_value
        return fallback

    # -- language and detection scope ---------------------------------------
    languages_raw = (
        _split_list(_env("LANG")) if (use_env and _env("LANG")) else _as_list(config.get("language"))
    )
    languages = normalise_languages(languages_raw)

    profile = str(pick("PROFILE", config.get("profile"), DEFAULT_PROFILE)).lower()
    if profile not in PROFILES:
        raise ValueError(
            f"unknown profile {profile!r}. Available: {', '.join(sorted(PROFILES))}."
        )

    only = _split_list(_env("TYPES")) if (use_env and _env("TYPES")) else _as_list(config.get("types"))
    add = (
        _split_list(_env("ADD_TYPES"))
        if (use_env and _env("ADD_TYPES"))
        else _as_list(config.get("add_types"))
    )
    skip = (
        _split_list(_env("SKIP_TYPES"))
        if (use_env and _env("SKIP_TYPES"))
        else _as_list(config.get("skip_types"))
    )
    types = _resolve_type_set(profile, only, add, skip)

    # -- paths ---------------------------------------------------------------
    db_raw = pick("DB", vault_section.get("path"), "")
    db_path = Path(str(db_raw)).expanduser() if db_raw else default_data_dir() / "mapping.db"

    terms_raw = pick("TERMS", vault_section.get("terms"), "")
    terms_path = Path(str(terms_raw)).expanduser() if terms_raw else None

    # -- everything else -----------------------------------------------------
    disable = pick_bool("DISABLE", config.get("disable"), False)
    enabled_file = config.get("enabled")
    enabled = (not disable) if not isinstance(enabled_file, bool) else (enabled_file and not disable)

    return Settings(
        enabled=enabled,
        block=pick_bool("BLOCK", config.get("block"), False),
        languages=languages,
        profile=profile,
        types=types,
        db_path=db_path,
        terms_path=terms_path,
        config_path=config_path,
        use_ner=pick_bool("NER", ner_section.get("enabled"), False),
        ner_model=str(pick("NER_MODEL", ner_section.get("model"), "")),
        ner_max_chars=pick_int("NER_MAX_CHARS", ner_section.get("max_chars"), 20_000),
        budget_ms=pick_int("BUDGET_MS", config.get("budget_ms"), 300),
        max_bytes=pick_int("MAX_BYTES", config.get("max_bytes"), 4 * 1024 * 1024),
        cache_entries=pick_int("CACHE_ENTRIES", config.get("cache_entries"), 4096),
        restore_bare_tokens=pick_bool(
            "RESTORE_BARE_TOKENS", config.get("restore_bare_tokens"), True
        ),
        guard_tool_results=pick_bool(
            "GUARD_TOOL_RESULTS", config.get("guard_tool_results"), True
        ),
        guard_payload=pick_bool("GUARD_PAYLOAD", config.get("guard_payload"), True),
        restore_tool_args=pick_bool(
            "RESTORE_TOOL_ARGS", config.get("restore_tool_args"), True
        ),
        egress_extra=frozenset(
            _split_list(_env("EGRESS_TOOLS"))
            if (use_env and _env("EGRESS_TOOLS"))
            else _as_list(tools_section.get("egress"))
        ),
        local_extra=frozenset(
            _split_list(_env("LOCAL_TOOLS"))
            if (use_env and _env("LOCAL_TOOLS"))
            else _as_list(tools_section.get("local"))
        ),
        log_counts=pick_bool("LOG_COUNTS", config.get("log_counts"), False),
    )


def with_overrides(settings: Settings, **overrides: Any) -> Settings:
    """Return a copy of *settings* with fields replaced (used by hosts/tests)."""
    return replace(settings, **overrides)
