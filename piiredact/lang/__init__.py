"""Language pack registry.

A pack is a plain module exposing ``LANG``, ``RULES`` and (optionally)
``NER_MODEL``. Adding a language is therefore a single self-contained file with
no wiring elsewhere — see ``CONTRIBUTING.md``.

Several packs can be active at once (``language = ["en", "fr"]``): their rules
are concatenated and re-sorted by priority, so "most specific first" holds
*across* languages and not merely within one. The first language listed wins
ties, and also decides the default NER model.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..rules import Rule, order_rules

#: Packs shipped with the project. Keep ``fr`` first: it is the default — this
#: plugin's primary user and its whole leak corpus are French.
BUILTIN_LANGUAGES: Tuple[str, ...] = ("fr", "en")

DEFAULT_LANGUAGE = "fr"

_CACHE: Dict[str, ModuleType] = {}


def available() -> Tuple[str, ...]:
    """Return the language codes that can be enabled."""
    return BUILTIN_LANGUAGES


def load_pack(code: str) -> ModuleType:
    """Import one language pack, or raise ``ValueError`` naming the valid ones."""
    normalised = (code or "").strip().lower().replace("-", "_")
    # Accept locale-ish spellings ("en_US", "fr-FR") — only the language
    # subtag selects a pack.
    normalised = normalised.split("_", 1)[0]
    if normalised not in BUILTIN_LANGUAGES:
        raise ValueError(
            f"unknown language {code!r}. Available: {', '.join(BUILTIN_LANGUAGES)}."
        )
    cached = _CACHE.get(normalised)
    if cached is None:
        cached = import_module(f"{__name__}.{normalised}")
        _CACHE[normalised] = cached
    return cached


def normalise_languages(codes: Optional[Iterable[str]]) -> Tuple[str, ...]:
    """Validate and de-duplicate a language list, preserving order."""
    if not codes:
        return (DEFAULT_LANGUAGE,)
    out: List[str] = []
    for code in codes:
        pack = load_pack(code)
        if pack.LANG not in out:
            out.append(pack.LANG)
    return tuple(out) or (DEFAULT_LANGUAGE,)


def build_rules(codes: Sequence[str]) -> Tuple[Rule, ...]:
    """Compose the active rule set: neutral pack + every selected language."""
    from . import common

    rules: List[Rule] = list(common.RULES)
    for code in normalise_languages(codes):
        rules.extend(load_pack(code).RULES)
    return order_rules(rules)


def default_ner_model(codes: Sequence[str]) -> str:
    """Return the spaCy model matching the first language that declares one."""
    for code in normalise_languages(codes):
        model = getattr(load_pack(code), "NER_MODEL", "")
        if model:
            return str(model)
    return "xx_ent_wiki_sm"


def describe() -> Dict[str, Dict[str, object]]:
    """Summarise every pack — used by ``piiredact languages``."""
    out: Dict[str, Dict[str, object]] = {}
    for code in BUILTIN_LANGUAGES:
        pack = load_pack(code)
        types = sorted({rule.entity_type for rule in pack.RULES})
        out[code] = {
            "rules": len(pack.RULES),
            "types": types,
            "ner_model": getattr(pack, "NER_MODEL", ""),
        }
    return out
