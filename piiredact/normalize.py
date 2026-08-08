"""Value normalisation and hashing.

Two written forms of the same fact must collapse to one token, otherwise the
vault grows a new token per formatting variant and the model sees
``[PHONE_0007]`` and ``[PHONE_0031]`` for the same line. Normalisation happens
*before* hashing; the untouched original is what gets restored.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from functools import lru_cache

from .types import EntityType

#: Types whose value is a pure identifier — separators carry no meaning.
_STRIP_SEPARATORS = {
    EntityType.IBAN,
    EntityType.SIRET,
    EntityType.NIR,
    EntityType.CARD,
    EntityType.ACCOUNT,
    EntityType.PHONE,
    EntityType.POSTAL,
    EntityType.PLATE,
}

#: Types compared case-insensitively (and accent-insensitively for names).
_CASEFOLD = {
    EntityType.EMAIL,
    EntityType.PERSON,
    EntityType.ORG,
    EntityType.LOC,
    EntityType.ADDR,
    EntityType.URL,
}

_SEPARATORS_RE = re.compile(r"[ .\-_/ ]")
_WHITESPACE_RE = re.compile(r"\s+")


@lru_cache(maxsize=8192)
def strip_accents(value: str) -> str:
    """Fold accents so ``Amélie`` and ``Amelie`` hash to the same key.

    Memoised: a dense document calls this once per detected occurrence, and
    NFD decomposition over the same handful of distinct values was the single
    largest cost in the profile of a 200 KB scan.
    """
    decomposed = unicodedata.normalize("NFD", value)
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")


def normalize_value(entity_type: str, value: str) -> str:
    """Return the canonical key for *value* under *entity_type*."""
    normalized = _WHITESPACE_RE.sub(" ", value).strip()
    if entity_type == EntityType.PHONE:
        # +33 6 12 ... and 06 12 ... are the same subscriber.
        digits = _SEPARATORS_RE.sub("", normalized)
        if digits.startswith("+33"):
            digits = "0" + digits[3:]
        elif digits.startswith("0033"):
            digits = "0" + digits[4:]
        return digits
    if entity_type in _STRIP_SEPARATORS:
        return _SEPARATORS_RE.sub("", normalized).upper()
    if entity_type in _CASEFOLD:
        return strip_accents(normalized).casefold()
    return normalized


@lru_cache(maxsize=16384)
def hash_value(entity_type: str, value: str) -> str:
    """SHA-256 of ``type:normalized`` — the vault's dedup key.

    The hash, not the value, is what makes the mapping deterministic across
    processes and runs: the same real value always resolves to the same row,
    so the same token, so a byte-identical prompt prefix (which is what keeps
    the provider's prompt cache warm).
    """
    key = f"{entity_type}:{normalize_value(entity_type, value)}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def content_hash(text: str) -> str:
    """Cache key for an already-redacted chunk of text."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
