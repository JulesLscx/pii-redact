"""Core value types shared by every layer of the redaction pipeline.

Deliberately dependency-free (stdlib only) so the same objects travel across
host integrations — Hermes plugin hooks, a Claude Code hook subprocess, an
OpenCode/Codex adapter, or a plain ``python -m piiredact`` pipe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple


class EntityType:
    """Canonical entity-type names.

    These strings are baked into the emitted tokens (``[EMAIL_0001]``) and
    into the vault's ``entity_type`` column, so they are part of the on-disk
    format: renaming one invalidates existing mappings.
    """

    EMAIL = "EMAIL"
    IBAN = "IBAN"
    NIR = "NIR"          # French social-security number
    SIRET = "SIRET"      # French company establishment id
    CARD = "CARD"        # payment card number
    PHONE = "PHONE"
    ACCOUNT = "ACCOUNT"  # bank account number introduced by "compte n° ..."
    ADDR = "ADDR"        # street address
    POSTAL = "POSTAL"    # 5-digit French postal code
    PERSON = "PERSON"
    ORG = "ORG"
    LOC = "LOC"
    PLATE = "PLATE"      # vehicle registration
    URL = "URL"          # URL carrying credentials or a personal path
    AMOUNT = "AMOUNT"
    DATE = "DATE"


#: Types that directly identify a person or an account. Always redacted.
DIRECT_IDENTIFIERS: Tuple[str, ...] = (
    EntityType.EMAIL,
    EntityType.IBAN,
    EntityType.NIR,
    EntityType.SIRET,
    EntityType.CARD,
    EntityType.PHONE,
    EntityType.ACCOUNT,
    EntityType.ADDR,
    EntityType.POSTAL,
    EntityType.PERSON,
    EntityType.ORG,
    EntityType.LOC,
    EntityType.PLATE,
    EntityType.URL,
)

#: Quasi-identifiers: meaningless on their own once the direct identifiers are
#: gone, but expensive to lose because the model needs them to do arithmetic
#: and temporal reasoning. Redacted only in the ``strict`` profile.
QUASI_IDENTIFIERS: Tuple[str, ...] = (
    EntityType.AMOUNT,
    EntityType.DATE,
)

ALL_TYPES: Tuple[str, ...] = DIRECT_IDENTIFIERS + QUASI_IDENTIFIERS


@dataclass(frozen=True)
class Span:
    """A half-open ``[start, end)`` character range detected as PII.

    ``origin`` records which detector claimed the span (``rule``, ``vault``,
    ``terms``, ``ner``) and is used by diagnostics and tests; it never
    influences the token that gets emitted.
    """

    start: int
    end: int
    entity_type: str
    text: str
    origin: str = "rule"

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end


@dataclass
class RedactionResult:
    """Outcome of one :meth:`Redactor.redact` call."""

    text: str
    """The redacted text, safe to hand to a remote model."""

    spans: List[Span] = field(default_factory=list)
    """Detected spans, in document order."""

    tokens: Dict[str, str] = field(default_factory=dict)
    """``token -> original value`` for this call only (never persisted here)."""

    truncated: bool = False
    """True when the fail-closed size/deadline guard replaced the tail."""

    elapsed_ms: float = 0.0
    """Wall-clock cost of the call, for budget assertions and telemetry."""

    cached: bool = False
    """True when the result came from the content-hash cache."""

    @property
    def changed(self) -> bool:
        return bool(self.spans) or self.truncated

    def counts(self) -> Dict[str, int]:
        """Return ``{entity_type: n}`` — safe to log (no values)."""
        out: Dict[str, int] = {}
        for span in self.spans:
            out[span.entity_type] = out.get(span.entity_type, 0) + 1
        return out


def resolve_overlaps(spans: Sequence[Span]) -> List[Span]:
    """Return non-overlapping spans, earliest-then-longest wins.

    Detectors are run most-specific first and each one already skips claimed
    regions, but the vault/terms matchers and the optional NER can still
    propose spans that straddle a rule hit. Sorting by ``(start, -length)``
    and dropping anything that intersects an already-accepted span gives a
    stable, deterministic resolution independent of detector ordering.
    """
    ordered = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    accepted: List[Span] = []
    last_end = -1
    for span in ordered:
        if span.start < last_end:
            continue
        accepted.append(span)
        last_end = span.end
    return accepted
