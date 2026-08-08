"""Core value types shared by every layer of the redaction pipeline.

Deliberately dependency-free (stdlib only) so the same objects travel across
host integrations — Hermes plugin hooks, a Claude Code hook subprocess, an
OpenCode/Codex adapter, or a plain ``python -m piiredact`` pipe.

Entity-type names are **language-neutral**: a French NIR and a US SSN are both
``NATIONAL_ID``, a SIRET and an EIN are both ``TAX_ID``. Country-specific
spellings live in the language packs (:mod:`piiredact.lang`), which keeps the
token vocabulary stable when a user enables a second language.
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Tuple


class EntityType:
    """Canonical entity-type names.

    These strings are baked into the emitted tokens (``[EMAIL_0001]``) and into
    the vault's ``entity_type`` column, so they are part of the on-disk format:
    renaming one invalidates existing mappings.
    """

    PERSON = "PERSON"
    ORG = "ORG"
    LOC = "LOC"

    EMAIL = "EMAIL"
    PHONE = "PHONE"
    URL = "URL"           # only URLs carrying credentials
    IP = "IP"

    ADDR = "ADDR"         # street address
    POSTAL = "POSTAL"     # postal / ZIP code

    IBAN = "IBAN"
    CARD = "CARD"         # payment card number
    ACCOUNT = "ACCOUNT"   # bank / contract / customer account number

    NATIONAL_ID = "NATIONAL_ID"  # FR NIR, US SSN, UK NINO...
    TAX_ID = "TAX_ID"            # FR SIRET/SIREN/VAT, US EIN...
    PLATE = "PLATE"              # vehicle registration

    AMOUNT = "AMOUNT"
    DATE = "DATE"


#: Identifiers that point at exactly one person or account. Redacted in every
#: profile — masking these is the entire point of the plugin.
CORE_IDENTIFIERS: Tuple[str, ...] = (
    EntityType.EMAIL,
    EntityType.PHONE,
    EntityType.IBAN,
    EntityType.CARD,
    EntityType.ACCOUNT,
    EntityType.NATIONAL_ID,
    EntityType.TAX_ID,
    EntityType.URL,
)

#: Identifying in context: a name, an address, a plate. Redacted by default,
#: but a user working on public/company data may reasonably drop some.
CONTEXT_IDENTIFIERS: Tuple[str, ...] = (
    EntityType.PERSON,
    EntityType.ORG,
    EntityType.LOC,
    EntityType.ADDR,
    EntityType.POSTAL,
    EntityType.PLATE,
)

#: Quasi-identifiers: meaningless on their own once the identifiers are gone,
#: but expensive to lose because the model needs them to do arithmetic and
#: temporal reasoning. Redacted only in the ``strict`` profile.
QUASI_IDENTIFIERS: Tuple[str, ...] = (
    EntityType.AMOUNT,
    EntityType.DATE,
    EntityType.IP,
)

ALL_TYPES: Tuple[str, ...] = CORE_IDENTIFIERS + CONTEXT_IDENTIFIERS + QUASI_IDENTIFIERS

#: Named type sets, from least to most aggressive. ``balanced`` is the default:
#: see ``SPEC.md`` for why amounts and dates are not in it.
PROFILES: Dict[str, Tuple[str, ...]] = {
    "minimal": CORE_IDENTIFIERS,
    "balanced": CORE_IDENTIFIERS + CONTEXT_IDENTIFIERS,
    "strict": ALL_TYPES,
}

DEFAULT_PROFILE = "balanced"

#: User-facing spellings accepted in configuration. Nobody should have to
#: remember that a phone number is ``PHONE`` and not ``TEL`` — or that their
#: country's id scheme maps to ``NATIONAL_ID``. Matching is case-insensitive
#: and ignores ``-``/``_``/spaces.
TYPE_ALIASES: Dict[str, str] = {
    # person
    "name": EntityType.PERSON,
    "names": EntityType.PERSON,
    "nom": EntityType.PERSON,
    "fullname": EntityType.PERSON,
    "personname": EntityType.PERSON,
    "people": EntityType.PERSON,
    # organisation
    "company": EntityType.ORG,
    "companies": EntityType.ORG,
    "organisation": EntityType.ORG,
    "organization": EntityType.ORG,
    "entreprise": EntityType.ORG,
    "societe": EntityType.ORG,
    # location
    "location": EntityType.LOC,
    "city": EntityType.LOC,
    "place": EntityType.LOC,
    "ville": EntityType.LOC,
    "lieu": EntityType.LOC,
    # contact
    "mail": EntityType.EMAIL,
    "emailaddress": EntityType.EMAIL,
    "courriel": EntityType.EMAIL,
    "tel": EntityType.PHONE,
    "telephone": EntityType.PHONE,
    "phonenumber": EntityType.PHONE,
    "mobile": EntityType.PHONE,
    "portable": EntityType.PHONE,
    # address
    "address": EntityType.ADDR,
    "adresse": EntityType.ADDR,
    "street": EntityType.ADDR,
    "streetaddress": EntityType.ADDR,
    "zip": EntityType.POSTAL,
    "zipcode": EntityType.POSTAL,
    "postcode": EntityType.POSTAL,
    "postalcode": EntityType.POSTAL,
    "codepostal": EntityType.POSTAL,
    # banking
    "creditcard": EntityType.CARD,
    "card": EntityType.CARD,
    "carte": EntityType.CARD,
    "cb": EntityType.CARD,
    "bankaccount": EntityType.ACCOUNT,
    "compte": EntityType.ACCOUNT,
    "customerid": EntityType.ACCOUNT,
    # national / tax ids
    "ssn": EntityType.NATIONAL_ID,
    "socialsecurity": EntityType.NATIONAL_ID,
    "socialsecuritynumber": EntityType.NATIONAL_ID,
    "nir": EntityType.NATIONAL_ID,
    "secu": EntityType.NATIONAL_ID,
    "nino": EntityType.NATIONAL_ID,
    "nationalid": EntityType.NATIONAL_ID,
    "siret": EntityType.TAX_ID,
    "siren": EntityType.TAX_ID,
    "vat": EntityType.TAX_ID,
    "tva": EntityType.TAX_ID,
    "ein": EntityType.TAX_ID,
    "taxid": EntityType.TAX_ID,
    # misc
    "licenseplate": EntityType.PLATE,
    "immatriculation": EntityType.PLATE,
    "plaque": EntityType.PLATE,
    "money": EntityType.AMOUNT,
    "montant": EntityType.AMOUNT,
    "currency": EntityType.AMOUNT,
    "prices": EntityType.AMOUNT,
    "price": EntityType.AMOUNT,
    "dates": EntityType.DATE,
    "ipaddress": EntityType.IP,
    "ipv4": EntityType.IP,
    "url": EntityType.URL,
    "urls": EntityType.URL,
}


def _normalise_key(raw: str) -> str:
    return "".join(ch for ch in raw.lower() if ch.isalnum())


def resolve_type(raw: str) -> str:
    """Map a user-supplied type name to a canonical one.

    Raises ``ValueError`` with the accepted names listed, because a silently
    ignored typo in ``skip_types`` is a leak the user believes they configured
    away.
    """
    key = _normalise_key(raw)
    for canonical in ALL_TYPES:
        if _normalise_key(canonical) == key:
            return canonical
    alias = TYPE_ALIASES.get(key)
    if alias is not None:
        return alias
    raise ValueError(
        f"unknown entity type {raw!r}. Known types: {', '.join(ALL_TYPES)}. "
        f"Aliases such as name/address/mail/tel/zip are also accepted."
    )


def resolve_types(raw_values: Iterable[str]) -> Tuple[str, ...]:
    """Resolve a list of user-supplied type names, preserving order."""
    out: List[str] = []
    for raw in raw_values:
        canonical = resolve_type(raw)
        if canonical not in out:
            out.append(canonical)
    return tuple(out)


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


class ClaimSet:
    """Sorted interval index answering "is this range already taken?".

    Detectors run in priority order and each one must skip text an earlier
    detector claimed. Scanning a growing list linearly makes that check O(n²)
    in the number of hits — on a large document (tens of thousands of matches)
    the pass goes from milliseconds to minutes. Bisecting a sorted interval
    list makes it O(log n) per query, which keeps the cost linear overall and
    the latency budget meaningful on inputs of any size.
    """

    __slots__ = ("_starts", "_ends")

    def __init__(self) -> None:
        self._starts: List[int] = []
        self._ends: List[int] = []

    def __len__(self) -> int:
        return len(self._starts)

    def overlaps(self, start: int, end: int) -> bool:
        """True when ``[start, end)`` intersects any claimed interval."""
        index = bisect_left(self._starts, start)
        # The interval starting at or after `start` overlaps when it begins
        # before `end`.
        if index < len(self._starts) and self._starts[index] < end:
            return True
        # The interval starting before `start` overlaps when it ends after it.
        if index > 0 and self._ends[index - 1] > start:
            return True
        return False

    def add(self, start: int, end: int) -> None:
        index = bisect_left(self._starts, start)
        self._starts.insert(index, start)
        self._ends.insert(index, end)

    def add_span(self, span: "Span") -> None:
        self.add(span.start, span.end)

    def extend(self, spans: Sequence["Span"]) -> None:
        for span in spans:
            self.add(span.start, span.end)


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
