"""Literal gazetteer — deterministic recall for values the rules can't shape.

A regex can describe an IBAN. It cannot describe "Amélie" without also
describing every other capitalised word. The gazetteer closes that gap without
reaching for a model: **once a value has been tokenised even once, every later
occurrence of it is matched literally, everywhere, forever.**

That makes recall improve monotonically and deterministically:

* a name caught by the title rule (``Mme Amélie Roux``) is thereafter caught
  bare, mid-sentence, in a file the agent reads three days later;
* the user can seed values by hand (``piiredact vault add PERSON "Amélie"``)
  or via a terms file, which covers pseudonyms, code names and nicknames;
* an optional NER pass, when enabled, feeds the same store — so the expensive
  statistical layer only ever has to see a value *once*, and the cheap layer
  handles every subsequent occurrence.

Matching is a single compiled alternation (longest literal first), which the
``re`` engine runs as one linear scan.
"""

from __future__ import annotations

import re
import threading
from typing import Dict, FrozenSet, Iterable, List, Optional, Pattern, Sequence, Tuple

from .normalize import strip_accents
from .types import EntityType, Span

#: Types compared without case/accents. Identifiers are matched verbatim
#: (their normalised form is already covered by the rules).
_FOLDED_TYPES = frozenset(
    {EntityType.PERSON, EntityType.ORG, EntityType.LOC, EntityType.ADDR, EntityType.EMAIL}
)

#: Literals shorter than this are ignored — a 2-letter "value" would carpet the
#: text with false positives and destroy the model's ability to read anything.
MIN_LITERAL_LEN = 3

#: Upper bound on alternation size. Beyond this the pattern's compile time and
#: memory stop being worth it; the longest (most specific) literals are kept.
MAX_LITERALS = 5000


def _fold(value: str) -> str:
    return strip_accents(value).casefold()


class LiteralMatcher:
    """Compiled literal alternation over known values.

    Rebuilt lazily whenever the vault's generation counter moves, so a value
    learned during this turn is matched on the very next call.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pattern: Optional[Pattern[str]] = None
        self._lookup: Dict[str, str] = {}   # folded literal -> entity type
        self._built_for: Tuple[int, int] = (-1, -1)  # (generation, wanted hash)

    # -- construction --------------------------------------------------------

    def build(self, entries: Iterable[Tuple[str, str]], wanted: FrozenSet[str]) -> None:
        """Compile the alternation from ``(entity_type, value)`` pairs."""
        literals: List[Tuple[str, str]] = []
        seen: set = set()
        for entity_type, value in entries:
            if entity_type not in wanted:
                continue
            literal = value.strip()
            if len(literal) < MIN_LITERAL_LEN:
                continue
            key = _fold(literal) if entity_type in _FOLDED_TYPES else literal
            if key in seen:
                continue
            seen.add(key)
            literals.append((entity_type, literal))

        literals.sort(key=lambda pair: len(pair[1]), reverse=True)
        literals = literals[:MAX_LITERALS]

        lookup: Dict[str, str] = {}
        alternatives: List[str] = []
        for entity_type, literal in literals:
            folded = entity_type in _FOLDED_TYPES
            key = _fold(literal) if folded else literal
            lookup[key] = entity_type
            # Accents are folded on the *lookup* side only; the pattern itself
            # keeps the original characters and relies on re.IGNORECASE, so
            # "AMÉLIE" and "Amélie" both hit while "Amelie" is picked up by the
            # separate unaccented literal the vault stores for it, if any.
            alternatives.append(re.escape(literal))

        with self._lock:
            self._lookup = lookup
            if not alternatives:
                self._pattern = None
                return
            # (?<!\w) / (?!\w) rather than \b: a literal may legitimately start
            # or end with a non-word character (an address ends with a digit or
            # a dot), and \b would then refuse to anchor.
            self._pattern = re.compile(
                r"(?<!\w)(?:" + "|".join(alternatives) + r")(?!\w)",
                re.IGNORECASE,
            )

    def ensure_built(
        self,
        generation: int,
        wanted: FrozenSet[str],
        loader: "callable",
    ) -> None:
        """Rebuild if the vault or the active type set changed."""
        stamp = (generation, hash(wanted))
        if self._built_for == stamp:
            return
        self.build(loader(), wanted)
        self._built_for = stamp

    # -- matching ------------------------------------------------------------

    def spans(self, text: str, claimed: Sequence[Span]) -> List[Span]:
        """Return literal hits that do not intersect an already-claimed span."""
        pattern = self._pattern
        if pattern is None:
            return []
        found: List[Span] = []
        for match in pattern.finditer(text):
            matched = match.group(0)
            entity_type = (
                self._lookup.get(_fold(matched))
                or self._lookup.get(matched)
            )
            if entity_type is None:
                continue
            span = Span(match.start(), match.end(), entity_type, matched, origin="vault")
            if any(span.overlaps(other) for other in claimed):
                continue
            found.append(span)
        return found

    @property
    def size(self) -> int:
        return len(self._lookup)


def parse_terms_file(raw: str) -> List[Tuple[str, str]]:
    """Parse a ``TYPE:value`` terms file into ``(entity_type, value)`` pairs.

    Blank lines and ``#`` comments are ignored. A line without a recognised
    type prefix is treated as a ``PERSON`` — the common case when a user dumps
    a list of family first names into the file.
    """
    pairs: List[Tuple[str, str]] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entity_type, _, value = stripped.partition(":")
        entity_type = entity_type.strip().upper()
        value = value.strip()
        if not value:
            pairs.append((EntityType.PERSON, stripped))
            continue
        pairs.append((entity_type, value))
    return pairs
