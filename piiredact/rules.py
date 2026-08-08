"""Rule engine — the primary, deterministic detection layer.

The rules themselves live in :mod:`piiredact.lang` (one pack per language plus
a language-neutral pack); this module holds only the machinery that runs them.

Design constraints that shaped the engine:

* **Deterministic first.** Regex is O(n), allocation-free on a miss, and gives
  the same answer on every machine. Statistical NER (:mod:`piiredact.ner`) is
  an opt-in *addition*, never a prerequisite: the pipeline must stay correct
  and fast with spaCy absent.
* **Never end a pattern with** ``\\b``. ``\\b`` is a transition between a word
  and a non-word character, so a pattern whose last literal is itself a
  non-word character (``€``, ``°``, a closing quote) fails to match when the
  value is followed by punctuation — ``"1 234,56 €."`` silently escapes and the
  real amount reaches the model. ``(?!\\w)`` asserts "not followed by a word
  character" regardless of what came before, which is the property we actually
  want. :func:`audit_patterns` enforces this at test time.
* **Specific before generic.** Rules carry a :attr:`Rule.priority` and the
  composed pack is sorted by it, so a bare "five digits" postal-code rule can
  never nibble a fragment of an IBAN — including when two language packs are
  enabled at once and their rules interleave.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, List, Pattern, Sequence, Tuple

from .types import ClaimSet, Span

#: Emitted token shape. ``{4,}`` digits so a token can never be mistaken for a
#: 5-digit postal code at sequence 10000+ — and token spans are claimed before
#: any rule runs anyway (see :func:`token_spans`), which makes redaction
#: idempotent: ``redact(redact(x)) == redact(x)``.
TOKEN_RE: Pattern[str] = re.compile(r"\[([A-Z][A-Z_]*)_(\d{4,})\]")

#: Same token without the brackets — models occasionally strip them when the
#: token lands inside code or a Markdown table.
BARE_TOKEN_RE: Pattern[str] = re.compile(r"(?<![\w\[])([A-Z][A-Z_]{2,15})_(\d{4,})(?![\w\]])")


class Priority:
    """Ordering bands for rules. Lower runs first and claims its text first."""

    STRUCTURED = 10   # IBAN, card, national id, tax id — unambiguous shapes
    CONTACT = 20      # email, phone, credential-bearing URL, plate
    ADDRESS = 30      # street addresses (must beat the postal-code rule)
    NAME = 40         # people and organisations, anchored by title or field
    QUASI = 70        # amounts, dates, IP addresses
    GENERIC = 90      # bare postal / ZIP codes — last, always


@dataclass(frozen=True)
class Rule:
    """One deterministic detector.

    ``group`` selects which capture group becomes the redacted span, letting a
    rule use surrounding context as an anchor without swallowing it: the
    ``ACCOUNT`` rule matches ``"account no. 123456789"`` but only redacts the
    digits, so the model still reads the word "account" and keeps its bearings.
    """

    entity_type: str
    pattern: Pattern[str]
    group: int = 0
    priority: int = Priority.NAME
    #: Language code this rule came from — surfaced by ``piiredact doctor``.
    lang: str = "xx"

    def finditer(self, text: str) -> Iterator[Tuple[int, int, str]]:
        for match in self.pattern.finditer(text):
            start, end = match.span(self.group)
            if start < 0 or end <= start:
                continue
            yield start, end, match.group(self.group)


def compile_pattern(pattern: str, flags: int = 0) -> Pattern[str]:
    """Shorthand used by the language packs."""
    return re.compile(pattern, flags)


def order_rules(rules: Sequence[Rule]) -> Tuple[Rule, ...]:
    """Sort a composed rule set by priority, stably.

    Stability matters: within one band the pack's own ordering is meaningful (a
    country-specific phone shape should be tried before a looser one), and when
    two languages are active the first-listed one keeps precedence.
    """
    return tuple(sorted(rules, key=lambda rule: rule.priority))


def token_spans(text: str) -> ClaimSet:
    """Return a claim set covering tokens already present in *text*.

    Claiming these before any rule runs is what makes the whole pipeline
    idempotent and safe to run at several layers of the same request (a tool
    result is redacted once on its way out of the tool, then the provider
    payload containing it is scanned again before the wire).
    """
    claimed = ClaimSet()
    for match in TOKEN_RE.finditer(text):
        claimed.add(match.start(), match.end())
    return claimed


def rule_spans(
    text: str,
    wanted: frozenset,
    claimed: ClaimSet,
    rules: Sequence[Rule],
) -> List[Span]:
    """Run every enabled rule, skipping regions already claimed.

    ``claimed`` is updated as spans are accepted so that later (more generic)
    rules cannot overlap earlier (more specific) hits.
    """
    found: List[Span] = []
    for rule in rules:
        if rule.entity_type not in wanted:
            continue
        for start, end, matched in rule.finditer(text):
            if claimed.overlaps(start, end):
                continue
            found.append(Span(start, end, rule.entity_type, matched, origin="rule"))
            claimed.add(start, end)
    return found


def audit_patterns(rules: Sequence[Rule]) -> List[str]:
    """Return descriptions of rules violating the ``\\b``-tail ban.

    Kept in the shipped module rather than only in tests so a host — or a
    contributor adding a language pack — can assert the invariant directly.
    """
    problems: List[str] = []
    for rule in rules:
        source = rule.pattern.pattern
        for alternative in source.split("|"):
            stripped = alternative.rstrip()
            if stripped.endswith(r"\b"):
                problems.append(
                    f"{rule.lang}/{rule.entity_type}: alternative ends with "
                    f"\\b: {alternative!r}"
                )
    return problems
