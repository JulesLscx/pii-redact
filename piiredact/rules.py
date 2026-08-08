"""Deterministic French PII rules — the primary detection layer.

Design constraints that shaped this file:

* **Deterministic first.** Regex is O(n), allocation-free on a miss, and gives
  the same answer on every machine. Statistical NER (``ner.py``) is an opt-in
  *addition*, never a prerequisite: the pipeline must stay correct and fast
  with spaCy absent.
* **Never end a pattern with** ``\\b``. ``\\b`` is a transition between a word
  and a non-word character, so a pattern whose last literal is itself a
  non-word character (``€``, ``°``, a closing quote) fails to match when the
  value is followed by punctuation — ``"1 234,56 €."`` silently escapes and the
  real amount reaches the model. ``(?!\\w)`` asserts "not followed by a word
  character" regardless of what came before, which is the property we actually
  want. :func:`audit_patterns` enforces this at test time.
* **Specific before generic.** IBAN/NIR/SIRET/CARD claim their text before the
  bare ``\\d{5}`` postal-code rule can nibble a fragment of it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, List, Pattern, Sequence, Tuple

from .types import ClaimSet, EntityType, Span

#: Emitted token shape. ``{4,}`` digits so a token can never be mistaken for a
#: 5-digit postal code at sequence 10000+ — and token spans are claimed before
#: any rule runs anyway (see :func:`token_spans`), which makes redaction
#: idempotent: ``redact(redact(x)) == redact(x)``.
TOKEN_RE: Pattern[str] = re.compile(r"\[([A-Z]+)_(\d{4,})\]")

#: Same token without the brackets — models occasionally strip them when the
#: token lands inside code or a Markdown table.
BARE_TOKEN_RE: Pattern[str] = re.compile(r"(?<![\w\[])([A-Z]{3,8})_(\d{4,})(?![\w\]])")

_MONTHS = (
    "janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|"
    "septembre|octobre|novembre|décembre|decembre"
)

_TITLES = r"(?:M\.|MM\.|Mme|Mmes|Mlle|Dr|Pr|Me|Monsieur|Madame|Mademoiselle|Maître|Maitre)"

# A capitalised French name particle chain: "Jean-Pierre", "de La Fontaine".
_NAME_WORD = r"[A-ZÀ-Ý][\w'’\-]{1,30}"
_NAME_CHAIN = rf"{_NAME_WORD}(?:\s+(?:de|du|des|le|la|van|von|d'|l')?\s*{_NAME_WORD}){{0,3}}"


@dataclass(frozen=True)
class Rule:
    """One deterministic detector.

    ``group`` selects which capture group becomes the redacted span, letting a
    rule use surrounding context as an anchor without swallowing it: the
    ``ACCOUNT`` rule matches ``"compte n° 123456789"`` but only redacts the
    digits, so the model still reads the word "compte" and keeps its bearings.
    """

    entity_type: str
    pattern: Pattern[str]
    group: int = 0

    def finditer(self, text: str) -> Iterator[Tuple[int, int, str]]:
        for match in self.pattern.finditer(text):
            start, end = match.span(self.group)
            if start < 0 or end <= start:
                continue
            yield start, end, match.group(self.group)


def _c(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


#: Ordered most-specific first. Earlier rules claim their text; later rules
#: cannot overlap a claimed region.
RULES: Sequence[Rule] = (
    # -- credential-bearing URLs (before EMAIL: userinfo contains an '@') ----
    # Only URLs with embedded credentials are redacted. Redacting every URL
    # would break the agent's ability to fetch documentation for no privacy
    # gain, so the rule is deliberately narrow.
    Rule(
        EntityType.URL,
        _c(r"(?<!\w)[a-z][a-z0-9+.\-]*://[^\s/@]+:[^\s/@]+@[^\s<>\"')]+(?!\w)", re.I),
    ),
    Rule(
        EntityType.EMAIL,
        _c(r"(?<![\w.\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?!\w)"),
    ),
    # -- banking identifiers -------------------------------------------------
    Rule(
        EntityType.IBAN,
        _c(
            r"(?<![A-Za-z0-9])(?:"
            r"FR\d{2}(?:[ ]?[A-Z0-9]{4}){5}[ ]?[A-Z0-9]{3}"
            r"|[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,6}(?:[ ]?[A-Z0-9]{1,4})?"
            r")(?!\w)"
        ),
    ),
    Rule(
        EntityType.CARD,
        _c(r"(?<!\d)(?:\d{4}[ \-]){3}\d{4}(?!\d)|(?<!\d)\d{16}(?!\d)"),
    ),
    Rule(
        EntityType.NIR,
        _c(
            r"(?<!\d)[12]\s?\d{2}\s?(?:0[1-9]|1[0-2])\s?(?:\d{2}|2[AB])\s?"
            r"\d{3}\s?\d{3}(?:\s?\d{2})?(?!\d)"
        ),
    ),
    # SIRET (14) before SIREN-like generics; the digit lookarounds keep it from
    # biting a fragment of a 16-digit card.
    Rule(
        EntityType.SIRET,
        _c(r"(?<!\d)\d{3}[ ]\d{3}[ ]\d{3}[ ]\d{5}(?!\d)|(?<!\d)\d{14}(?!\d)"),
    ),
    # French intra-community VAT number.
    Rule(
        EntityType.SIRET,
        _c(r"(?<!\w)FR[ ]?[0-9A-Z]{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}(?!\w)"),
    ),
    Rule(
        EntityType.ACCOUNT,
        _c(
            r"(?:compte|contrat|dossier|client|adh[ée]rent|assur[ée]|police)\s*"
            r"(?:bancaire\s*)?(?:n[°ºo]|num[ée]ro)?\s*:?\s*([A-Z0-9][A-Z0-9\-]{5,19})(?!\w)",
            re.I,
        ),
        group=1,
    ),
    # -- contact details -----------------------------------------------------
    Rule(
        EntityType.PHONE,
        _c(r"(?<![\d+])(?:\+33[ .\-]?|0)[1-9](?:[ .\-]?\d{2}){4}(?!\d)"),
    ),
    Rule(
        EntityType.PLATE,
        _c(r"(?<![A-Z0-9\-])[A-Z]{2}-\d{3}-[A-Z]{2}(?!\w)"),
    ),
    # -- postal address ------------------------------------------------------
    Rule(
        EntityType.ADDR,
        _c(
            r"(?<!\w)\d{1,4}(?:\s?(?:bis|ter|quater))?[,]?\s+"
            r"(?:rue|avenue|av\.|boulevard|bd|impasse|chemin|all[ée]e|place|"
            r"route|quai|square|lieu-dit|r[ée]sidence|voie|cours|passage)\s+"
            # Quotes are excluded so redacting a JSON-encoded tool result
            # can never swallow a closing quote and corrupt the envelope.
            r"[^\n,;\"\']{2,60}?(?=\s*(?:,|;|\n|$))",
            re.I,
        ),
    ),
    # -- people --------------------------------------------------------------
    # Title-anchored names are the deterministic substitute for NER on the hot
    # path. Only the name is redacted; the civility stays so the sentence keeps
    # its grammar.
    Rule(
        EntityType.PERSON,
        _c(rf"(?<!\w){_TITLES}\s+({_NAME_CHAIN})(?!\w)"),
        group=1,
    ),
    # Field-style records: "Nom : DUPONT", "Titulaire: Marie Curie".
    Rule(
        EntityType.PERSON,
        _c(
            r"(?<!\w)(?:nom(?:\s+et\s+pr[ée]nom)?|pr[ée]nom|titulaire|b[ée]n[ée]ficiaire|"
            r"destinataire|exp[ée]diteur|sign[ée]|[ée]metteur|locataire|patient|[ée]l[èe]ve)"
            rf"\s*:\s*({_NAME_CHAIN})(?!\w)",
            re.I,
        ),
        group=1,
    ),
    # -- organisations -------------------------------------------------------
    Rule(
        EntityType.ORG,
        _c(
            r"(?<!\w)(?:SARL|SASU|SAS|SA|EURL|EIRL|SCI|SNC|SCCV|GIE|SCOP|SCP|"
            r"banque|caisse|mutuelle|association|cabinet)\b"
            rf"\s+({_NAME_CHAIN})(?!\w)",
            re.I,
        ),
        group=1,
    ),
    # -- quasi-identifiers (strict profile only) -----------------------------
    Rule(
        EntityType.AMOUNT,
        _c(
            # French copy uses the no-break (U+00A0) and narrow no-break
            # (U+202F) space as a thousands separator, not just " ".
            r"(?<![\w,.])\d{1,3}(?:[ .  ]\d{3})*(?:[,.]\d{2})?\s?(?:€|EUR|euros?)(?!\w)"
            r"|€\s?\d{1,3}(?:[ .  ]\d{3})*(?:[,.]\d{2})?(?!\w)",
            re.I,
        ),
    ),
    Rule(
        EntityType.DATE,
        _c(
            rf"(?<!\d)\d{{1,2}}[/.\-]\d{{1,2}}[/.\-]\d{{2,4}}(?!\d)"
            rf"|(?<!\w)\d{{1,2}}(?:er)?\s+(?:{_MONTHS})\s+\d{{4}}(?!\d)",
            re.I,
        ),
    ),
    # -- last, and only on text nothing else claimed -------------------------
    Rule(EntityType.POSTAL, _c(r"(?<!\d)\d{5}(?!\d)")),
)


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


def rule_spans(text: str, wanted: frozenset, claimed: ClaimSet) -> List[Span]:
    """Run every enabled rule, skipping regions already claimed.

    ``claimed`` is updated as spans are accepted so that later (more generic)
    rules cannot overlap earlier (more specific) hits.
    """
    found: List[Span] = []
    for rule in RULES:
        if rule.entity_type not in wanted:
            continue
        for start, end, matched in rule.finditer(text):
            if claimed.overlaps(start, end):
                continue
            found.append(Span(start, end, rule.entity_type, matched, origin="rule"))
            claimed.add(start, end)
    return found


def audit_patterns() -> List[str]:
    """Return a list of rule descriptions violating the ``\\b``-tail ban.

    Kept in the shipped module rather than only in tests so a host can assert
    the invariant at load time if it wants to.
    """
    problems: List[str] = []
    for rule in RULES:
        source = rule.pattern.pattern
        for alternative in source.split("|"):
            stripped = alternative.rstrip()
            if stripped.endswith(r"\b"):
                problems.append(f"{rule.entity_type}: alternative ends with \\b: {alternative!r}")
    return problems
