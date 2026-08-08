"""French pack.

Covers: NIR (social security), SIRET/SIREN and intra-EU VAT, context-anchored
account numbers, metropolitan phone numbers, postal addresses, postal codes,
license plates, title/field-anchored people names, legal-form-anchored
organizations, euro amounts, and dates.

Patterns with universal shape (email, IBAN, card) live in
:mod:`piiredact.lang.common`.
"""

from __future__ import annotations

import re
from typing import Tuple

from ..rules import Priority, Rule, compile_pattern
from ..types import EntityType

LANG = "fr"

#: spaCy model used when NER is enabled without an explicit model.
NER_MODEL = "fr_core_news_sm"

_MONTHS = (
    "janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|"
    "septembre|octobre|novembre|décembre|decembre"
)

_TITLES = r"(?:M\.|MM\.|Mme|Mmes|Mlle|Dr|Pr|Me|Monsieur|Madame|Mademoiselle|Maître|Maitre)"

# The initial uppercase is enforced with a local ``(?-i:...)``: rules embedding
# this fragment are compiled with ``re.IGNORECASE`` for their anchor
# ("banque", "titulaire"). Without the local flag, uppercase would stop being a
# constraint and the pattern would spill into ordinary lowercase words.
_NAME_WORD = r"(?-i:[A-ZÀ-Ý])[\w'’\-]{1,30}"
# ``[ \t]+`` rather than ``\s+``: a real name never spans a line break, but a
# field label on the following line ("Titulaire : Amélie Roux\nAdresse : …")
# starts with a capital too and would otherwise be swallowed into the chain.
_NAME_CHAIN = rf"{_NAME_WORD}(?:[ \t]+(?:de|du|des|le|la|van|von|d'|l')?[ \t]*{_NAME_WORD}){{0,3}}"

RULES: Tuple[Rule, ...] = (
    # -- national and tax identifiers ----------------------------------------
    Rule(
        EntityType.NATIONAL_ID,
        # NIR: sex, year, month, department (2A/2B for Corsica), commune,
        # order, then optional control key.
        compile_pattern(
            r"(?<!\d)[12]\s?\d{2}\s?(?:0[1-9]|1[0-2])\s?(?:\d{2}|2[AB])\s?"
            r"\d{3}\s?\d{3}(?:\s?\d{2})?(?!\d)"
        ),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.TAX_ID,
        # SIRET (14 digits, grouped or not). Numeric guards prevent matching a
        # fragment of a 16-digit card number.
        compile_pattern(r"(?<!\d)\d{3}[ ]\d{3}[ ]\d{3}[ ]\d{5}(?!\d)|(?<!\d)\d{14}(?!\d)"),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.TAX_ID,
        # French intra-EU VAT number.
        compile_pattern(r"(?<!\w)FR[ ]?[0-9A-Z]{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}(?!\w)"),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.NATIONAL_ID,
        # Driver's license number. The format changed multiple times (12 digits
        # before 2013, then 2 digits + 2 letters + 5 digits), so the rule is
        # anchored on the label; a pure-shape rule would capture many internal
        # administrative references.
        compile_pattern(
            r"(?<!\w)permis(?:\s+de\s+conduire)?\s*(?:n[°ºo]|num[ée]ro)?\s*:?\s*"
            r"((?-i:(?=[A-Z0-9]*\d)[A-Z0-9]{8,15}))(?!\w)",
            re.I,
        ),
        group=1,
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.ACCOUNT,
        compile_pattern(
            r"(?:compte|contrat|dossier|client|adh[ée]rent|assur[ée]|police|"
            r"facture|r[ée]f[ée]rence|r[ée]f)\s*"
            r"(?:bancaire\s*)?"
            # A qualifier can appear in between ("dossier sinistre n° …").
            # Harmless since the capture group now requires uppercase and at
            # least one digit, so ordinary words cannot pass.
            r"(?:(?-i:[a-zà-ÿ]{2,15})\s+)?"
            r"(?:n[°ºo]|num[ée]ro)?\s*:?\s*"
            # Same precaution as ``_NAME_WORD``: this rule is compiled with
            # ``re.IGNORECASE`` for its anchor, which would otherwise drop the
            # case constraint and let the group swallow the next word
            # ("dossier sinistre n° …" -> "sinistre"). The mandatory digit also
            # excludes all-uppercase labels.
            r"((?-i:(?=[A-Z0-9\-]*\d)[A-Z0-9][A-Z0-9\-]{5,19}))(?!\w)",
            re.I,
        ),
        group=1,
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    # -- contact -------------------------------------------------------------
    Rule(
        EntityType.PHONE,
        compile_pattern(r"(?<![\d+])(?:\+33[ .\-]?|0)[1-9](?:[ .\-]?\d{2}){4}(?!\d)"),
        priority=Priority.CONTACT,
        lang=LANG,
    ),
    Rule(
        EntityType.PLATE,
        compile_pattern(r"(?<![A-Z0-9\-])[A-Z]{2}-\d{3}-[A-Z]{2}(?!\w)"),
        priority=Priority.CONTACT,
        lang=LANG,
    ),
    # -- postal address -------------------------------------------------------
    Rule(
        EntityType.ADDR,
        compile_pattern(
            r"(?<!\w)\d{1,4}(?:\s?(?:bis|ter|quater))?[,]?\s+"
            r"(?:rue|avenue|av\.|boulevard|bd|impasse|chemin|all[ée]e|place|"
            r"route|quai|square|lieu-dit|r[ée]sidence|voie|cours|passage)\s+"
            # Quotes are excluded so redaction inside a JSON-encoded tool output
            # can never swallow a closing quote and corrupt the envelope.
            r"[^\n,;\"']{2,60}?(?=\s*(?:,|;|\n|$))",
            re.I,
        ),
        priority=Priority.ADDRESS,
        lang=LANG,
    ),
    # -- persons --------------------------------------------------------------
    Rule(
        EntityType.PERSON,
        compile_pattern(rf"(?<!\w){_TITLES}\s+({_NAME_CHAIN})(?!\w)"),
        group=1,
        priority=Priority.NAME,
        lang=LANG,
    ),
    Rule(
        EntityType.PERSON,
        compile_pattern(
            r"(?<!\w)(?:nom(?:\s+et\s+pr[ée]nom)?|pr[ée]nom|titulaire|"
            r"b[ée]n[ée]ficiaire|destinataire|exp[ée]diteur|sign[ée]|"
            r"[ée]metteur|locataire|patient|[ée]l[èe]ve|contact)"
            rf"\s*[:\-—]\s*({_NAME_CHAIN})(?!\w)",
            re.I,
        ),
        group=1,
        priority=Priority.NAME,
        lang=LANG,
    ),
    # -- organizations --------------------------------------------------------
    Rule(
        EntityType.ORG,
        # In French, the legal form precedes the name, unlike English.
        compile_pattern(
            r"(?<!\w)(?:SARL|SASU|SAS|SA|EURL|EIRL|SCI|SNC|SCCV|GIE|SCOP|SCP|"
            r"banque|caisse|mutuelle|association|cabinet)\b"
            rf"\s+({_NAME_CHAIN})(?!\w)",
            re.I,
        ),
        group=1,
        priority=Priority.NAME,
        lang=LANG,
    ),
    # -- quasi-identifiers (strict profile only) ------------------------------
    Rule(
        EntityType.AMOUNT,
        compile_pattern(
            # French uses non-breaking spaces (U+00A0) and narrow non-breaking
            # spaces (U+202F) as thousands separators.
            r"(?<![\w,.])\d{1,3}(?:[ .  ]\d{3})*(?:[,.]\d{2})?\s?(?:€|EUR|euros?)(?!\w)"
            r"|€\s?\d{1,3}(?:[ .  ]\d{3})*(?:[,.]\d{2})?(?!\w)",
            re.I,
        ),
        priority=Priority.QUASI,
        lang=LANG,
    ),
    Rule(
        EntityType.DATE,
        compile_pattern(
            r"(?<!\d)\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}(?!\d)"
            rf"|(?<!\w)\d{{1,2}}(?:er)?\s+(?:{_MONTHS})\s+\d{{4}}(?!\d)",
            re.I,
        ),
        priority=Priority.QUASI,
        lang=LANG,
    ),
    # -- last, on text untouched by other rules -------------------------------
    Rule(
        EntityType.POSTAL,
        # Guards use ``[\w-]`` and not only ``\d``: without them, the last five
        # digits of an alphanumeric identifier ("13AA00002", "2024-DA-88213")
        # could be read as a postal code, splitting the token and making it
        # unreadable for the model.
        compile_pattern(r"(?<![\w-])\d{5}(?![\w-])"),
        priority=Priority.GENERIC,
        lang=LANG,
    ),
)
