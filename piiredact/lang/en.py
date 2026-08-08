"""English pack (default) — US/UK/international conventions.

Covers: US SSN and EIN, UK NINO, US ZIP and UK postcode, North-American phone
numbers, street addresses, people anchored by title or by field label,
companies anchored by a legal suffix, dates and money.

Anything with the same shape everywhere (email, IBAN, card) lives in
:mod:`piiredact.lang.common`.
"""

from __future__ import annotations

import re
from typing import Tuple

from ..rules import Priority, Rule, compile_pattern
from ..types import EntityType

LANG = "en"

#: spaCy model used when the NER layer is enabled and no model is configured.
NER_MODEL = "en_core_web_sm"

_MONTHS = (
    "January|February|March|April|May|June|July|August|September|October|"
    "November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sept?|Oct|Nov|Dec"
)

_TITLES = r"(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Sir|Dame|Lord|Lady|Rev|Hon|Capt|Sgt)\.?"

# The leading capital is asserted with a scoped ``(?-i:...)`` because the rules
# that embed this chain are compiled with ``re.IGNORECASE`` for their anchor
# ("account holder", "ltd"). Without the scoped flag the capital stops being a
# constraint and the chain runs on through ordinary lowercase words.
_NAME_WORD = r"(?-i:[A-Z])[\w'’\-]{1,30}"
# ``[ \t]+`` rather than ``\s+``: a real name never spans a line break, but a
# field label on the following line ("Name: John Smith\nAddress: …") starts
# with a capital too and would otherwise be swallowed into the chain.
_NAME_CHAIN = rf"{_NAME_WORD}(?:[ \t]+(?:van|von|de|del|della|da|di|du|la|le|Mc|Mac)?[ \t]*{_NAME_WORD}){{0,3}}"

_STREET_TYPES = (
    r"Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|"
    r"Drive|Dr\.?|Court|Ct\.?|Place|Pl\.?|Terrace|Ter\.?|Way|Circle|Cir\.?|"
    r"Parkway|Pkwy\.?|Highway|Hwy\.?|Square|Sq\.?|Trail|Loop|Alley|Crescent"
)

_COMPANY_SUFFIX = (
    r"Inc|Incorporated|Ltd|Limited|LLC|LLP|LP|PLC|Corp|Corporation|Co|Company|"
    r"GmbH|AG|NV|BV|Pty|Holdings|Group|Partners|Associates"
)

RULES: Tuple[Rule, ...] = (
    # -- national and tax identifiers ---------------------------------------
    Rule(
        EntityType.NATIONAL_ID,
        # US SSN. The area/group/serial guards reject the reserved 000/666/9xx
        # ranges, which is what keeps ordinary "123-45-6789"-shaped reference
        # numbers from being swept up.
        compile_pattern(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)"),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.NATIONAL_ID,
        # UK National Insurance number.
        compile_pattern(
            r"(?<!\w)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?"
            r"\d{2}\s?\d{2}\s?\d{2}\s?[A-D]?(?!\w)"
        ),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.TAX_ID,
        # US Employer Identification Number.
        compile_pattern(r"(?<!\d)\d{2}-\d{7}(?!\d)"),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.ACCOUNT,
        compile_pattern(
            r"(?:account|acct|customer|client|policy|contract|member|patient|"
            r"invoice|reference|ref|case|file)\s*"
            r"(?:number|no|nr|#|id)?\s*[:.#]?\s*"
            # Same precaution as ``_NAME_WORD``: the rule is compiled with
            # ``re.IGNORECASE`` for its anchor, which would drop the case
            # constraint and let the group swallow the following word
            # ("customer complaint 4471" → "complaint"). The mandatory digit
            # also rejects all-caps labels.
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
        # North-American numbering plan, with or without +1 and punctuation.
        compile_pattern(
            r"(?<![\d+])(?:\+1[ .\-]?)?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}(?!\d)"
            r"|(?<![\d+])\+1\d{10}(?!\d)"
        ),
        priority=Priority.CONTACT,
        lang=LANG,
    ),
    Rule(
        EntityType.PHONE,
        # UK numbers in national (0…) or international (+44…) form.
        compile_pattern(r"(?<![\d+])(?:\+44\s?|0)(?:\d\s?){9,10}(?!\d)"),
        priority=Priority.CONTACT,
        lang=LANG,
    ),
    Rule(
        EntityType.PLATE,
        # UK current-style registration.
        compile_pattern(r"(?<![A-Z0-9\-])[A-Z]{2}\d{2}\s?[A-Z]{3}(?!\w)"),
        priority=Priority.CONTACT,
        lang=LANG,
    ),
    # -- addresses -----------------------------------------------------------
    Rule(
        EntityType.ADDR,
        compile_pattern(
            rf"(?<!\w)\d{{1,5}}[A-Za-z]?\s+(?:[A-Z][\w'’\-]*\.?\s+){{0,4}}"
            rf"(?:{_STREET_TYPES})"
            rf"(?:\s+(?:Apt|Apartment|Suite|Ste|Unit|Floor|Fl|#)\s*[\w\-]+)?(?!\w)"
        ),
        priority=Priority.ADDRESS,
        lang=LANG,
    ),
    Rule(
        EntityType.ADDR,
        # "P.O. Box 1234"
        compile_pattern(r"(?<!\w)P\.?\s?O\.?\s?Box\s+\d{1,7}(?!\w)", re.I),
        priority=Priority.ADDRESS,
        lang=LANG,
    ),
    # -- people --------------------------------------------------------------
    # Title-anchored names are the deterministic substitute for NER on the hot
    # path. Only the name is redacted; the honorific stays so the sentence
    # keeps its grammar.
    Rule(
        EntityType.PERSON,
        compile_pattern(rf"(?<!\w){_TITLES}\s+({_NAME_CHAIN})(?!\w)"),
        group=1,
        priority=Priority.NAME,
        lang=LANG,
    ),
    Rule(
        EntityType.PERSON,
        # Field-style records: "Name: John Smith", "Account holder — Jane Doe".
        compile_pattern(
            r"(?<!\w)(?:full\s+name|first\s+name|last\s+name|name|surname|"
            r"account\s+holder|policy\s+holder|cardholder|beneficiary|"
            r"recipient|sender|customer|client|patient|employee|student|"
            r"signed|attn|contact)\s*[:\-—]\s*"
            rf"({_NAME_CHAIN})(?!\w)",
            re.I,
        ),
        group=1,
        priority=Priority.NAME,
        lang=LANG,
    ),
    # -- organisations -------------------------------------------------------
    Rule(
        EntityType.ORG,
        # English puts the legal form *after* the name, unlike French.
        compile_pattern(rf"(?<!\w)({_NAME_CHAIN})\s+(?:{_COMPANY_SUFFIX})\.?(?!\w)"),
        group=1,
        priority=Priority.NAME,
        lang=LANG,
    ),
    # -- quasi-identifiers (strict profile only) -----------------------------
    Rule(
        EntityType.AMOUNT,
        compile_pattern(
            r"(?<![\w.,])[$£¥]\s?\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?(?!\w)"
            r"|(?<![\w.,])\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?\s?"
            r"(?:USD|GBP|EUR|CAD|AUD|dollars?|pounds?|cents?)(?!\w)",
            re.I,
        ),
        priority=Priority.QUASI,
        lang=LANG,
    ),
    Rule(
        EntityType.DATE,
        compile_pattern(
            r"(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)"                      # ISO 8601
            r"|(?<!\d)\d{1,2}/\d{1,2}/\d{2,4}(?!\d)"               # 03/12/2025
            rf"|(?<!\w)(?:{_MONTHS})\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}(?!\d)"
            rf"|(?<!\w)\d{{1,2}}(?:st|nd|rd|th)?\s+(?:{_MONTHS})\.?,?\s+\d{{4}}(?!\d)",
            re.I,
        ),
        priority=Priority.QUASI,
        lang=LANG,
    ),
    # -- last, and only on text nothing else claimed -------------------------
    Rule(
        EntityType.POSTAL,
        # UK postcode first (it is longer and unambiguous), then US ZIP/ZIP+4.
        compile_pattern(
            r"(?<![\w\-])[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}(?!\w)"
            # The ZIP guards mirror the postcode ones above: anchored on ``\d``
            # alone they bite the trailing digits of an alphanumeric identifier
            # ("13AA00002"), splitting the token in half.
            r"|(?<![\w\-])\d{5}(?:-\d{4})?(?![\w\-])"
        ),
        priority=Priority.GENERIC,
        lang=LANG,
    ),
)
