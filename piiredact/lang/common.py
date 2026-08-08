"""Language-neutral rules — always active, whatever ``language`` is set to.

An email address, an IBAN and a card number have the same shape in every
locale, so keeping them here means a new language pack starts with the hardest
identifiers already covered and only has to describe what is genuinely local:
name conventions, address forms, national id schemes, date and money notation.
"""

from __future__ import annotations

import re
from typing import Tuple

from ..rules import Priority, Rule, compile_pattern
from ..types import EntityType

LANG = "xx"

RULES: Tuple[Rule, ...] = (
    # Credential-bearing URLs, before EMAIL: the userinfo part contains an '@'.
    # Only URLs *with* credentials are redacted — redacting every URL would
    # break the agent's ability to fetch documentation for no privacy gain.
    Rule(
        EntityType.URL,
        compile_pattern(
            r"(?<!\w)[a-z][a-z0-9+.\-]*://[^\s/@]+:[^\s/@]+@[^\s<>\"')]+(?!\w)", re.I
        ),
        priority=Priority.CONTACT,
        lang=LANG,
    ),
    Rule(
        EntityType.EMAIL,
        compile_pattern(r"(?<![\w.\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?!\w)"),
        priority=Priority.CONTACT,
        lang=LANG,
    ),
    # IBAN: the country-specific French form first (it is the longest and most
    # common in this project's own corpus), then the generic ISO 13616 shape.
    Rule(
        EntityType.IBAN,
        compile_pattern(
            r"(?<![A-Za-z0-9])(?:"
            r"FR\d{2}(?:[ ]?[A-Z0-9]{4}){5}[ ]?[A-Z0-9]{3}"
            r"|[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,6}(?:[ ]?[A-Z0-9]{1,4})?"
            r")(?!\w)"
        ),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    # BIC/SWIFT (ISO 9362) — same shape worldwide, and next to an IBAN it is
    # what routes the account. Anchored on its label rather than matched on
    # shape alone: eight to eleven uppercase alphanumerics also describes a
    # great many ordinary constants a coding agent reads all day.
    Rule(
        EntityType.ACCOUNT,
        compile_pattern(
            r"(?<!\w)(?:BIC|SWIFT)(?:[ \-]?(?:BIC|code))?\s*:?\s*"
            r"((?-i:[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?))(?!\w)",
            re.I,
        ),
        group=1,
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.CARD,
        compile_pattern(r"(?<!\d)(?:\d{4}[ \-]){3}\d{4}(?!\d)|(?<!\d)\d{16}(?!\d)"),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    # IPv4. Not in the default profile: a coding agent reads version numbers
    # and localhost addresses all day, and masking those hurts more than it
    # helps. Enable with `add_types = ["ip"]` when you handle server logs.
    Rule(
        EntityType.IP,
        compile_pattern(
            r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?![\w.])"
        ),
        priority=Priority.QUASI,
        lang=LANG,
    ),
)
