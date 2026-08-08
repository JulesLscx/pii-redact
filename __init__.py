"""pii-redact — Hermes plugin entry point.

Deliberately three lines of logic: everything real lives in the host-agnostic
:mod:`piiredact` package next to this file, and :mod:`piiredact.adapters.hermes`
is the only module that knows what a Hermes hook is. Other hosts (Claude Code,
OpenCode, Codex) get their own adapter of the same size, so the detection and
restoration behaviour can never drift between them.

What the plugin does, in one sentence: real PII stays on this machine, the
model reasons over stable ``[TYPE_NNNN]`` tokens, and the values come back
before anything is written to disk, run as a command, or shown to the user.

Configuration is entirely environment-driven — see ``README.md``. The knobs
you are most likely to want:

``PII_REDACT_DISABLE=1``   turn the plugin off without uninstalling it
``PII_REDACT_PROFILE``     ``balanced`` (default) or ``strict``
``PII_REDACT_BLOCK=1``     refuse egress tool calls carrying personal data
``PII_REDACT_NER=1``       add the optional spaCy pass (slower, better recall)
``PII_REDACT_DB``          override the vault location
"""

from __future__ import annotations

try:
    # Normal path: Hermes loads this directory as a package, so the core is a
    # subpackage of it.
    from .piiredact.adapters.hermes import register
except ImportError:  # pragma: no cover - exercised by tooling, not by Hermes
    # Fallback for anything that loads this file as a loose module rather than
    # as a package member (test collectors, `python __init__.py`, editors).
    # Without it the relative import above raises and the tool reports a
    # spurious failure against a plugin that is in fact fine.
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from piiredact.adapters.hermes import register  # type: ignore[no-redef]

__all__ = ["register"]
