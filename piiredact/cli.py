"""``python -m piiredact`` — the host-independent entry point.

Any tool that can run a subprocess can use the engine through this CLI, which
makes it the lowest-common-denominator integration path when no native adapter
exists yet:

    cat invoice.txt | python -m piiredact redact
    python -m piiredact restore < answer.txt
    python -m piiredact config init          # write a documented config.toml
    python -m piiredact vault add PERSON "Amelia"
    python -m piiredact serve                # persistent JSON-lines server

``serve`` exists because per-event subprocess spawning costs ~80-120 ms of
interpreter startup, which would eat a third of the latency budget before any
work happens. Hosts that fire many events should keep one server warm and talk
to it over a pipe.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, get_redactor, reset_redactor
from .config import (
    CONFIG_FILENAME,
    Settings,
    config_search_paths,
    default_data_dir,
    find_config_file,
    load_settings,
)
from .lang import available, describe
from .rules import audit_patterns
from .types import ALL_TYPES, PROFILES, TYPE_ALIASES

CONFIG_TEMPLATE = '''# piiredact configuration.
#
# Every setting here can be overridden by an environment variable named
# PII_REDACT_<SETTING> (see README). Precedence: environment > this file >
# built-in defaults.

# Which language packs to run. The first one also decides the default spaCy
# model. Available: {languages}.
language = ["en"]

# How much to mask.
#   "minimal"  — only hard identifiers (email, phone, IBAN, card, national id,
#                tax id, account, credential URLs)
#   "balanced" — the above plus names, organisations, places, addresses,
#                postal codes and plates. Amounts and dates stay readable so
#                the model can still add up and reason about deadlines.
#   "strict"   — everything, including amounts, dates and IP addresses.
profile = "balanced"

# Fine-tune the profile. Friendly names are accepted: name, address, mail, tel,
# zip, company, city, ssn, vat, card, money, dates, ip...
# Full list: {types}
add_types = []
skip_types = []

# Setting `types` explicitly replaces the profile entirely.
# types = ["name", "address", "mail", "tel"]

# Refuse tool calls that would send personal data to a third party, instead of
# letting them run on tokens.
block = false

# Per-call latency budget, in milliseconds. The deterministic layers always
# run; the optional ones are skipped once the budget is spent.
budget_ms = 300

[ner]
# Statistical named-entity recognition. Off by default: it needs a spaCy model,
# costs 30-150 ms per document, and the deterministic layers do not depend on
# it. Turning it on improves recall on bare names the rules cannot anchor.
enabled = false
# Empty means "derive from the first language" (en -> en_core_web_sm,
# fr -> fr_core_news_sm).
model = ""
max_chars = 20000

[vault]
# Where the token -> value mapping lives. Empty means the default location.
path = ""
# Optional file of extra values to always mask, one "TYPE: value" per line.
terms = ""

[tools]
# Extra tool names to treat as third-party egress (never given real values).
egress = []
# Tool names to force back to "local" despite matching an egress marker.
local = []
'''


def _read_input(path: Optional[str]) -> str:
    if path in (None, "-"):
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _apply_cli_overrides(args: argparse.Namespace) -> None:
    """Let ``--lang`` / ``--profile`` override the resolved settings.

    Rebuilding the singleton (rather than mutating it) keeps the rule set, the
    NER backend and the caches consistent with the settings that produced them.
    """
    lang = getattr(args, "lang", None)
    profile = getattr(args, "profile", None)
    if not lang and not profile:
        return
    base = get_redactor().settings
    overrides = {}
    if lang:
        overrides["languages"] = tuple(part.strip() for part in lang.split(",") if part.strip())
    if profile:
        overrides["profile"] = profile
        overrides["types"] = frozenset(PROFILES[profile])
    reset_redactor()
    from .redactor import Redactor

    import piiredact

    piiredact._redactor = Redactor(dataclasses.replace(base, **overrides))


def _cmd_redact(args: argparse.Namespace) -> int:
    _apply_cli_overrides(args)
    result = get_redactor().redact(_read_input(args.file))
    if args.json:
        json.dump(
            {
                "text": result.text,
                "counts": result.counts(),
                "elapsed_ms": round(result.elapsed_ms, 3),
                "truncated": result.truncated,
            },
            sys.stdout,
            ensure_ascii=False,
        )
        sys.stdout.write("\n")
    else:
        sys.stdout.write(result.text)
    if args.stats:
        print(
            f"[pii-redact] {len(result.spans)} span(s) in {result.elapsed_ms:.1f} ms "
            f"{result.counts()}",
            file=sys.stderr,
        )
    return 0


def _cmd_restore(args: argparse.Namespace) -> int:
    sys.stdout.write(get_redactor().restore(_read_input(args.file)))
    return 0


def _cmd_vault(args: argparse.Namespace) -> int:
    red = get_redactor()
    if args.action == "count":
        print(json.dumps(red.vault.counts_by_type(), ensure_ascii=False, indent=2))
        return 0
    if args.action == "list":
        for entity_type, value, token in red.vault.entries():
            shown = value if args.reveal else _mask(value)
            print(f"{token}\t{entity_type}\t{shown}")
        return 0
    if args.action == "add":
        if not args.value or not args.type:
            print("usage: piiredact vault add TYPE VALUE", file=sys.stderr)
            return 2
        from .types import resolve_type

        try:
            entity_type = resolve_type(args.type)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(red.learn(entity_type, args.value))
        return 0
    if args.action == "forget":
        if not args.value:
            print("usage: piiredact vault forget '[TYPE_0001]'", file=sys.stderr)
            return 2
        print("removed" if red.vault.forget(args.value) else "not found")
        return 0
    return 2


def _mask(value: str) -> str:
    """Show enough to identify a row without printing the value in full."""
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def _cmd_config(args: argparse.Namespace) -> int:
    if args.action == "path":
        found = find_config_file()
        print(json.dumps(
            {
                "active": str(found) if found else None,
                "searched": [str(p) for p in config_search_paths()],
            },
            indent=2,
        ))
        return 0

    if args.action == "show":
        print(json.dumps(get_redactor().settings.describe(), indent=2, ensure_ascii=False))
        return 0

    if args.action == "init":
        target = (
            Path(args.output).expanduser()
            if args.output
            else default_data_dir() / CONFIG_FILENAME
        )
        if target.exists() and not args.force:
            print(f"{target} already exists (use --force to overwrite)", file=sys.stderr)
            return 1
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            CONFIG_TEMPLATE.format(
                languages=", ".join(available()),
                types=", ".join(t.lower() for t in ALL_TYPES),
            ),
            encoding="utf-8",
        )
        print(target)
        return 0
    return 2


def _cmd_languages(args: argparse.Namespace) -> int:
    print(json.dumps(describe(), indent=2))
    return 0


def _cmd_types(args: argparse.Namespace) -> int:
    """List the maskable types, the profiles, and the accepted aliases."""
    aliases: dict = {}
    for alias, canonical in TYPE_ALIASES.items():
        aliases.setdefault(canonical, []).append(alias)
    print(json.dumps(
        {
            "types": {t: sorted(aliases.get(t, [])) for t in ALL_TYPES},
            "profiles": {name: list(members) for name, members in PROFILES.items()},
        },
        indent=2,
    ))
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Report configuration and invariants — the "is it really on?" command."""
    red = get_redactor()
    problems = audit_patterns(red.rules)
    report = dict(red.settings.describe())
    report.update(
        {
            "version": __version__,
            "rules": len(red.rules),
            "rules_by_language": _rules_by_language(red.rules),
            "vault_exists": red.settings.db_path.exists(),
            "mappings": red.vault.count(),
            "ner_available": red.ner.available if red.settings.use_ner else None,
            "pattern_audit": problems or "ok",
        }
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if problems else 0


def _rules_by_language(rules) -> dict:
    counts: dict = {}
    for rule in rules:
        counts[rule.lang] = counts.get(rule.lang, 0) + 1
    return counts


def _cmd_bench(args: argparse.Namespace) -> int:
    """Measure the per-call cost against the latency budget."""
    _apply_cli_overrides(args)
    red = get_redactor()
    sample = _read_input(args.file) if args.file else _SAMPLE * args.repeat
    red.redact(sample)  # warm the vault/gazetteer
    timings: List[float] = []
    for index in range(args.runs):
        # Vary the text so the content-hash cache does not answer for us; the
        # number we want is the cold-path cost, not the cache's.
        probe = f"{sample}\nrun {index}"
        started = time.perf_counter()
        red.redact(probe)
        timings.append((time.perf_counter() - started) * 1000)
    timings.sort()
    print(
        json.dumps(
            {
                "chars": len(sample),
                "runs": args.runs,
                "p50_ms": round(timings[len(timings) // 2], 2),
                "p95_ms": round(timings[int(len(timings) * 0.95) - 1], 2),
                "max_ms": round(timings[-1], 2),
                "budget_ms": red.settings.budget_ms,
            },
            indent=2,
        )
    )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from .adapters.stdio import serve

    serve(sys.stdin, sys.stdout)
    return 0


def _cmd_hook(args: argparse.Namespace) -> int:
    from .adapters.claude_code import handle_event

    payload = sys.stdin.read()
    try:
        event = json.loads(payload) if payload.strip() else {}
    except ValueError:
        json.dump({"systemMessage": "pii-redact: invalid hook payload"}, sys.stdout)
        return 0
    json.dump(handle_event(event), sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


_SAMPLE = (
    "Invoice #2025-0042 — Dupont Roofing Ltd, 742 Evergreen Terrace, Springfield.\n"
    "Customer: Ms Amelia Rooke, amelia.rooke@example.com, (415) 555-0132.\n"
    "IBAN GB29 NWBK 6016 1331 9268 19 — total $1,234.56 due on 2025-03-12.\n"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="piiredact",
        description="Local, deterministic PII pseudonymisation for LLM agents.",
    )
    parser.add_argument("--version", action="version", version=f"piiredact {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    redact = sub.add_parser("redact", help="pseudonymise stdin or a file")
    redact.add_argument("file", nargs="?", default="-")
    redact.add_argument("--json", action="store_true", help="emit a JSON envelope")
    redact.add_argument("--stats", action="store_true", help="print counts to stderr")
    redact.add_argument("--lang", help="comma-separated language packs (e.g. en,fr)")
    redact.add_argument("--profile", choices=sorted(PROFILES), help="override the profile")
    redact.set_defaults(func=_cmd_redact)

    restore = sub.add_parser("restore", help="put real values back")
    restore.add_argument("file", nargs="?", default="-")
    restore.set_defaults(func=_cmd_restore)

    vault = sub.add_parser("vault", help="inspect or edit the local mapping")
    vault.add_argument("action", choices=("list", "count", "add", "forget"))
    vault.add_argument("type", nargs="?", help="entity type for 'add'")
    vault.add_argument("value", nargs="?", help="value for 'add' / token for 'forget'")
    vault.add_argument(
        "--reveal",
        action="store_true",
        help="print values unmasked (they are personal data — be deliberate)",
    )
    vault.set_defaults(func=_cmd_vault)

    config = sub.add_parser("config", help="create or inspect the config file")
    config.add_argument("action", choices=("init", "show", "path"))
    config.add_argument("-o", "--output", help="where to write (for 'init')")
    config.add_argument("--force", action="store_true", help="overwrite an existing file")
    config.set_defaults(func=_cmd_config)

    languages = sub.add_parser("languages", help="list available language packs")
    languages.set_defaults(func=_cmd_languages)

    types_cmd = sub.add_parser("types", help="list maskable types, profiles and aliases")
    types_cmd.set_defaults(func=_cmd_types)

    doctor = sub.add_parser("doctor", help="show effective configuration and invariants")
    doctor.set_defaults(func=_cmd_doctor)

    bench = sub.add_parser("bench", help="measure per-call latency")
    bench.add_argument("file", nargs="?", default=None)
    bench.add_argument("--runs", type=int, default=50)
    bench.add_argument("--repeat", type=int, default=20, help="sample repetitions")
    bench.add_argument("--lang", help="comma-separated language packs")
    bench.set_defaults(func=_cmd_bench)

    serve = sub.add_parser("serve", help="JSON-lines server on stdin/stdout")
    serve.set_defaults(func=_cmd_serve)

    hook = sub.add_parser("hook", help="handle one Claude Code hook event on stdin")
    hook.set_defaults(func=_cmd_hook)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ValueError as exc:
        # Configuration errors (unknown type, unknown language, bad profile)
        # must be loud: a silently ignored setting is a policy the user thinks
        # is in force but is not.
        print(f"piiredact: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
