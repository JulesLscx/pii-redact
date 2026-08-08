"""``python -m piiredact`` — the host-independent entry point.

Any tool that can run a subprocess can use the engine through this CLI, which
makes it the lowest-common-denominator integration path when no native adapter
exists yet:

    cat facture.txt | python -m piiredact redact
    python -m piiredact restore < reponse.txt
    python -m piiredact vault add PERSON "Amélie"
    python -m piiredact serve          # persistent JSON-lines server

``serve`` exists because per-event subprocess spawning costs ~80-120 ms of
interpreter startup, which would eat a third of the latency budget before any
work happens. Hosts that fire many events should keep one server warm and talk
to it over a pipe.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import List, Optional, Sequence

from . import __version__, get_redactor
from .rules import RULES, audit_patterns
from .types import ALL_TYPES


def _read_input(path: Optional[str]) -> str:
    if path in (None, "-"):
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _cmd_redact(args: argparse.Namespace) -> int:
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
        entity_type = args.type.upper()
        if entity_type not in ALL_TYPES:
            print(
                f"unknown type {entity_type!r}; expected one of {', '.join(ALL_TYPES)}",
                file=sys.stderr,
            )
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


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Report configuration and invariants — the "is it really on?" command."""
    red = get_redactor()
    settings = red.settings
    problems = audit_patterns()
    report = {
        "version": __version__,
        "enabled": settings.enabled,
        "profile": settings.profile,
        "types": sorted(settings.types),
        "block": settings.block,
        "ner_enabled": settings.use_ner,
        "ner_available": red.ner.available if settings.use_ner else None,
        "db_path": str(settings.db_path),
        "db_exists": settings.db_path.exists(),
        "mappings": red.vault.count(),
        "rules": len(RULES),
        "budget_ms": settings.budget_ms,
        "pattern_audit": problems or "ok",
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if problems else 0


def _cmd_bench(args: argparse.Namespace) -> int:
    """Measure the per-call cost against the latency budget."""
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
    "Facture n° 2025-0042 — SARL Dupont Toitures, 12 rue des Lilas, 69007 Lyon.\n"
    "Client : Amélie Roux, amelie.roux@example.fr, 06 12 34 56 78.\n"
    "IBAN FR76 3000 4000 0512 3456 7890 143 — total 1 234,56 € au 12/03/2025.\n"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="piiredact",
        description="Pseudonymisation locale et déterministe des données personnelles.",
    )
    parser.add_argument("--version", action="version", version=f"piiredact {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    redact = sub.add_parser("redact", help="pseudonymise stdin or a file")
    redact.add_argument("file", nargs="?", default="-")
    redact.add_argument("--json", action="store_true", help="emit a JSON envelope")
    redact.add_argument("--stats", action="store_true", help="print counts to stderr")
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

    doctor = sub.add_parser("doctor", help="show effective configuration and invariants")
    doctor.set_defaults(func=_cmd_doctor)

    bench = sub.add_parser("bench", help="measure per-call latency")
    bench.add_argument("file", nargs="?", default=None)
    bench.add_argument("--runs", type=int, default=50)
    bench.add_argument("--repeat", type=int, default=20, help="sample repetitions")
    bench.set_defaults(func=_cmd_bench)

    serve = sub.add_parser("serve", help="JSON-lines server on stdin/stdout")
    serve.set_defaults(func=_cmd_serve)

    hook = sub.add_parser("hook", help="handle one Claude Code hook event on stdin")
    hook.set_defaults(func=_cmd_hook)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
