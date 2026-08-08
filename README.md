# pii-redact

Local, deterministic pseudonymization for personal data used by LLM agents.

The model never sees your real data; you still do. Files written to disk, commands run locally, and displayed answers contain real values — only the path to the LLM provider is pseudonymized.

```
You   : "what is the billing address on the latest quote?"
        │
        ├─ agent reads quote.pdf        → "12 bis rue des Lilas, 69007 Lyon"
        ├─ pii-redact                   → "[ADDR_0001], [POSTAL_0001] Lyon"
        ├─ LLM reasons on tokens        → "...is [ADDR_0001]"
        └─ pii-redact restores          → "...is 12 bis rue des Lilas"
You   : read the real address. The model never received it.
```

## What is detected

Email · IBAN · card numbers · French NIR (social security) · SIRET / intra-EU VAT · account or contract IDs · phone numbers · license plates · postal addresses · ZIP/postal codes · URLs containing identifiers · person names anchored by title (`Ms X`, `Dr X`) or field (`Account holder: X`) · organizations anchored by legal form (`SARL X`) · amounts · dates.

Plus: **any value seen once already**. The literal directory is persistent, so a name captured once (for example via title) is then recognized everywhere, unanchored, across documents.

## Installation

### Hermes Agent

The plugin is already in place (`~/.hermes/plugins/pii-redact/`). Enable it in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - pii-redact
```

Then run `hermes gateway restart` (or restart your session). Verify:

```bash
hermes plugins list | grep pii-redact
python3 -m piiredact doctor         # from ~/.hermes/plugins/pii-redact
```

### Other hosts (Claude Code, OpenCode, Codex, scripts)

The core is a dependency-free Python package. Three integration modes:

**1. Library**

```python
from piiredact import redact, restore

safe = redact(document).text     # → LLM
real = restore(model_answer)     # → user / local tool
```

**2. Claude Code hooks** — `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse":  [{"hooks": [{"type": "command", "command": "python3 -m piiredact hook"}]}],
    "PostToolUse": [{"hooks": [{"type": "command", "command": "python3 -m piiredact hook"}]}]
  }
}
```

`PostToolUse` pseudonymizes tool results (`updatedToolOutput`), `PreToolUse` restores values for local tools (`updatedInput`) and blocks egress tools in `block` mode.

> **Known limitation**: `UserPromptSubmit` cannot rewrite prompt text. PII typed directly by the user in Claude Code cannot be pseudonymized in transit — you get a warning, or a hard block if `PII_REDACT_BLOCK=1`. Hermes does not have this limitation (`llm_request` middleware covers the full payload).

**3. JSON-lines server** — for any host that can spawn a subprocess. Keeping one hot process avoids Python startup overhead on each event:

```bash
python3 -m piiredact serve
{"op":"redact","text":"IBAN FR76 3000 4000 0512 3456 7890 143"}
{"ok": true, "text": "IBAN [IBAN_0001]", "counts": {"IBAN": 1}, "ms": 0.4}
```

Available ops: `redact`, `restore`, `redact_args`, `restore_args`, `learn`, `status`.

## CLI usage

```bash
python3 -m piiredact redact < invoice.txt      # pseudonymize
python3 -m piiredact restore < answer.txt      # restore
python3 -m piiredact doctor                    # effective config + invariants
python3 -m piiredact bench                     # measured latency
python3 -m piiredact vault count               # number of known values
python3 -m piiredact vault list                # masked values (--reveal to show all)
python3 -m piiredact vault add PERSON "Amelie" # learn a value manually
python3 -m piiredact vault forget '[PERSON_0003]'
```

`vault add` is the escape hatch for values no rule can infer: a child first name, nickname, project codename. Once added, it is masked everywhere, permanently.

## Configuration

Everything is environment-driven (in `~/.hermes/.env` for Hermes).

| Variable | Default | Effect |
|---|---|---|
| `PII_REDACT_DISABLE` | `0` | Disable everything (full no-op) |
| `PII_REDACT_PROFILE` | `balanced` | `balanced` or `strict` (see below) |
| `PII_REDACT_BLOCK` | `0` | Reject egress tool calls containing PII instead of allowing tokenized output |
| `PII_REDACT_DB` | `$HERMES_HOME/pii-redact/mapping.db` | Vault location |
| `PII_REDACT_LANG` | `fr` | Active rule pack(s), comma-separated (`fr`, `en`, or `fr,en`) |
| `PII_REDACT_TERMS` | — | `TYPE:value` file loaded at startup |
| `PII_REDACT_NER` | `0` | Enable spaCy pass |
| `PII_REDACT_NER_MODEL` | `fr_core_news_sm` | spaCy model |
| `PII_REDACT_TYPES` | — | Explicit type list (replaces profile) |
| `PII_REDACT_ADD_TYPES` / `PII_REDACT_SKIP_TYPES` | — | Profile adjustments |
| `PII_REDACT_BUDGET_MS` | `300` | Latency budget per call |
| `PII_REDACT_MAX_BYTES` | `4194304` | Content is truncated above this size (never sent in clear text) |
| `PII_REDACT_EGRESS_TOOLS` | — | Extra tools treated as third-party egress |
| `PII_REDACT_LOCAL_TOOLS` | — | Tools forced to local mode |
| `PII_REDACT_GUARD_PAYLOAD` | `1` | Final pass on provider payload |
| `PII_REDACT_RESTORE_TOOL_ARGS` | `1` | Restore local tool arguments |
| `PII_REDACT_LOG_COUNTS` | `0` | Log per-type counters (never values) |

### Profiles

**`balanced` (default)** — all direct identifiers are pseudonymized; **amounts and dates stay readable**. A standalone amount, once name/address/IBAN are removed, is typically not identifying, while masking it harms arithmetic, comparisons, and due-date reasoning.

**`strict`** — also masks amounts and dates. Use when your threat model includes linkage re-identification. You lose model arithmetic and temporal reasoning.

```bash
PII_REDACT_PROFILE=strict     # mask everything
PII_REDACT_SKIP_TYPES=ORG,LOC # or tune type-by-type
```

## Performance

Measured on this machine (`python3 -m piiredact bench`) on dense PII text:

| Size | p50 | p95 |
|---|---|---|
| 4 KB | 5 ms | 6 ms |
| 210 KB | 167 ms | 203 ms |

Cost is **linear** (~0.8 ms/KB). Previously seen content is hash-cached, so the provider payload pass (which replays full history before each API call) stays in the microsecond range once warm. The 300 ms budget covers roughly 300 KB.

spaCy pass costs 30–150 ms per document, so it is disabled by default. Model load itself can take ~16 s cold-start, so loading runs on a background thread at session startup. Until ready, NER returns no matches; deterministic layers still run and tool calls are not blocked.

## Security

- SQLite vault is created with `0600` permissions in a `0700` directory. It contains real values and stays local.
- **No agent-exposed tool can read the vault** — otherwise the model could trivially ask for table contents.
- Logs never include values, only per-type counters.
- Unknown tokens restore to themselves: a rotated database degrades to inert markers, never corrupted output.

## Development

```bash
python3 -m pytest                 # 114 tests
python3 -m piiredact doctor       # invariants (including pattern audit)
```

The key test is `tests/test_leak.py`: four realistic French documents (invoice, bank statement, tax notice, report) and an assertion that no declared value survives redaction.

**Do not reintroduce this trap**: a rule ending with `\b` breaks when a value is followed by punctuation (`1 234,56 €.`), because there is no word boundary between `€` and `.` — the value can leak. Use `(?!\w)` instead. `audit_patterns()` rejects faulty patterns and a dedicated test enforces it.

See [docs/SPEC.md](docs/SPEC.md) for invariants, threat model, and design trade-offs.
