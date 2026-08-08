# SPEC — pii-redact

## Goal

No real personal data leaves the machine toward an LLM, **without breaking agent capabilities**. The user should still be able to ask “what is the billing address?”, “how much did I pay?”, “send an email to the client”, and get a real answer from a model that never saw real values.

## Invariants

| # | Invariant | Verified by |
|---|---|---|
| I1 | No real PII value from test documents appears in transmitted text | `test_leak.py::test_no_real_value_survives_redaction` |
| I2 | `restore(redact(x)) == x` | `test_roundtrip_restores_the_original` |
| I3 | `redact(redact(x)) == redact(x)` (idempotence) | `test_redaction_is_idempotent` |
| I4 | Same real value → same token, within a run and across processes | `test_same_value_yields_same_token_across_processes` |
| I5 | No rule pattern ends with `\b` | `audit_patterns()` + `test_no_rule_pattern_ends_with_word_boundary` |
| I6 | Correlation IDs (`tool_call_id`, ...) and tool schemas are never rewritten | `test_provider_payload_is_redacted_without_touching_ids` |
| I7 | Cost < 300 ms per tool call on realistic documents | `test_latency.py` |
| I8 | Egress tools (web search, fetch, browser) never receive real values | `test_egress_tool_keeps_tokens` |
| I9 | SQLite mapping permissions are `0600` | `test_vault_file_is_owner_only` |
| I10 | Byte-identical output for identical history (prompt cache preserved) | `test_payload_pass_is_deterministic_across_calls` |

## Architecture

```
                local machine                      │    network
                                                    │
files ──► tool ──► [raw output] ───────────────────┼──► ✗ never
                        │                           │
                        ▼ redact()                  │
                  [TYPE_NNNN] ─────────────────────┼──► LLM
                        ▲                           │    │
                        │ restore()                 │    │ reply
disk ◄── local tool ◄───┤                           │    │ (tokens)
screen ◄── user ◄───────┴───────────────────────────┼────┘
                                                    │
SQLite vault (token → real value) ─ local, 0600, never transmitted
```

### Detection layers (execution order)

1. **Token pre-reservation** — zones already containing `[TYPE_NNNN]` are frozen. This guarantees idempotence and makes repeated passes safe.
2. **Deterministic rules** (`rules.py` + `lang/`) — neutral engine with language packs (`lang/fr.py`, `lang/en.py`) and shared universal pack (`lang/common.py`: email, IBAN, cards, IP). `PII_REDACT_LANG` selects active packs; combined rules are priority-sorted for “specific before generic”.
3. **Literal directory** (`matcher.py`) — all already-known vault values plus user-provided terms. Once detected once, values are redetected everywhere, unanchored.
4. **In-document rescan** — values discovered during the same pass are searched again in the same text (anchored first mention covers later unanchored mentions).
5. **spaCy NER** (`ner.py`) — optional, disabled by default, latency-budget bounded.

Layers 1–4 are **fully deterministic**. Layer 5 is never required for correctness.

### Token assignment

`SHA-256(type + ":" + normalized value)` → unique row in `pii_mapping` → `[TYPE_NNNN]` (type-local sequence, ≥4 digits). Normalization folds case, accents, and separators per type so equivalent forms map to one token.

## Threat model

**Covered** — PII leakage to the LLM provider from any input path (file reads, command output, injected memory, pasted message); leakage to third-party services through egress tools.

**Not covered** — adversary with local host access (vault stores real values in clear text, protected by filesystem permissions); linkage re-identification from quasi-identifiers left clear in `balanced` profile (amounts, dates); documents the agent never opens.

## Key decisions and trade-offs

- **Default `balanced` profile**: direct identifiers are always pseudonymized; amounts/dates only in `strict`, preserving core model reasoning.
- **No agent-facing vault read tool**: prevents trivial exfiltration.
- **Restore only for local tools**: avoids replacing LLM leakage with third-party leakage.
- **Intentional over-detection**: false positives are acceptable because restoration is exact; false negatives are leaks.

## Known limitations

- Never-seen bare proper names without title/field anchors are not caught by deterministic layers.
- In Claude Code, `UserPromptSubmit` cannot rewrite user-typed prompt text.
- Cost scales linearly with size (~0.8 ms/KB); `PII_REDACT_MAX_BYTES` bounds worst-case processing by truncation with explicit model note.
