"""Pipeline orchestration: detect → tokenise → (later) restore.

Layer order is deliberate, cheapest and most certain first:

1. **token pre-claim** — regions already holding a token are frozen, which is
   what makes the whole operation idempotent and safe to apply at several
   layers of the same request;
2. **deterministic rules** (:mod:`.rules`) — structured French PII;
3. **literal gazetteer** (:mod:`.matcher`) — every value ever tokenised, plus
   the user's own terms file;
4. **statistical NER** (:mod:`.ner`) — opt-in, deadline-guarded, and its finds
   are fed back into layer 3 so it never has to see the same value twice.

Latency is a hard product requirement (a tool call must not get more than a few
hundred milliseconds slower), so the orchestrator carries an explicit budget:
layers 3 and 4 are skipped once the deadline is blown, and oversized input is
cut with an explicit notice rather than passed through. Skipping *never* means
"emit the raw text" — the guard fails closed in every branch.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .cache import LruCache
from .config import Settings, load_settings
from .matcher import LiteralMatcher, parse_terms_file
from .ner import NerBackend
from .normalize import content_hash
from .rules import BARE_TOKEN_RE, TOKEN_RE, rule_spans, token_spans
from .types import RedactionResult, Span, resolve_overlaps
from .vault import Vault

logger = logging.getLogger(__name__)

#: Appended when the fail-closed guard cuts oversized content. Phrased for the
#: model: it explains the gap so the agent asks for a narrower read instead of
#: silently reasoning on a truncated document.
TRUNCATION_NOTICE = (
    "\n\n[pii-redact] Contenu tronqué localement avant transmission "
    "(taille supérieure à la limite de scan). Relancez la lecture sur une "
    "portion plus petite pour obtenir la suite."
)


class Redactor:
    """Stateful facade over the vault, the matchers and the caches.

    One instance per process is the intended usage (see
    :func:`piiredact.get_redactor`); it is safe to share across threads.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        vault: Optional[Vault] = None,
    ) -> None:
        self.settings = settings or load_settings()
        self.vault = vault or Vault(self.settings.db_path)
        self.matcher = LiteralMatcher()
        self.ner = NerBackend(self.settings.ner_model)
        self._redact_cache: LruCache[Tuple[str, Tuple[Span, ...], bool]] = LruCache(
            self.settings.cache_entries
        )
        self._terms_loaded = False

    # -- public API ----------------------------------------------------------

    def redact(self, text: str, deadline_ms: Optional[int] = None) -> RedactionResult:
        """Replace every detected PII value with its stable token."""
        started = time.perf_counter()
        if not text or not self.settings.enabled:
            return RedactionResult(text=text, elapsed_ms=0.0)

        digest = content_hash(text)
        generation = self.vault.generation
        cached = self._redact_cache.get(generation, digest)
        if cached is not None:
            redacted, spans, truncated = cached
            return RedactionResult(
                text=redacted,
                spans=list(spans),
                truncated=truncated,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                cached=True,
            )

        budget = self.settings.budget_ms if deadline_ms is None else deadline_ms
        deadline = started + (budget / 1000.0)

        working, truncated = self._apply_size_guard(text)
        spans = self._detect(working, deadline)
        redacted, tokens = self._apply(working, spans)
        if truncated:
            redacted += TRUNCATION_NOTICE

        self._redact_cache.put(generation, digest, (redacted, tuple(spans), truncated))
        elapsed = (time.perf_counter() - started) * 1000
        if self.settings.log_counts and spans:
            logger.info(
                "pii-redact: %d span(s) redacted in %.1f ms %s",
                len(spans), elapsed, _counts(spans),
            )
        return RedactionResult(
            text=redacted,
            spans=spans,
            tokens=tokens,
            truncated=truncated,
            elapsed_ms=elapsed,
        )

    def restore(self, text: str) -> str:
        """Put the real values back. Unknown tokens are left untouched.

        This is the half that preserves functionality: the model reasons over
        tokens, and the user — or the tool about to run — receives real data.
        An unknown token restores to itself rather than to a placeholder, so a
        vault that has been rotated degrades to "harmless leftover marker"
        instead of "corrupted output".
        """
        if not text or not self.settings.enabled:
            return text

        def _from_token(match: "Any") -> str:
            token = match.group(0)
            value = self.vault.value_for(token)
            return value if value is not None else token

        restored = TOKEN_RE.sub(_from_token, text)

        if self.settings.restore_bare_tokens:
            def _from_bare(match: "Any") -> str:
                bracketed = f"[{match.group(1)}_{match.group(2)}]"
                value = self.vault.value_for(bracketed)
                return value if value is not None else match.group(0)

            restored = BARE_TOKEN_RE.sub(_from_bare, restored)
        return restored

    def redact_obj(self, obj: Any, deadline_ms: Optional[int] = None) -> Tuple[Any, int]:
        """Recursively redact every string in a JSON-like structure.

        Returns ``(new_obj, span_count)``. Working on the parsed structure
        rather than the serialised blob means a replacement can never straddle
        a quote and corrupt the envelope the host is about to parse.
        """
        count = 0
        if isinstance(obj, str):
            result = self.redact(obj, deadline_ms=deadline_ms)
            return result.text, len(result.spans)
        if isinstance(obj, dict):
            out: Dict[Any, Any] = {}
            for key, value in obj.items():
                new_value, n = self.redact_obj(value, deadline_ms=deadline_ms)
                out[key] = new_value
                count += n
            return out, count
        if isinstance(obj, list):
            items = []
            for value in obj:
                new_value, n = self.redact_obj(value, deadline_ms=deadline_ms)
                items.append(new_value)
                count += n
            return items, count
        return obj, 0

    def redact_payload(self, payload: str, deadline_ms: Optional[int] = None) -> Tuple[str, int]:
        """Redact a string that may or may not be JSON.

        Hermes tool results are JSON strings; other hosts hand over raw text.
        Trying the structured path first keeps the JSON valid, and the raw path
        is the fallback — either way the return value is a string of the same
        kind that came in.
        """
        stripped = payload.lstrip()
        if stripped[:1] in "{[":
            try:
                parsed = json.loads(payload)
            except (ValueError, TypeError):
                parsed = None
            if parsed is not None:
                redacted, count = self.redact_obj(parsed, deadline_ms=deadline_ms)
                if count == 0:
                    return payload, 0
                return json.dumps(redacted, ensure_ascii=False), count
        result = self.redact(payload, deadline_ms=deadline_ms)
        return result.text, len(result.spans)

    def restore_obj(self, obj: Any) -> Any:
        """Recursively restore tokens inside a JSON-like structure."""
        if isinstance(obj, str):
            return self.restore(obj)
        if isinstance(obj, dict):
            return {key: self.restore_obj(value) for key, value in obj.items()}
        if isinstance(obj, list):
            return [self.restore_obj(value) for value in obj]
        return obj

    def learn(self, entity_type: str, value: str) -> str:
        """Register a value manually; returns its token."""
        return self.vault.add_literal(entity_type, value)

    # -- internals -----------------------------------------------------------

    def _apply_size_guard(self, text: str) -> Tuple[str, bool]:
        """Cut oversized input so scan time stays bounded and predictable.

        Truncating loses information, which is why the notice is explicit — but
        the alternative (letting a 50 MB dump through unscanned to stay fast)
        would be a leak, and the whole point of this plugin is that there is no
        such trade to make.
        """
        limit = self.settings.max_bytes
        if limit <= 0 or len(text) <= limit:
            return text, False
        return text[:limit], True

    def _detect(self, text: str, deadline: float) -> List[Span]:
        wanted = self.settings.types

        # 1. Freeze existing tokens (idempotence).
        claimed: List[Span] = token_spans(text)
        collected: List[Span] = []

        # 2. Deterministic rules — always run, never skipped by the budget.
        collected.extend(rule_spans(text, wanted, claimed))

        # 3. Literal gazetteer (vault + terms file).
        if time.perf_counter() < deadline:
            self._ensure_matcher(wanted)
            literal_hits = self.matcher.spans(text, claimed)
            collected.extend(literal_hits)
            claimed.extend(literal_hits)

        # 4. Optional NER, last and strictly budget-gated.
        if (
            self.settings.use_ner
            and len(text) <= self.settings.ner_max_chars
            and time.perf_counter() < deadline
        ):
            ner_hits = self.ner.spans(text, wanted, claimed)
            collected.extend(ner_hits)
            claimed.extend(ner_hits)

        return resolve_overlaps(collected)

    def _ensure_matcher(self, wanted: "frozenset") -> None:
        self._load_terms_once()
        self.matcher.ensure_built(
            self.vault.generation,
            wanted,
            lambda: [(t, v) for t, v, _tok in self.vault.entries()],
        )

    def _load_terms_once(self) -> None:
        """Seed the vault from the user's terms file, if configured."""
        if self._terms_loaded:
            return
        self._terms_loaded = True
        path: Optional[Path] = self.settings.terms_path
        if path is None or not path.exists():
            return
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("pii-redact: cannot read terms file %s: %s", path, exc)
            return
        for entity_type, value in parse_terms_file(raw):
            try:
                self.vault.add_literal(entity_type, value)
            except Exception as exc:
                logger.debug("pii-redact: skipping term %r: %s", value, exc)

    def _apply(self, text: str, spans: Sequence[Span]) -> Tuple[str, Dict[str, str]]:
        """Splice tokens into *text* for the (already disjoint) spans."""
        if not spans:
            return text, {}
        pieces: List[str] = []
        tokens: Dict[str, str] = {}
        cursor = 0
        for span in spans:
            if span.origin == "token":
                continue
            token = self.vault.token_for(span.entity_type, span.text)
            pieces.append(text[cursor:span.start])
            pieces.append(token)
            tokens[token] = span.text
            cursor = span.end
        pieces.append(text[cursor:])
        return "".join(pieces), tokens


def _counts(spans: Sequence[Span]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for span in spans:
        out[span.entity_type] = out.get(span.entity_type, 0) + 1
    return out
