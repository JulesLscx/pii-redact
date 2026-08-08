"""Optional spaCy NER — the *last* layer, never a dependency.

Why it is off by default:

* it costs 30-150 ms for a page of French text, which alone would consume the
  whole per-tool-call latency budget;
* it needs a model download the host may not have;
* every miss it would have caught is, in practice, caught deterministically on
  the second occurrence once the value lands in the vault gazetteer.

When enabled (``PII_REDACT_NER=1``), the import is lazy and every failure is
swallowed into "no spans": a missing model degrades recall, it must never
degrade availability. Anything it finds is written to the vault, so the cheap
literal matcher picks up that value from then on — the expensive layer pays
once per distinct value, not once per occurrence.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, List, Optional, Sequence

from .types import ClaimSet, EntityType, Span

logger = logging.getLogger(__name__)

#: spaCy label -> our entity types. Labels outside this map are ignored.
LABEL_MAP = {
    "PER": EntityType.PERSON,
    "PERSON": EntityType.PERSON,
    "ORG": EntityType.ORG,
    "LOC": EntityType.LOC,
    "GPE": EntityType.LOC,
}

FALLBACK_MODEL = "xx_ent_wiki_sm"


class NerBackend:
    """Lazy, fail-open wrapper around a spaCy pipeline."""

    def __init__(self, model_name: str) -> None:
        self.model_name = model_name
        self._lock = threading.Lock()
        self._nlp: Optional[Any] = None
        self._unavailable = False
        self._loading = False

    @property
    def available(self) -> bool:
        return not self._unavailable

    @property
    def ready(self) -> bool:
        """True when the model is loaded and a pass would run in-line."""
        return self._nlp is not None

    def prewarm(self) -> None:
        """Load the model on a background thread.

        Loading ``fr_core_news_sm`` takes seconds — measured at ~16 s cold on
        this machine. Doing that inside a tool call would blow the latency
        budget by two orders of magnitude on the first call of every session,
        so the load never happens on the hot path: it is kicked off at session
        start (and again, lazily, the first time a pass wants it), and until it
        finishes the deterministic layers carry the work alone.
        """
        if self._nlp is not None or self._unavailable or self._loading:
            return
        with self._lock:
            if self._nlp is not None or self._unavailable or self._loading:
                return
            self._loading = True
        thread = threading.Thread(
            target=self._load_in_background, name="pii-redact-ner-warm", daemon=True
        )
        thread.start()

    def _load_in_background(self) -> None:
        try:
            self._load()
        finally:
            self._loading = False

    def _load(self) -> Optional[Any]:
        if self._nlp is not None or self._unavailable:
            return self._nlp
        with self._lock:
            if self._nlp is not None or self._unavailable:
                return self._nlp
            try:
                import spacy  # noqa: PLC0415 - deliberately deferred
            except ImportError:
                logger.info("pii-redact: spaCy not installed; NER layer disabled")
                self._unavailable = True
                return None
            for name in (self.model_name, FALLBACK_MODEL):
                try:
                    # Only the NER component is needed; disabling the rest
                    # roughly halves the per-document cost.
                    self._nlp = spacy.load(name, exclude=["lemmatizer", "textcat"])
                    return self._nlp
                except Exception as exc:  # model missing / incompatible
                    logger.debug("pii-redact: cannot load spaCy model %s: %s", name, exc)
            logger.info(
                "pii-redact: no spaCy model available (tried %s, %s); NER layer disabled",
                self.model_name, FALLBACK_MODEL,
            )
            self._unavailable = True
            return None

    def spans(self, text: str, wanted: frozenset, claimed: ClaimSet) -> List[Span]:
        """Return NER spans that do not intersect an already-claimed region.

        Never blocks on the model load: if the pipeline is not ready yet the
        call returns nothing and schedules the load in the background. Recall
        is degraded for the first few calls of a cold session; latency is not.
        """
        nlp = self._nlp
        if nlp is None:
            self.prewarm()
            return []
        try:
            doc = nlp(text)
        except Exception as exc:
            logger.debug("pii-redact: NER pass failed: %s", exc)
            return []
        found: List[Span] = []
        for ent in doc.ents:
            entity_type = LABEL_MAP.get(ent.label_)
            if entity_type is None or entity_type not in wanted:
                continue
            start, end = ent.start_char, ent.end_char
            if claimed.overlaps(start, end):
                continue
            found.append(Span(start, end, entity_type, ent.text, origin="ner"))
            claimed.add(start, end)
        return found
