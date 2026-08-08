"""SQLite mapping store — the only place a real value is ever written.

The vault is strictly local: it holds ``token -> real value`` so the pipeline
can put the real data back after the model has answered. It is created with
``0600`` permissions inside a ``0700`` directory because its contents are, by
construction, the exact material we are keeping off the network.

Concurrency: a Hermes session is multi-threaded (delegated tool calls,
background workers) and several processes can share one home (gateway, CLI,
kanban workers). The connection therefore runs in WAL mode with
``check_same_thread=False`` behind an ``RLock``, and every write is a single
``INSERT ... ON CONFLICT`` so two racing threads converge on the same token
instead of allocating two.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .normalize import hash_value

SCHEMA = """
PRAGMA journal_mode=WAL;

-- Local-only correspondence table. Never transmitted, never summarised into
-- a prompt: the model only ever sees the `token` column's shape.
CREATE TABLE IF NOT EXISTS pii_mapping (
    token       TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    real_value  TEXT NOT NULL,
    value_hash  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE(entity_type, value_hash)
);

CREATE TABLE IF NOT EXISTS pii_counters (
    entity_type TEXT PRIMARY KEY,
    next_seq    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pii_type ON pii_mapping(entity_type);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Vault:
    """Deterministic ``value <-> token`` store backed by SQLite."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._token_cache: Dict[str, str] = {}   # value_hash -> token
        self._value_cache: Dict[str, str] = {}   # token -> real value
        self._generation = 0
        self._prepare_paths()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()
        self._harden_permissions()

    # -- lifecycle -----------------------------------------------------------

    def _prepare_paths(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass

    def _harden_permissions(self) -> None:
        """Restrict the DB (and its WAL siblings) to the owner."""
        for suffix in ("", "-wal", "-shm"):
            target = Path(str(self.path) + suffix)
            try:
                if target.exists():
                    os.chmod(target, 0o600)
            except OSError:
                pass

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- token allocation ----------------------------------------------------

    @property
    def generation(self) -> int:
        """Bumped on every new mapping.

        Callers cache derived artefacts (the literal gazetteer, redaction
        results) keyed on this counter, so a new value invalidates them without
        any cross-object bookkeeping.
        """
        return self._generation

    def token_for(self, entity_type: str, value: str) -> str:
        """Return the stable token for *value*, creating it on first sight."""
        digest = hash_value(entity_type, value)
        cached = self._token_cache.get(digest)
        if cached is not None:
            return cached

        with self._lock:
            row = self._conn.execute(
                "SELECT token FROM pii_mapping WHERE entity_type = ? AND value_hash = ?",
                (entity_type, digest),
            ).fetchone()
            if row is not None:
                token = str(row["token"])
                self._token_cache[digest] = token
                return token

            token = self._allocate_locked(entity_type, value.strip(), digest)
            self._token_cache[digest] = token
            self._value_cache[token] = value.strip()
            self._generation += 1
            return token

    def _allocate_locked(self, entity_type: str, value: str, digest: str) -> str:
        """Allocate the next sequence number and insert the mapping.

        Runs inside ``self._lock``. The ``ON CONFLICT`` clause makes the insert
        idempotent across *processes* too: if another process won the race, we
        re-read its token rather than raising.
        """
        cur = self._conn.execute(
            "INSERT INTO pii_counters(entity_type, next_seq) VALUES (?, 2) "
            "ON CONFLICT(entity_type) DO UPDATE SET next_seq = next_seq + 1 "
            "RETURNING next_seq",
            (entity_type,),
        )
        next_seq = int(cur.fetchone()[0])
        seq = next_seq - 1 if next_seq > 1 else 1
        token = f"[{entity_type}_{seq:04d}]"
        self._conn.execute(
            "INSERT INTO pii_mapping(token, entity_type, real_value, value_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(entity_type, value_hash) DO NOTHING",
            (token, entity_type, value, digest, _now()),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT token FROM pii_mapping WHERE entity_type = ? AND value_hash = ?",
            (entity_type, digest),
        ).fetchone()
        return str(row["token"]) if row is not None else token

    # -- restore -------------------------------------------------------------

    def value_for(self, token: str) -> Optional[str]:
        """Return the real value behind *token*, or ``None`` if unknown."""
        cached = self._value_cache.get(token)
        if cached is not None:
            return cached
        with self._lock:
            row = self._conn.execute(
                "SELECT real_value FROM pii_mapping WHERE token = ?", (token,)
            ).fetchone()
        if row is None:
            return None
        value = str(row["real_value"])
        self._value_cache[token] = value
        return value

    # -- bulk reads (gazetteer, CLI) ----------------------------------------

    def entries(self, types: Optional[Iterable[str]] = None) -> List[Tuple[str, str, str]]:
        """Return ``(entity_type, real_value, token)`` rows, longest value first.

        Longest-first ordering matters for the literal matcher: "Marie Curie"
        must be tried before "Marie", otherwise the alternation would leave a
        dangling surname in the text sent to the model.
        """
        query = "SELECT entity_type, real_value, token FROM pii_mapping"
        params: Tuple[str, ...] = ()
        wanted = tuple(types) if types is not None else ()
        if wanted:
            placeholders = ",".join("?" for _ in wanted)
            query += f" WHERE entity_type IN ({placeholders})"
            params = wanted
        query += " ORDER BY LENGTH(real_value) DESC, token ASC"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [(str(r["entity_type"]), str(r["real_value"]), str(r["token"])) for r in rows]

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM pii_mapping").fetchone()[0])

    def counts_by_type(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT entity_type, COUNT(*) AS n FROM pii_mapping GROUP BY entity_type"
            ).fetchall()
        return {str(r["entity_type"]): int(r["n"]) for r in rows}

    # -- maintenance ---------------------------------------------------------

    def forget(self, token: str) -> bool:
        """Delete one mapping. The token then restores to itself (fail-safe)."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM pii_mapping WHERE token = ?", (token,))
            self._conn.commit()
            self._value_cache.pop(token, None)
            self._token_cache = {
                h: t for h, t in self._token_cache.items() if t != token
            }
            self._generation += 1
            return cur.rowcount > 0

    def add_literal(self, entity_type: str, value: str) -> str:
        """Register a value by hand so it is redacted from now on.

        This is the escape hatch for anything the rules cannot know: a
        pseudonym, a project code name, a child's first name.
        """
        return self.token_for(entity_type, value)
