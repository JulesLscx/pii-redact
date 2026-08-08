"""Test fixtures: every test gets its own vault and a clean singleton.

The redactor is a process-wide singleton holding an open SQLite connection, so
leaking one between tests would make token numbering depend on test order —
exactly the kind of hidden coupling that makes a determinism suite lie.
"""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path
from typing import Iterator

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from piiredact import Redactor, Settings, load_settings, reset_redactor  # noqa: E402
from piiredact.types import DIRECT_IDENTIFIERS, QUASI_IDENTIFIERS  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip host configuration so tests never read the developer's own vault."""
    for key in list(sys.modules.get("os").environ):  # type: ignore[union-attr]
        if key.startswith("PII_REDACT_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    reset_redactor()
    yield
    reset_redactor()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Balanced-profile settings pointing at a throwaway vault."""
    return dataclasses.replace(
        load_settings(),
        db_path=tmp_path / "mapping.db",
        types=frozenset(DIRECT_IDENTIFIERS),
    )


@pytest.fixture
def strict_settings(settings: Settings) -> Settings:
    return dataclasses.replace(
        settings,
        profile="strict",
        types=frozenset(DIRECT_IDENTIFIERS) | frozenset(QUASI_IDENTIFIERS),
    )


@pytest.fixture
def redactor(settings: Settings) -> Iterator[Redactor]:
    instance = Redactor(settings)
    yield instance
    instance.vault.close()


@pytest.fixture
def strict_redactor(strict_settings: Settings) -> Iterator[Redactor]:
    instance = Redactor(strict_settings)
    yield instance
    instance.vault.close()
