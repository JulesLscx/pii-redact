"""CLI surface — the integration path for hosts without a native adapter."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _run(args, tmp_path: Path, stdin: str = "") -> subprocess.CompletedProcess:
    env = {
        "PATH": "/usr/bin:/bin",
        "PII_REDACT_DB": str(tmp_path / "mapping.db"),
        "PYTHONPATH": str(REPO),
        "HOME": str(tmp_path),
    }
    return subprocess.run(
        [sys.executable, "-m", "piiredact", *args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=str(REPO),
        env=env,
        timeout=60,
    )


def test_redact_and_restore_roundtrip(tmp_path: Path) -> None:
    text = "Titulaire : Amélie Roux — jean@example.fr\n"
    redacted = _run(["redact"], tmp_path, stdin=text)
    assert redacted.returncode == 0, redacted.stderr
    assert "Amélie Roux" not in redacted.stdout
    assert "jean@example.fr" not in redacted.stdout

    restored = _run(["restore"], tmp_path, stdin=redacted.stdout)
    assert restored.returncode == 0
    assert restored.stdout == text


def test_doctor_reports_a_healthy_configuration(tmp_path: Path) -> None:
    result = _run(["doctor"], tmp_path)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["enabled"] is True
    assert report["pattern_audit"] == "ok"
    assert report["profile"] == "balanced"


def test_vault_add_then_redact_uses_the_new_literal(tmp_path: Path) -> None:
    added = _run(["vault", "add", "PERSON", "Bertrand Fauchier"], tmp_path)
    assert added.returncode == 0
    assert added.stdout.strip().startswith("[PERSON_")

    redacted = _run(["redact"], tmp_path, stdin="vu Bertrand Fauchier hier")
    assert "Bertrand Fauchier" not in redacted.stdout


def test_vault_list_masks_values_by_default(tmp_path: Path) -> None:
    _run(["vault", "add", "PERSON", "Amélie Roux"], tmp_path)
    listed = _run(["vault", "list"], tmp_path)
    assert "Amélie Roux" not in listed.stdout
    assert "PERSON" in listed.stdout

    revealed = _run(["vault", "list", "--reveal"], tmp_path)
    assert "Amélie Roux" in revealed.stdout


def test_vault_add_rejects_an_unknown_type(tmp_path: Path) -> None:
    result = _run(["vault", "add", "NOPE", "x"], tmp_path)
    assert result.returncode == 2
    assert "unknown entity type" in result.stderr


def test_json_output_shape(tmp_path: Path) -> None:
    result = _run(["redact", "--json"], tmp_path, stdin="mail jean@example.fr")
    payload = json.loads(result.stdout)
    assert payload["counts"] == {"EMAIL": 1}
    assert "jean@example.fr" not in payload["text"]


def test_serve_answers_json_lines(tmp_path: Path) -> None:
    requests = "\n".join(
        [
            json.dumps({"op": "redact", "text": "mail jean@example.fr"}),
            json.dumps({"op": "status"}),
        ]
    )
    result = _run(["serve"], tmp_path, stdin=requests + "\n")
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    assert lines[0]["ok"] is True and "jean@example.fr" not in lines[0]["text"]
    assert lines[1]["mappings"] >= 1


def test_hook_mode_speaks_claude_code_json(tmp_path: Path) -> None:
    event = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": "Titulaire : Amélie Roux",
        }
    )
    result = _run(["hook"], tmp_path, stdin=event)
    payload = json.loads(result.stdout)
    assert "Amélie Roux" not in payload["hookSpecificOutput"]["updatedToolOutput"]


def test_disable_switch_turns_everything_off(tmp_path: Path) -> None:
    env_run = subprocess.run(
        [sys.executable, "-m", "piiredact", "redact"],
        input="mail jean@example.fr",
        capture_output=True,
        text=True,
        cwd=str(REPO),
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(REPO),
            "HOME": str(tmp_path),
            "PII_REDACT_DB": str(tmp_path / "mapping.db"),
            "PII_REDACT_DISABLE": "1",
        },
        timeout=60,
    )
    assert env_run.stdout == "mail jean@example.fr"
