"""Adapter behaviour: the Hermes seams, the Claude Code hooks, the JSON server.

These tests are where the "no functionality loss" claim is actually checked:
that a tool result is redacted on the way out, that a local tool gets the real
values back on the way in, that an egress tool does not, and that the user's
final answer is de-pseudonymised.
"""

from __future__ import annotations

import dataclasses
import io
import json

import pytest

from piiredact.adapters import claude_code, hermes, stdio
from piiredact.payloads import redact_request, restore_args
from piiredact.policy import is_egress_tool, should_restore_args
from piiredact.rules import TOKEN_RE


@pytest.fixture(autouse=True)
def _use_test_redactor(monkeypatch: pytest.MonkeyPatch, redactor) -> None:
    """Point every adapter at the throwaway vault from ``conftest``."""
    monkeypatch.setattr(hermes, "_get_redactor", lambda: redactor)
    monkeypatch.setattr(claude_code, "get_redactor", lambda *a, **k: redactor)
    monkeypatch.setattr(stdio, "get_redactor", lambda *a, **k: redactor)


class FakeCtx:
    """Minimal stand-in for Hermes' ``PluginContext``."""

    def __init__(self) -> None:
        self.hooks: dict = {}
        self.middleware: dict = {}

    def register_hook(self, name: str, callback) -> None:
        self.hooks.setdefault(name, []).append(callback)

    def register_middleware(self, kind: str, callback) -> None:
        self.middleware.setdefault(kind, []).append(callback)


# -- registration ------------------------------------------------------------


def test_register_wires_every_declared_seam() -> None:
    ctx = FakeCtx()
    hermes.register(ctx)
    assert set(ctx.hooks) == set(hermes.HOOKS)
    assert set(ctx.middleware) == set(hermes.MIDDLEWARE)


def test_plugin_yaml_matches_the_code() -> None:
    """The manifest is what Hermes shows the user — it must not drift."""
    from pathlib import Path

    manifest = Path(__file__).resolve().parent.parent / "plugin.yaml"
    raw = manifest.read_text(encoding="utf-8")
    for hook in hermes.HOOKS:
        assert f"- {hook}" in raw, f"{hook} missing from plugin.yaml"
    for kind in hermes.MIDDLEWARE:
        assert f"- {kind}" in raw, f"{kind} missing from plugin.yaml"


# -- outbound: tool results --------------------------------------------------


def test_tool_result_is_redacted(redactor) -> None:
    result = json.dumps(
        {"content": "Titulaire : Amélie Roux — IBAN FR76 3000 4000 0512 3456 7890 143"},
        ensure_ascii=False,
    )
    out = hermes.on_transform_tool_result(tool_name="read_file", args={}, result=result)
    assert out is not None
    assert "Amélie Roux" not in out
    assert "FR76 3000 4000 0512 3456 7890 143" not in out
    json.loads(out)  # still valid JSON


def test_clean_tool_result_is_left_alone() -> None:
    result = json.dumps({"content": "rien de personnel ici"})
    assert hermes.on_transform_tool_result(tool_name="read_file", result=result) is None


def test_non_string_result_is_ignored() -> None:
    assert hermes.on_transform_tool_result(tool_name="x", result={"a": 1}) is None


# -- outbound: provider payload ---------------------------------------------


def test_provider_payload_is_redacted_without_touching_ids(redactor) -> None:
    request = {
        "model": "claude-opus-5",
        "messages": [
            {"role": "user", "content": "écris à amelie.roux@example.fr"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_12345",
                        "type": "function",
                        "function": {
                            "name": "send",
                            "arguments": '{"to": "amelie.roux@example.fr"}',
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_12345", "content": "ok"},
        ],
        "tools": [{"function": {"name": "send", "description": "envoie à 12345"}}],
    }
    out = hermes.on_llm_request(request=request)
    assert out is not None
    new = out["request"]

    serialised = json.dumps(new, ensure_ascii=False)
    assert "amelie.roux@example.fr" not in serialised
    # Correlation ids and tool schemas must survive byte-identical.
    assert new["messages"][1]["tool_calls"][0]["id"] == "call_12345"
    assert new["messages"][2]["tool_call_id"] == "call_12345"
    assert new["tools"] == request["tools"]
    assert new["model"] == "claude-opus-5"


def test_payload_pass_is_deterministic_across_calls(redactor) -> None:
    """Byte-identical output on repeat = the provider prompt cache still hits."""
    request = {"messages": [{"role": "user", "content": "IBAN FR76 3000 4000 0512 3456 7890 143"}]}
    first = hermes.on_llm_request(request=request)["request"]
    second = hermes.on_llm_request(request=request)["request"]
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_clean_payload_is_not_rewritten() -> None:
    request = {"messages": [{"role": "user", "content": "bonjour"}]}
    assert hermes.on_llm_request(request=request) is None


# -- inbound: tool arguments -------------------------------------------------


def test_local_tool_gets_real_values_back(redactor) -> None:
    redacted = redactor.redact("écris à amelie.roux@example.fr").text
    token = TOKEN_RE.search(redacted).group(0)

    out = hermes.on_tool_request(
        tool_name="write_file",
        args={"path": "/tmp/a.txt", "content": f"destinataire: {token}"},
    )
    assert out is not None
    assert out["args"]["content"] == "destinataire: amelie.roux@example.fr"


def test_egress_tool_keeps_tokens(redactor) -> None:
    redacted = redactor.redact("écris à amelie.roux@example.fr").text
    token = TOKEN_RE.search(redacted).group(0)
    assert hermes.on_tool_request(tool_name="web_search", args={"query": token}) is None


def test_args_without_tokens_are_untouched() -> None:
    assert hermes.on_tool_request(tool_name="write_file", args={"path": "/tmp/a"}) is None


def test_protected_keys_are_never_rewritten(redactor) -> None:
    """A five-digit call id must not be mistaken for a postal code."""
    args = {"tool_call_id": "call_69007", "content": "code 69007"}
    new_args, _ = restore_args(redactor, args)
    assert new_args["tool_call_id"] == "call_69007"


# -- inbound: final answer ---------------------------------------------------


def test_final_answer_is_restored_for_the_user(redactor) -> None:
    redacted = redactor.redact("Titulaire : Amélie Roux").text
    token = TOKEN_RE.search(redacted).group(0)
    out = hermes.on_transform_llm_output(response_text=f"La titulaire est {token}.")
    assert out == "La titulaire est Amélie Roux."


def test_answer_without_tokens_is_left_alone() -> None:
    assert hermes.on_transform_llm_output(response_text="tout va bien") is None


def test_end_to_end_question_answer_keeps_functionality(redactor) -> None:
    """The user asks for an address; the model never sees it; the user gets it.

    This is the whole product in six lines.
    """
    document = "Adresse de facturation : 12 bis rue des Lilas, 69007 Lyon"
    seen_by_model = hermes.on_transform_tool_result(
        tool_name="read_file", result=json.dumps({"content": document}, ensure_ascii=False)
    )
    assert "rue des Lilas" not in seen_by_model

    address_token = TOKEN_RE.search(seen_by_model).group(0)
    model_answer = f"L'adresse de facturation est {address_token}."
    shown_to_user = hermes.on_transform_llm_output(response_text=model_answer)
    assert "12 bis rue des Lilas" in shown_to_user


# -- block mode --------------------------------------------------------------


def test_block_mode_refuses_egress_with_personal_data(redactor, monkeypatch) -> None:
    monkeypatch.setattr(
        redactor, "settings", dataclasses.replace(redactor.settings, block=True)
    )
    decision = hermes.on_pre_tool_call(
        tool_name="web_search", args={"query": "coordonnées de amelie.roux@example.fr"}
    )
    assert decision is not None and decision["action"] == "block"


def test_block_mode_allows_clean_egress(redactor, monkeypatch) -> None:
    monkeypatch.setattr(
        redactor, "settings", dataclasses.replace(redactor.settings, block=True)
    )
    assert hermes.on_pre_tool_call(tool_name="web_search", args={"query": "météo Lyon"}) is None


def test_block_mode_never_blocks_local_tools(redactor, monkeypatch) -> None:
    monkeypatch.setattr(
        redactor, "settings", dataclasses.replace(redactor.settings, block=True)
    )
    assert hermes.on_pre_tool_call(
        tool_name="write_file", args={"content": "amelie.roux@example.fr"}
    ) is None


def test_default_mode_does_not_block(redactor) -> None:
    assert hermes.on_pre_tool_call(
        tool_name="web_search", args={"query": "amelie.roux@example.fr"}
    ) is None


# -- egress policy -----------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["web_search", "WebSearch", "web.search", "browser_navigate", "firecrawl_scrape", "WebFetch"],
)
def test_egress_names_are_recognised_whatever_the_style(name: str) -> None:
    assert is_egress_tool(name) is True


@pytest.mark.parametrize("name", ["write_file", "read_file", "execute_code", "patch", "grep"])
def test_local_tools_are_not_egress(name: str) -> None:
    assert should_restore_args(name) is True


def test_policy_overrides_are_honoured() -> None:
    assert is_egress_tool("notes_sync", extra_egress={"notes_sync"}) is True
    assert is_egress_tool("web_search", forced_local={"web_search"}) is False


# -- Claude Code -------------------------------------------------------------


def test_claude_code_post_tool_use_replaces_output(redactor) -> None:
    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": "Titulaire : Amélie Roux",
    }
    out = claude_code.handle_event(event)
    specific = out["hookSpecificOutput"]
    assert specific["hookEventName"] == "PostToolUse"
    assert "Amélie Roux" not in specific["updatedToolOutput"]


def test_claude_code_pre_tool_use_restores_local_input(redactor) -> None:
    token = TOKEN_RE.search(redactor.redact("mail: jean@example.fr").text).group(0)
    out = claude_code.handle_event(
        {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"content": token}}
    )
    assert out["hookSpecificOutput"]["updatedInput"]["content"] == "jean@example.fr"


def test_claude_code_pre_tool_use_leaves_egress_alone(redactor) -> None:
    token = TOKEN_RE.search(redactor.redact("mail: jean@example.fr").text).group(0)
    out = claude_code.handle_event(
        {"hook_event_name": "PreToolUse", "tool_name": "WebSearch", "tool_input": {"query": token}}
    )
    assert out == {}


def test_claude_code_warns_on_prompt_it_cannot_rewrite(redactor) -> None:
    """Documented gap: UserPromptSubmit cannot replace the prompt text."""
    out = claude_code.handle_event(
        {"hook_event_name": "UserPromptSubmit", "prompt": "mon iban est FR76 3000 4000 0512 3456 7890 143"}
    )
    assert "systemMessage" in out


def test_claude_code_ignores_unknown_events() -> None:
    assert claude_code.handle_event({"hook_event_name": "Nope"}) == {}


# -- stdio server ------------------------------------------------------------


def test_stdio_roundtrip(redactor) -> None:
    source = io.StringIO(
        json.dumps({"op": "redact", "text": "mail jean@example.fr"}) + "\n"
    )
    sink = io.StringIO()
    stdio.serve(source, sink)
    response = json.loads(sink.getvalue().strip())
    assert response["ok"] is True
    assert "jean@example.fr" not in response["text"]

    token = TOKEN_RE.search(response["text"]).group(0)
    source = io.StringIO(json.dumps({"op": "restore", "text": token}) + "\n")
    sink = io.StringIO()
    stdio.serve(source, sink)
    assert json.loads(sink.getvalue().strip())["text"] == "jean@example.fr"


def test_stdio_reports_errors_without_dying(redactor) -> None:
    source = io.StringIO("not json\n" + json.dumps({"op": "nope"}) + "\n")
    sink = io.StringIO()
    stdio.serve(source, sink)
    lines = [json.loads(line) for line in sink.getvalue().splitlines()]
    assert lines[0]["ok"] is False and "invalid JSON" in lines[0]["error"]
    assert lines[1]["ok"] is False and "unknown op" in lines[1]["error"]


def test_stdio_refuses_to_restore_for_egress_tools(redactor) -> None:
    token = TOKEN_RE.search(redactor.redact("mail jean@example.fr").text).group(0)
    response = stdio.handle_request(
        {"op": "restore_args", "tool": "web_search", "args": {"q": token}}
    )
    assert response["changed"] is False
    assert response["args"]["q"] == token


def test_request_redaction_helper_reports_no_change_on_clean_input(redactor) -> None:
    request = {"messages": [{"role": "user", "content": "bonjour"}]}
    out, count = redact_request(redactor, request)
    assert count == 0 and out is request
