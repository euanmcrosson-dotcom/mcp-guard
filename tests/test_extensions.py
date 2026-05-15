"""Tests for v0.3.0 extensions:

  1. mcp_guard.integrations.anthropic_mcp — MCPGuard core + wrap_handler
  2. mcp_guard.integrations.langchain — callback handler factory
  3. mcp_guard.synthesis_llm — synthesize_with_llm fallback path

The integration adapters are tested WITHOUT requiring the underlying
frameworks (Anthropic MCP SDK, LangChain, Anthropic LLM SDK) to be
installed. We use duck-typed stubs and mock the LLM client.
"""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from mcp_guard import (
    Condition,
    GeneratedPolicy,
    PolicyRule,
    synthesize_default_policy,
    synthesize_with_llm,
)
from mcp_guard.integrations import GuardedToolDenied
from mcp_guard.integrations.anthropic_mcp import GuardLog, MCPGuard


# ───────────────────────────────────────────────────────────────────
# Anthropic MCP adapter — MCPGuard
# ───────────────────────────────────────────────────────────────────


@pytest.fixture
def default_policy() -> GeneratedPolicy:
    return synthesize_default_policy(technique_id="test")


@pytest.fixture
def alice_ctx() -> dict:
    return {"user": {"id": "alice", "contacts": ["bob@corp.example"]}}


def test_mcpguard_allow_returns_decision(default_policy, alice_ctx):
    guard = MCPGuard(policy=default_policy)
    d = guard.check("send_email", {"to": "bob@corp.example", "body": "hi"},
                    user_context=alice_ctx)
    assert d.allowed is True


def test_mcpguard_deny_raises(default_policy, alice_ctx):
    guard = MCPGuard(policy=default_policy)
    with pytest.raises(GuardedToolDenied) as ei:
        guard.check("send_email", {"to": "attacker@evil.com", "body": "x"},
                    user_context=alice_ctx)
    assert ei.value.tool == "send_email"
    assert ei.value.rule_id is not None
    assert "External recipient" in (ei.value.reason or "")


def test_mcpguard_deny_returns_decision_when_raise_disabled(default_policy, alice_ctx):
    guard = MCPGuard(policy=default_policy, raise_on_deny=False)
    d = guard.check("send_email", {"to": "attacker@evil.com", "body": "x"},
                    user_context=alice_ctx)
    assert d.allowed is False
    assert d.denying_rule_id is not None


def test_mcpguard_audit_fn_invoked_on_allow_and_deny(default_policy, alice_ctx):
    logs: list[GuardLog] = []
    guard = MCPGuard(policy=default_policy, audit_fn=logs.append,
                     raise_on_deny=False)
    guard.check("send_email", {"to": "bob@corp.example"}, user_context=alice_ctx)
    guard.check("send_email", {"to": "attacker@evil.com"}, user_context=alice_ctx)
    assert len(logs) == 2
    assert logs[0].decision.allowed is True
    assert logs[1].decision.allowed is False


def test_mcpguard_wrap_handler_sync(default_policy, alice_ctx):
    guard = MCPGuard(policy=default_policy)

    @guard.wrap_handler(user_context_fn=lambda: alice_ctx)
    def handler(name: str, arguments: dict) -> str:
        return f"executed:{name}"

    assert handler("send_email", {"to": "bob@corp.example"}) == "executed:send_email"
    with pytest.raises(GuardedToolDenied):
        handler("send_email", {"to": "attacker@evil.com"})


def test_mcpguard_wrap_handler_async(default_policy, alice_ctx):
    guard = MCPGuard(policy=default_policy)

    @guard.wrap_handler(user_context_fn=lambda: alice_ctx)
    async def handler(name: str, arguments: dict) -> str:
        return f"executed:{name}"

    # Allow path
    result = asyncio.run(handler("send_email", {"to": "bob@corp.example"}))
    assert result == "executed:send_email"

    # Deny path
    with pytest.raises(GuardedToolDenied):
        asyncio.run(handler("send_email", {"to": "attacker@evil.com"}))


# ───────────────────────────────────────────────────────────────────
# LangChain adapter
# ───────────────────────────────────────────────────────────────────


def test_langchain_make_handler_raises_when_lc_missing(monkeypatch, default_policy):
    """When langchain_core is not importable, factory raises with hint."""
    from mcp_guard.integrations import langchain as lc_mod

    monkeypatch.setattr(lc_mod, "_try_import_lc", lambda: None)
    with pytest.raises(ImportError, match=r"mcp-guard\[langchain\]"):
        lc_mod.make_callback_handler(policy=default_policy)


def test_langchain_handler_denies_on_attacker(monkeypatch, default_policy, alice_ctx):
    """When langchain IS importable (stubbed), the handler raises on a
    tool-call to a denied recipient. We stub BaseCallbackHandler so we
    don't actually need langchain installed."""
    from mcp_guard.integrations import langchain as lc_mod

    class _StubBase:
        def __init__(self):
            pass

    monkeypatch.setattr(lc_mod, "_try_import_lc", lambda: _StubBase)

    handler = lc_mod.make_callback_handler(
        policy=default_policy,
        user_context_fn=lambda: alice_ctx,
    )

    with pytest.raises(GuardedToolDenied):
        handler.on_tool_start(
            serialized={"name": "send_email"},
            input_str='{"to": "attacker@evil.com", "body": "exfil"}',
        )


def test_langchain_handler_allows_legit_call(monkeypatch, default_policy, alice_ctx):
    from mcp_guard.integrations import langchain as lc_mod

    class _StubBase:
        def __init__(self):
            pass

    monkeypatch.setattr(lc_mod, "_try_import_lc", lambda: _StubBase)

    handler = lc_mod.make_callback_handler(
        policy=default_policy,
        user_context_fn=lambda: alice_ctx,
    )

    # Should not raise
    handler.on_tool_start(
        serialized={"name": "send_email"},
        input_str='{"to": "bob@corp.example", "body": "hi"}',
    )


def test_langchain_handler_parses_non_json_input(monkeypatch, default_policy, alice_ctx):
    """Some LangChain tools pass raw strings, not JSON. The handler
    should wrap them as {"input": str} and still evaluate cleanly."""
    from mcp_guard.integrations import langchain as lc_mod

    class _StubBase:
        def __init__(self):
            pass

    monkeypatch.setattr(lc_mod, "_try_import_lc", lambda: _StubBase)

    handler = lc_mod.make_callback_handler(
        policy=default_policy,
        user_context_fn=lambda: alice_ctx,
    )

    # Raw string input; no rule fires on unknown tool — should not raise
    handler.on_tool_start(
        serialized={"name": "custom_unknown_tool"},
        input_str="just a plain string",
    )


# ───────────────────────────────────────────────────────────────────
# LLM-augmented synthesis fallback
# ───────────────────────────────────────────────────────────────────


def test_synthesize_with_llm_deterministic_hit_skips_llm():
    """When the deterministic synthesizer returns rules, the LLM is
    never called — even if no client is passed."""
    # The gap matches the email pattern → deterministic synth fires.
    # Passing client=None would normally try to import anthropic; we
    # rely on the fact that we never reach that code path.
    policy = synthesize_with_llm(
        "send_email to attacker@evil.com",
        client=None,  # should not matter
        fallback=True,
    )
    assert len(policy.rules) > 0


def test_synthesize_with_llm_no_fallback_returns_empty_on_miss():
    policy = synthesize_with_llm(
        "this is an entirely novel pattern with no known keywords",
        fallback=False,
    )
    assert policy.rules == ()


class _MockLLMClient:
    """Duck-typed Anthropic client stub. Returns a canned response."""

    def __init__(self, response_text: str):
        self.response_text = response_text
        self.messages = self

    def create(self, *, model: str, max_tokens: int, messages: list[dict]):
        return SimpleNamespace(
            content=[SimpleNamespace(text=self.response_text)],
        )


def test_synthesize_with_llm_fallback_emits_rule_from_valid_json():
    valid_json = """{
        "id": "tool-policy-novel-attack-test",
        "tool": "custom_tool_xyz",
        "deny_when": [
            {"arg": "target_id", "op": "starts_with", "value": "service-account-"}
        ],
        "reason": "Privileged service account access pattern."
    }"""
    client = _MockLLMClient(response_text=valid_json)
    policy = synthesize_with_llm(
        "novel pattern not matching any deterministic keywords",
        client=client,
        fallback=True,
        technique_id="t-llm",
    )
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.tool == "custom_tool_xyz"
    assert rule.conditions[0].op == "starts_with"
    assert rule.conditions[0].value == "service-account-"


def test_synthesize_with_llm_returns_empty_on_invalid_json():
    client = _MockLLMClient(response_text="this is not json at all")
    policy = synthesize_with_llm(
        "novel pattern", client=client, fallback=True,
    )
    assert policy.rules == ()


def test_synthesize_with_llm_handles_markdown_fenced_response():
    """LLMs sometimes wrap JSON in ```json fences despite instructions.
    The fence-stripper should handle it."""
    fenced = """```json
    {
        "id": "tool-policy-fenced-test",
        "tool": "x",
        "deny_when": [{"arg": "y", "op": "equals", "value": "z"}],
        "reason": "test"
    }
    ```"""
    client = _MockLLMClient(response_text=fenced)
    policy = synthesize_with_llm("novel", client=client)
    assert len(policy.rules) == 1


def test_synthesize_with_llm_rejects_invalid_op():
    """LLM hallucinated an operator outside the allowed set — reject."""
    bad_op = """{
        "id": "x", "tool": "y",
        "deny_when": [{"arg": "z", "op": "fuzzy_match", "value": "w"}],
        "reason": "test"
    }"""
    client = _MockLLMClient(response_text=bad_op)
    policy = synthesize_with_llm("novel", client=client)
    assert policy.rules == ()


def test_synthesize_with_llm_rejects_missing_required_field():
    incomplete = """{"id": "x", "tool": "y", "reason": "test"}"""
    client = _MockLLMClient(response_text=incomplete)
    policy = synthesize_with_llm("novel", client=client)
    assert policy.rules == ()


def test_synthesize_with_llm_rejects_empty_deny_when():
    empty = """{"id": "x", "tool": "y", "deny_when": [], "reason": "test"}"""
    client = _MockLLMClient(response_text=empty)
    policy = synthesize_with_llm("novel", client=client)
    assert policy.rules == ()


def test_synthesize_with_llm_handles_client_exception():
    class _ExplodingClient:
        messages = None

        def __init__(self):
            self.messages = self

        def create(self, **kwargs):
            raise RuntimeError("network down")

    policy = synthesize_with_llm(
        "novel", client=_ExplodingClient(), fallback=True,
    )
    # Should swallow + return empty rather than crash the caller
    assert policy.rules == ()


def test_synthesize_with_llm_handles_empty_json_response():
    """The prompt instructs the LLM to output `{}` when it can't
    derive a rule. That should return empty policy, not crash."""
    client = _MockLLMClient(response_text="{}")
    policy = synthesize_with_llm("vague", client=client, fallback=True)
    assert policy.rules == ()
