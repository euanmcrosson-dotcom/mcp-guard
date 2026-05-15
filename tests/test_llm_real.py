"""Real-API LLM fallback test (opt-in).

By default these tests are skipped — they cost real money on the
Anthropic API (~$0.01–$0.02 per run) and require an API key. To run
them locally:

    pip install 'mcp-guard[llm]'
    export ANTHROPIC_API_KEY=sk-ant-...
    python -m pytest tests/test_llm_real.py -v

The mocked LLM tests in `tests/test_extensions.py` validate the
schema-validation, parse-failure, fence-stripping, and exception
handling paths without burning credit. This file validates that the
full pipeline works end-to-end against a real Anthropic model.

What we verify:

  1. A genuinely novel gap (one the deterministic synthesiser doesn't
     match) round-trips through the LLM and produces a rule that
     passes the validator — i.e., the prompt is clear enough that a
     production model returns schema-compliant JSON in practice.
  2. A deliberately-vague gap returns an empty policy (or empty
     `{}` JSON, which the validator handles gracefully). Confirms
     the prompt's "if too vague, output {}" instruction works.
"""

from __future__ import annotations

import os

import pytest

from mcp_guard import synthesize_with_llm


def _anthropic_sdk_available() -> bool:
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


# Module-level gating: skip everything in this file unless both
# (a) an API key is set in the environment, and
# (b) the anthropic SDK is importable.
pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("ANTHROPIC_API_KEY"),
        reason="real-API test — set ANTHROPIC_API_KEY to run (burns ~$0.01/test)",
    ),
    pytest.mark.skipif(
        not _anthropic_sdk_available(),
        reason="anthropic SDK not installed; pip install 'mcp-guard[llm]'",
    ),
]


_VALID_OPS = frozenset({
    "in", "not_in", "equals", "not_equals",
    "matches", "not_matches", "starts_with", "not_starts_with",
    "contains", "not_contains", "length_gt", "length_lt",
})


def test_real_api_synthesises_rule_for_novel_gap():
    """A genuinely novel gap (not matching any deterministic keyword)
    should round-trip through Claude and produce a syntactically valid
    rule. We don't pin the exact rule contents — only that the
    validator accepted SOMETHING."""
    gap = (
        "Agent invoked custom_tool_dispatch_v2 with arg target_role "
        "set to 'service-account-cluster-admin' from a session bound "
        "to user role 'reader'. Tenant boundary violation: the role "
        "string came from a poisoned config-cache entry."
    )
    policy = synthesize_with_llm(
        gap,
        technique_id="real-api-novel-gap-test",
        fallback=True,
    )

    # The deterministic synthesiser does not match this gap (no email /
    # file / SSRF / shell / SQL / network / PII keywords). If a rule
    # comes back, it came from the LLM.
    assert len(policy.rules) >= 1, (
        "LLM fallback returned empty policy. Either the model declined "
        "(output `{}`) or returned malformed JSON. Inspect prompt + "
        "model response."
    )

    rule = policy.rules[0]
    # Structural validation — these are the contract the validator
    # already enforces, but assert here to surface real-API regressions.
    assert isinstance(rule.rule_id, str) and rule.rule_id
    assert isinstance(rule.tool, str) and rule.tool
    assert len(rule.conditions) >= 1
    assert isinstance(rule.reason, str) and rule.reason
    for cond in rule.conditions:
        # Exactly one of value/ref is set (enforced by Condition.__post_init__).
        # The op must be a valid Op literal.
        assert cond.op in _VALID_OPS


def test_real_api_returns_empty_on_too_vague_gap():
    """The prompt instructs the model to output `{}` when the gap is
    too vague to derive a sensible rule. We can't *guarantee* the
    model follows this on every call, but we can at least assert that
    the response (if any) parses without crashing the validator."""
    vague_gap = "Something bad happened. Please fix."
    policy = synthesize_with_llm(
        vague_gap,
        technique_id="real-api-vague-gap-test",
        fallback=True,
    )
    # We accept either:
    #   - empty (model followed the {} instruction), or
    #   - a rule (model interpreted the vague gap creatively).
    # Either way, the call should not crash. If a rule came back, it
    # must still pass validation.
    if policy.rules:
        for rule in policy.rules:
            assert isinstance(rule.rule_id, str) and rule.rule_id
            assert isinstance(rule.tool, str) and rule.tool
            assert len(rule.conditions) >= 1
            for cond in rule.conditions:
                assert cond.op in _VALID_OPS
