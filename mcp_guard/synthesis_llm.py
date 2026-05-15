"""LLM-augmented synthesis fallback.

The deterministic synthesiser (`synthesis.synthesize_from_text`)
covers a known set of attack-class patterns. For novel cases the
patterns don't recognise — say a previously-unseen exfil arg or an
ICS-protocol-specific abuse — it returns an empty policy. That's
correct behaviour for a deterministic system, but a deployed
defender often wants a "best-effort" rule.

`synthesize_with_llm()` adds an LLM fallback path. Flow:

    1. Try `synthesize_from_text(detail)`.
    2. If it returns at least one rule → return that, done.
    3. If it returns empty AND `fallback=True` → call Anthropic Claude
       with a structured prompt asking for ONE rule in JSON shape.
    4. Parse + validate the JSON. If parse fails, return empty policy
       (deliberate — we'd rather miss a rule than emit a malformed one).

The deterministic path is still the authority. The LLM is asked for
ONE rule, structured, and validated before being mixed into the
policy. The LLM cannot bypass the schema or invent new operators.

Optional dep: `pip install 'mcp-guard[llm]'` installs `anthropic`.

Usage:

    from mcp_guard import synthesize_with_llm

    # Deterministic patterns handle this; no LLM call.
    p1 = synthesize_with_llm("send_email to attacker@evil.com")
    assert len(p1.rules) > 0

    # Novel pattern → LLM fallback fires (if [llm] extra installed).
    p2 = synthesize_with_llm(
        "agent invoked custom_tool_xyz with arg target_id pointing "
        "to a privileged service account ID outside the user's tenant"
    )
"""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

from .policy import Condition, GeneratedPolicy, PolicyRule
from .synthesis import synthesize_from_text


_INSTALL_HINT = (
    "Anthropic SDK not installed. Install with:\n"
    "    pip install 'mcp-guard[llm]'"
)


# Schema-pinned prompt. We give the LLM ONLY the surface it can use,
# no creative latitude on the data model. The validator below rejects
# anything that doesn't fit.
_PROMPT_TEMPLATE = """\
You are a security policy synthesiser. The user observed the following
runtime gap in an MCP-using AI agent's tool calls. Your job: emit ONE
JSON policy rule that would deny the abuse pattern at the agent's
tool-call boundary.

The rule MUST conform to this exact JSON schema:

{{
  "id": "tool-policy-<descriptive-slug>-{technique_id}",
  "tool": "<MCP tool name being abused>",
  "deny_when": [
    {{
      "arg": "<argument path: bare name OR 'context.user.X'>",
      "op": "<one of: in, not_in, equals, not_equals, matches, not_matches, starts_with, not_starts_with, contains, not_contains, length_gt, length_lt>",
      "value": <literal value> | <int for length ops>
    }}
  ],
  "reason": "<one-sentence human-readable reason starting with the abuse class>"
}}

Conditions are AND-conjoined: the rule denies iff ALL conditions match.

Rules MUST:
  - Use a real argument name from the gap description.
  - Use `value` for literals or `ref` (e.g. 'context.user.contacts') for context refs.
  - NOT include both `value` and `ref` in the same condition.
  - Not invent operators outside the enumerated list.

OUTPUT FORMAT: Output ONLY the JSON object. No prose, no markdown
fences, no commentary. If the gap is too vague to derive a rule,
output exactly: {{}}

Gap description:
{detail}
"""


class _LLMClient(Protocol):
    """Minimal duck-typed interface for the LLM client. The Anthropic
    SDK's Client matches this; tests pass a stub."""

    def messages_create(self, *, model: str, max_tokens: int, messages: list[dict]) -> Any: ...


def synthesize_with_llm(
    detail: str,
    *,
    technique_id: str = "llm-fallback",
    fallback: bool = True,
    client: Any = None,
    model: str = "claude-sonnet-4-6",
    max_tokens: int = 800,
) -> GeneratedPolicy:
    """Synthesise a policy, falling back to an LLM for novel gap
    shapes the deterministic patterns don't match.

    :param detail: free-text gap description
    :param technique_id: included in the synthesised rule id for traceability
    :param fallback: if False, behaves identically to `synthesize_from_text`
    :param client: optional pre-constructed LLM client (defaults to
                   `anthropic.Anthropic()` from env). Tests pass a stub.
    :param model: Anthropic model identifier
    :param max_tokens: max response size (one rule is ~200 tokens)
    """
    deterministic = synthesize_from_text(detail, technique_id=technique_id)
    if deterministic.rules or not fallback:
        return deterministic

    rule = _call_llm_for_rule(detail, technique_id, client, model, max_tokens)
    if rule is None:
        return GeneratedPolicy()  # honest "no rule" on parse/validation failure
    return GeneratedPolicy(rules=(rule,))


def _call_llm_for_rule(
    detail: str,
    technique_id: str,
    client: Any,
    model: str,
    max_tokens: int,
) -> PolicyRule | None:
    if client is None:
        client = _default_anthropic_client()

    prompt = _PROMPT_TEMPLATE.format(technique_id=_slug(technique_id), detail=detail)

    try:
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception:
        return None

    text = _extract_text(response)
    if not text:
        return None

    return _parse_rule_json(text)


def _default_anthropic_client():
    try:
        import anthropic  # type: ignore
    except ImportError as e:
        raise ImportError(_INSTALL_HINT) from e
    return anthropic.Anthropic()


def _extract_text(response: Any) -> str | None:
    """Pull the text out of an Anthropic-shaped response. Defensive —
    handles SDK shape variations and test-stub shapes."""
    if response is None:
        return None
    # SDK shape: response.content[0].text
    content = getattr(response, "content", None)
    if isinstance(content, list) and content:
        first = content[0]
        text = getattr(first, "text", None)
        if isinstance(text, str):
            return text
    # Stub shape: response.content as a string
    if isinstance(content, str):
        return content
    # Stub shape: response is a dict
    if isinstance(response, dict):
        c = response.get("content")
        if isinstance(c, list) and c:
            t = c[0].get("text") if isinstance(c[0], dict) else None
            if isinstance(t, str):
                return t
        if isinstance(c, str):
            return c
    return None


def _parse_rule_json(raw: str) -> PolicyRule | None:
    """Parse the LLM's JSON output into a validated PolicyRule.
    Returns None on any parse / validation failure — empty policy is
    preferable to a malformed rule."""
    cleaned = _strip_markdown_fence(raw).strip()
    if cleaned in ("", "{}"):
        return None
    try:
        data = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    rule_id = data.get("id")
    tool = data.get("tool")
    deny_when = data.get("deny_when")
    reason = data.get("reason")
    if not (isinstance(rule_id, str) and isinstance(tool, str)
            and isinstance(deny_when, list) and isinstance(reason, str)):
        return None
    if not deny_when:
        return None
    try:
        conds = tuple(_validate_condition(c) for c in deny_when)
    except (KeyError, TypeError, ValueError):
        return None
    if any(c is None for c in conds):
        return None
    return PolicyRule(
        rule_id=rule_id,
        tool=tool,
        conditions=conds,  # type: ignore[arg-type]
        reason=reason,
    )


_VALID_OPS = frozenset({
    "in", "not_in", "equals", "not_equals",
    "matches", "not_matches", "starts_with", "not_starts_with",
    "contains", "not_contains", "length_gt", "length_lt",
})


def _validate_condition(c: Any) -> Condition | None:
    if not isinstance(c, dict):
        return None
    arg = c.get("arg")
    op = c.get("op")
    value = c.get("value")
    ref = c.get("ref")
    if not isinstance(arg, str) or op not in _VALID_OPS:
        return None
    has_value = value is not None
    has_ref = ref is not None
    if has_value == has_ref:
        return None  # need exactly one
    if has_ref and not isinstance(ref, str):
        return None
    try:
        return Condition(arg=arg, op=op, value=value, ref=ref)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return None


def _strip_markdown_fence(s: str) -> str:
    """LLMs sometimes wrap JSON in ```json ... ``` despite instructions.
    Strip the fence so the parser succeeds."""
    s = s.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    return s


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-").lower() or "unknown"
