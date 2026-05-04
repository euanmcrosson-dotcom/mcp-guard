"""Synthesize a tool-call policy from an analysis gap.

The Engineer's first real job: given a gap (what failed, what was
abused) and the indicators recorded by the Attacker (which tool fired,
which arguments leaked), produce a `GeneratedPolicy` whose rules deny
the observed abuse pattern.

This is intentionally deterministic + pattern-based, not LLM-driven.
The mapping is small enough to enumerate, and a deterministic
synthesizer is unit-testable, debuggable from the audit log, and not
subject to model drift.

Adding new attack-class → rule mappings is the way this module grows.
LLM-driven synthesis can layer on top later for novel cases the
patterns don't cover; the deterministic path stays as a backstop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .policy import Condition, GeneratedPolicy, PolicyRule


# Lightweight gap representation — mcp_guard does not depend on
# purple's pydantic contracts. Callers pass either a GapDescription
# dataclass or use synthesize_from_text() for plain free-text input.
@dataclass(frozen=True)
class GapDescription:
    kind: str  # e.g. "no_telemetry", "telemetry_no_rule", "rule_misfire"
    detail: str
    proposed_fix_summary: str = ""


@dataclass(frozen=True)
class SynthesisInput:
    """Everything the synthesizer needs from observed runtime state."""

    gap: GapDescription
    indicators: list[str]
    technique_id: str


# ─── Public entrypoint ─────────────────────────────────────────────


def synthesize_from_text(
    detail: str,
    *,
    technique_id: str = "anonymous",
    kind: str = "telemetry_no_rule",
    proposed_fix_summary: str = "",
    indicators: list[str] | None = None,
) -> GeneratedPolicy:
    """Convenience: synthesize a policy from a free-text gap
    description. Indicator patterns are inferred from the text
    (substring scan for tool names + sensitive paths). Use the
    structured `synthesize(SynthesisInput(...))` entrypoint when you
    have richer signals from a probe."""
    auto_indicators: list[str] = list(indicators or [])
    detail_l = detail.lower()
    if "email.send" in detail_l or "send_email" in detail_l:
        auto_indicators.append("tool:email.send")
    if "attacker@" in detail_l or "@evil" in detail_l:
        for token in detail_l.replace(",", " ").replace(".", " ").split():
            if token.startswith("attacker@") or "@evil" in token:
                auto_indicators.append(f"argument:to={token}")
                break
    if "ssh" in detail_l or "id_rsa" in detail_l or ".aws" in detail_l:
        auto_indicators.append("tool:read_file")
        auto_indicators.append("argument:path=sensitive")
    return synthesize(
        SynthesisInput(
            gap=GapDescription(kind=kind, detail=detail,
                               proposed_fix_summary=proposed_fix_summary),
            indicators=auto_indicators,
            technique_id=technique_id,
        )
    )


def synthesize(inp: SynthesisInput) -> GeneratedPolicy:
    """Pattern-match the indicators + gap onto a policy.

    Strategy: look for known abuse signatures in the indicator stream
    and emit one rule per signature. If nothing matches, return an
    empty policy and let the orchestrator surface that as a synthesis
    miss (rather than a confidently-wrong rule)."""
    rules: list[PolicyRule] = []

    if _saw_email_send(inp.indicators):
        external_to = _extract_email_argument(inp.indicators)
        rules.append(_email_contact_allowlist_rule(inp.technique_id, external_to))

    if _saw_sensitive_file_read(inp.indicators):
        rules.append(_block_sensitive_file_read_rule(inp.technique_id))

    return GeneratedPolicy(rules=tuple(rules))


# ─── Pattern matchers on indicators ────────────────────────────────


def _saw_email_send(indicators: list[str]) -> bool:
    return any(
        ind.startswith("tool:email.send") or ind == "tool:send_email"
        for ind in indicators
    )


def _saw_sensitive_file_read(indicators: list[str]) -> bool:
    sensitive = (
        "~/.ssh/",
        "id_rsa",
        "id_ed25519",
        "~/.aws/",
        "credentials",
        "/etc/shadow",
    )
    return any(
        any(s in ind for s in sensitive) for ind in indicators
    )


def _extract_email_argument(indicators: list[str]) -> str | None:
    """Pull the recipient out of an `argument:to=...` indicator if
    present. Used purely for the rule's reason text — the rule itself
    does not hard-code the recipient."""
    for ind in indicators:
        m = re.match(r"argument:to=(.+)", ind)
        if m:
            return m.group(1).strip()
    return None


# ─── Rule constructors ─────────────────────────────────────────────


def _email_contact_allowlist_rule(
    technique_id: str, observed_to: str | None
) -> PolicyRule:
    sample = (
        f" (observed exfil attempt to {observed_to})"
        if observed_to
        else ""
    )
    return PolicyRule(
        rule_id=f"tool-policy-email-contact-allowlist--{_slug(technique_id)}",
        tool="send_email",
        conditions=(
            Condition(
                arg="to",
                op="not_in",
                ref="context.user.contacts",
            ),
        ),
        reason=(
            "External recipient outside the authenticated user's contact "
            f"list{sample}; treat as exfiltration attempt and deny."
        ),
    )


def _block_sensitive_file_read_rule(technique_id: str) -> PolicyRule:
    sensitive_pattern = r"(\.ssh/|id_rsa|id_ed25519|\.aws/|/etc/shadow|credentials)"
    return PolicyRule(
        rule_id=f"tool-policy-block-sensitive-file-read--{_slug(technique_id)}",
        tool="read_file",
        conditions=(
            Condition(arg="path", op="matches", value=sensitive_pattern),
        ),
        reason=(
            "Read of sensitive credential / private-key path. Likely "
            "result of cross-tool prompt injection — deny unconditionally."
        ),
    )


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-").lower()
