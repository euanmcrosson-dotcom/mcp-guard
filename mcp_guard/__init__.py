"""mcp-guard: drop-in deterministic policy layer for MCP-using agents.

Synthesizes tool-call policies from observed indirect-injection
gaps, evaluates tool calls against those policies, and provides a
backtest harness for measuring false-positive rate against legitimate
traffic before deployment.

This is the defensive companion to `purple-scaffold`'s indirect-
injection probes. Findings from the probes feed into policy
synthesis; the resulting policy is what a product-side defender would
ship in front of the agent's tool-call boundary.

Quickstart:

    from mcp_guard import synthesize_from_text, evaluate, default_corpus, run_backtest

    # 1. Synthesize a policy from a free-text gap description.
    policy = synthesize_from_text(
        "agent emitted email.send to attacker@evil.com when user "
        "asked it to read a ticket",
        technique_id="lab-2026-05-04",
    )
    print(policy.to_yaml())

    # 2. Evaluate a tool call against the policy.
    decision = evaluate(
        policy,
        tool_name="send_email",
        args={"to": "attacker@evil.com"},
        user_context={"user": {"contacts": ["bob@corp"]}},
    )
    print(decision)  # Decision(allowed=False, denying_rule_id=..., reason=...)

    # 3. Backtest the policy against a fixture corpus.
    metrics = run_backtest(policy, default_corpus())
    print(f"FPR: {metrics.false_positive_rate:.4f}, "
          f"TPR: {metrics.true_positive_rate:.4f}")

CLI: see `mcp-guard --help`.
"""

from .policy import (
    Condition,
    Decision,
    GeneratedPolicy,
    PolicyRule,
    evaluate,
)
from .synthesis import (
    SynthesisInput,
    synthesize,
    synthesize_from_text,
)
from .backtest import (
    BacktestCase,
    BacktestFailure,
    BacktestMetrics,
    default_corpus,
    run_backtest,
)

__version__ = "0.1.0"

__all__ = [
    "Condition",
    "Decision",
    "GeneratedPolicy",
    "PolicyRule",
    "evaluate",
    "SynthesisInput",
    "synthesize",
    "synthesize_from_text",
    "BacktestCase",
    "BacktestFailure",
    "BacktestMetrics",
    "default_corpus",
    "run_backtest",
]
