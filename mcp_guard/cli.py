"""mcp-guard CLI.

Three subcommands:

    mcp-guard synthesize "<gap text>"       — print a YAML policy
    mcp-guard evaluate <policy.yaml> <tool> <args.json>
                                            — score one tool call
    mcp-guard backtest <policy.yaml>        — run the default corpus

The policy YAML is the same shape produced by synthesize / consumed
by evaluate. To deploy: emit the YAML from synthesize, drop the
evaluator into your agent product's tool-call boundary, hand it the
policy + each candidate tool call. Decisions are pure (no I/O), so
the gate is fast and audit-loggable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .backtest import default_corpus, run_backtest
from .policy import (
    Condition,
    GeneratedPolicy,
    PolicyRule,
    evaluate,
)
from .synthesis import synthesize_from_text


def _policy_from_yaml(text: str) -> GeneratedPolicy:
    """Parse the YAML produced by GeneratedPolicy.to_yaml() back into
    a GeneratedPolicy. Implementing a tiny parser here to avoid
    pulling in PyYAML; the YAML shape mcp_guard emits is fixed and
    minimal so a hand parser is fine."""
    rules: list[PolicyRule] = []
    current_rule_id = None
    current_tool = None
    current_reason = ""
    current_conds: list[Condition] = []
    current_cond_args: dict[str, str] = {}

    def _flush_cond() -> None:
        if not current_cond_args:
            return
        arg = current_cond_args.get("arg", "")
        op = current_cond_args.get("op", "equals")
        if "value" in current_cond_args:
            current_conds.append(Condition(arg=arg, op=op,  # type: ignore[arg-type]
                                            value=current_cond_args["value"]))
        elif "ref" in current_cond_args:
            current_conds.append(Condition(arg=arg, op=op,  # type: ignore[arg-type]
                                            ref=current_cond_args["ref"]))
        current_cond_args.clear()

    def _flush_rule() -> None:
        nonlocal current_rule_id, current_tool, current_reason, current_conds
        _flush_cond()
        if current_rule_id and current_tool:
            rules.append(PolicyRule(
                rule_id=current_rule_id, tool=current_tool,
                conditions=tuple(current_conds), reason=current_reason,
            ))
        current_rule_id = None
        current_tool = None
        current_reason = ""
        current_conds = []

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if line.startswith("  - id:"):
            _flush_rule()
            current_rule_id = stripped[len("- id:"):].strip()
        elif line.startswith("    tool:"):
            current_tool = stripped[len("tool:"):].strip()
        elif line.startswith("    reason:"):
            v = stripped[len("reason:"):].strip()
            if v.startswith("'") and v.endswith("'"):
                v = v[1:-1].replace("''", "'")
            current_reason = v
        elif line.startswith("      - arg:"):
            _flush_cond()
            current_cond_args["arg"] = stripped[len("- arg:"):].strip()
        elif line.startswith("        op:"):
            current_cond_args["op"] = stripped[len("op:"):].strip()
        elif line.startswith("        value:"):
            v = stripped[len("value:"):].strip()
            if v.startswith("'") and v.endswith("'"):
                v = v[1:-1].replace("''", "'")
            current_cond_args["value"] = v
        elif line.startswith("        ref:"):
            current_cond_args["ref"] = stripped[len("ref:"):].strip()
    _flush_rule()
    return GeneratedPolicy(rules=tuple(rules))


def _cmd_synthesize(args: argparse.Namespace) -> int:
    policy = synthesize_from_text(
        args.detail,
        technique_id=args.technique_id,
        kind=args.kind,
    )
    print(policy.to_yaml())
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    policy = _policy_from_yaml(Path(args.policy).read_text(encoding="utf-8"))
    tool_args = json.loads(args.tool_args) if args.tool_args else {}
    user_context = json.loads(args.user_context) if args.user_context else {}
    decision = evaluate(policy, args.tool_name, tool_args, user_context)
    print(json.dumps({
        "allowed": decision.allowed,
        "denying_rule_id": decision.denying_rule_id,
        "reason": decision.reason,
    }, indent=2))
    return 0 if decision.allowed else 2


def _cmd_backtest(args: argparse.Namespace) -> int:
    policy = _policy_from_yaml(Path(args.policy).read_text(encoding="utf-8"))
    metrics = run_backtest(policy, default_corpus())
    print(json.dumps({
        "corpus_size": metrics.corpus_size,
        "tp": metrics.tp,
        "fp": metrics.fp,
        "tn": metrics.tn,
        "fn": metrics.fn,
        "false_positive_rate": metrics.false_positive_rate,
        "true_positive_rate": metrics.true_positive_rate,
        "matches_attack_sample": metrics.matches_attack_sample,
        "failures": [
            {"case_id": f.case_id, "expected": f.expected,
             "actual": f.actual, "denying_rule_id": f.denying_rule_id,
             "note": f.note}
            for f in metrics.failures
        ],
    }, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-guard")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_syn = sub.add_parser("synthesize", help="Synthesize a policy from gap text.")
    p_syn.add_argument("detail", help="Free-text description of the observed gap.")
    p_syn.add_argument("--technique-id", default="anonymous")
    p_syn.add_argument("--kind", default="telemetry_no_rule")
    p_syn.set_defaults(fn=_cmd_synthesize)

    p_eval = sub.add_parser("evaluate", help="Evaluate one tool call against a policy.")
    p_eval.add_argument("policy", help="Path to a policy YAML file.")
    p_eval.add_argument("tool_name")
    p_eval.add_argument("tool_args", help="JSON-encoded tool args. Use '{}' for none.")
    p_eval.add_argument("--user-context", default="{}", help="JSON-encoded user context.")
    p_eval.set_defaults(fn=_cmd_evaluate)

    p_bt = sub.add_parser("backtest", help="Backtest a policy against the default corpus.")
    p_bt.add_argument("policy", help="Path to a policy YAML file.")
    p_bt.set_defaults(fn=_cmd_backtest)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
