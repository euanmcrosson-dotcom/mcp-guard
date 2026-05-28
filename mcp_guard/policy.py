"""Tool-call policy: data model + evaluator.

A `GeneratedPolicy` is a list of `PolicyRule`s. Each rule names a tool,
a list of AND-conjoined `Condition`s on the call arguments and the
caller's context, and a reason string. A policy denies a call iff any
rule's tool matches AND all of that rule's conditions hold.

The evaluator is pure — given `(tool_name, args, user_context)` it
returns `(allowed, denying_rule_id_or_None, reason_or_None)`. This is
the function that:

  - Engineer uses inside the backtest harness to compute FPR/TPR
    against a corpus.
  - The lab target (or any production tool-call gateway) uses inline
    on every tool call.

YAML / dict serialization makes the synthesized policy diff-able,
PR-able, and storable next to the run record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Op = Literal[
    "not_in",
    "in",
    "equals",
    "not_equals",
    "matches",
    "not_matches",
    "starts_with",
    "not_starts_with",
    "contains",
    "not_contains",
    "length_gt",
    "length_lt",
]


@dataclass(frozen=True)
class Condition:
    """One AND-conjunct of a rule's deny predicate.

    `arg` is a dotted path into the call args ("to", "body.subject")
    OR a context path prefixed with "context." ("context.user.role").
    `op` is the comparison. `value` is a literal; `ref` is a dotted
    path into the user context (e.g. "user.contacts"). Exactly one of
    `value` / `ref` must be set.
    """

    arg: str
    op: Op
    value: Any | None = None
    ref: str | None = None

    def __post_init__(self) -> None:
        has_value = self.value is not None
        has_ref = self.ref is not None
        if has_value == has_ref:  # both set or neither set
            raise ValueError(
                f"Condition needs exactly one of value/ref (got "
                f"value={self.value!r}, ref={self.ref!r})"
            )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"arg": self.arg, "op": self.op}
        if self.value is not None:
            d["value"] = self.value
        if self.ref is not None:
            d["ref"] = self.ref
        return d


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    tool: str
    conditions: tuple[Condition, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "tool": self.tool,
            "deny_when": [c.to_dict() for c in self.conditions],
            "reason": self.reason,
        }


@dataclass(frozen=True)
class GeneratedPolicy:
    rules: tuple[PolicyRule, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {"rules": [r.to_dict() for r in self.rules]}

    def to_yaml(self) -> str:
        """Hand-rolled minimal YAML — avoids adding PyYAML dep for one
        serialization. Output is deterministic for diff stability."""
        lines: list[str] = ["rules:"]
        for rule in self.rules:
            lines.append(f"  - id: {rule.rule_id}")
            lines.append(f"    tool: {rule.tool}")
            lines.append("    deny_when:")
            for cond in rule.conditions:
                lines.append(f"      - arg: {cond.arg}")
                lines.append(f"        op: {cond.op}")
                if cond.value is not None:
                    lines.append(f"        value: {_yaml_scalar(cond.value)}")
                if cond.ref is not None:
                    lines.append(f"        ref: {cond.ref}")
            lines.append(f"    reason: {_yaml_scalar(rule.reason)}")
        return "\n".join(lines) + "\n"


# ─── Evaluator ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class Decision:
    allowed: bool
    denying_rule_id: str | None = None
    reason: str | None = None


def evaluate(
    policy: GeneratedPolicy,
    tool_name: str,
    args: dict[str, Any],
    user_context: dict[str, Any],
) -> Decision:
    """Pure evaluator. Iterates rules; first matching deny wins."""
    for rule in policy.rules:
        if rule.tool != tool_name:
            continue
        if all(_check(c, args, user_context) for c in rule.conditions):
            return Decision(
                allowed=False,
                denying_rule_id=rule.rule_id,
                reason=rule.reason,
            )
    return Decision(allowed=True)


def _any_leaf(left: Any, pred: Any) -> bool:
    """Apply scalar predicate `pred` to `left`, recursing through list / tuple
    / dict so a deny condition cannot be evaded by wrapping the offending
    value in a container. Returns True if ANY leaf satisfies `pred`.

    This closes the type/shape-confusion fail-open: a string deny op
    (`contains "@evil.com"`) used to return False — i.e. "do not deny" — the
    moment the arg was a list/dict instead of a str, so `to=["x@evil.com"]`
    sailed past `to contains "@evil.com"`. Recursing makes the gate see the
    value regardless of how it's wrapped. Used only on the POSITIVE
    (match-to-deny) ops; the negative allowlist ops keep whole-value
    semantics, because recursing those would let an attacker slip a
    disallowed value past by mixing it with an allowed one.
    """
    if isinstance(left, (list, tuple)):
        return any(_any_leaf(item, pred) for item in left)
    if isinstance(left, dict):
        return any(_any_leaf(v, pred) for v in left.values())
    return bool(pred(left))


def _check(cond: Condition, args: dict[str, Any], ctx: dict[str, Any]) -> bool:
    """True iff this condition's deny predicate holds — i.e. the call
    matches the deny criterion, contributing to a deny verdict when
    AND-conjoined with the rule's other conditions."""
    left = _resolve(cond.arg, args, ctx)
    right = (
        cond.value if cond.ref is None else _resolve(cond.ref, args, ctx)
    )
    if cond.op == "in":
        # Whole-value membership OR any leaf's membership (container-aware).
        return _safe_in(left, right) or _any_leaf(left, lambda x: _safe_in(x, right))
    if cond.op == "not_in":
        return not _safe_in(left, right)
    if cond.op == "equals":
        # Whole-value equality (preserves list==list) OR any leaf equals.
        return left == right or _any_leaf(left, lambda x: x == right)
    if cond.op == "not_equals":
        return left != right
    if cond.op == "matches":
        import re

        if not isinstance(right, str):
            return False
        return _any_leaf(left, lambda x: isinstance(x, str) and re.search(right, x) is not None)
    if cond.op == "not_matches":
        import re

        if not isinstance(left, str) or not isinstance(right, str):
            return False
        return re.search(right, left) is None
    if cond.op == "starts_with":
        if not isinstance(right, str):
            return False
        return _any_leaf(left, lambda x: isinstance(x, str) and x.startswith(right))
    if cond.op == "not_starts_with":
        if not isinstance(left, str) or not isinstance(right, str):
            return False
        return not left.startswith(right)
    if cond.op == "contains":
        if not isinstance(right, str):
            return False
        return _any_leaf(left, lambda x: isinstance(x, str) and right in x)
    if cond.op == "not_contains":
        if not isinstance(left, str) or not isinstance(right, str):
            return False
        return right not in left
    if cond.op == "length_gt":
        if not isinstance(left, (str, list, tuple, dict)) or not isinstance(right, int):
            return False
        return len(left) > right
    if cond.op == "length_lt":
        if not isinstance(left, (str, list, tuple, dict)) or not isinstance(right, int):
            return False
        return len(left) < right
    raise ValueError(f"Unknown op: {cond.op!r}")


def _resolve(path: str, args: dict[str, Any], ctx: dict[str, Any]) -> Any:
    """Resolve a dotted path. `context.X` reads from `ctx`; anything
    else reads from `args`. Returns None if any segment is missing."""
    if path.startswith("context."):
        target: Any = ctx
        segments = path[len("context.") :].split(".")
    else:
        target = args
        segments = path.split(".")
    for seg in segments:
        if not isinstance(target, dict) or seg not in target:
            return None
        target = target[seg]
    return target


def _safe_in(needle: Any, haystack: Any) -> bool:
    if haystack is None:
        return False
    try:
        return needle in haystack
    except TypeError:
        return False


def _yaml_scalar(value: Any) -> str:
    """Minimal YAML scalar emitter — quotes strings only when ambiguous."""
    if isinstance(value, str):
        if any(ch in value for ch in ":#\n'\"") or value.strip() != value:
            return "'" + value.replace("'", "''") + "'"
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    return repr(value)
