"""CrewAI adapter.

CrewAI exposes tools as instances of `crewai.tools.BaseTool` (or
subclasses) with a `_run(*args, **kwargs)` execution path. This adapter
wraps a tool's `_run()` so every invocation is checked against the
policy before the underlying work executes.

Usage:

    from crewai import Agent
    from crewai.tools import BaseTool
    from mcp_guard import synthesize_default_policy
    from mcp_guard.integrations.crewai import wrap_tool

    policy = synthesize_default_policy()

    my_tool = MyCustomTool()                       # subclass of BaseTool
    guarded_tool = wrap_tool(
        my_tool,
        policy=policy,
        user_context_fn=lambda: {"user": {"id": current_user.id, ...}},
    )

    agent = Agent(role=..., goal=..., tools=[guarded_tool])

The wrap is in-place (mutates the tool object) AND returns the tool
for chaining. The wrap is idempotent — calling `wrap_tool` twice on the
same tool will not double-wrap.

CrewAI evolved out of the LangChain tool-execution path historically,
so some CrewAI deployments can also use the LangChain callback handler
in `mcp_guard.integrations.langchain` directly. The `wrap_tool`
approach here is the CrewAI-native path that doesn't require the
LangChain callback manager.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ..policy import GeneratedPolicy, evaluate
from . import GuardedToolDenied


_GUARDED_ATTR = "_mcp_guard_wrapped"


def wrap_tool(
    tool: Any,
    policy: GeneratedPolicy,
    *,
    user_context_fn: Callable[[], dict[str, Any]] | None = None,
    audit_fn: Callable[[str, dict, Any], None] | None = None,
) -> Any:
    """Wrap a CrewAI tool's `_run` to enforce the policy on each call.

    Idempotent — re-wrapping is a no-op. Mutates the tool in place and
    returns it for chaining.

    :param tool: any object exposing `_run(*args, **kwargs)` and a
                 `.name` attribute (CrewAI's BaseTool shape)
    :param policy: GeneratedPolicy to enforce
    :param user_context_fn: optional zero-arg callable returning the
                            user-context dict
    :param audit_fn: optional `(tool_name, args, decision) -> None`
                     callback for telemetry
    """
    if getattr(tool, _GUARDED_ATTR, False):
        return tool

    if not hasattr(tool, "_run"):
        raise TypeError(
            f"{tool!r} is not a CrewAI-shaped tool: missing _run() method. "
            "wrap_tool expects an instance of crewai.tools.BaseTool or compatible."
        )

    tool_name = _tool_name(tool)
    original_run = tool._run

    def guarded_run(*args: Any, **kwargs: Any) -> Any:
        args_dict = _coerce_args(args, kwargs)
        ctx = user_context_fn() if user_context_fn else {}
        decision = evaluate(policy, tool_name, args_dict, ctx)
        if audit_fn is not None:
            audit_fn(tool_name, args_dict, decision)
        if not decision.allowed:
            raise GuardedToolDenied(
                tool=tool_name,
                args=args_dict,
                rule_id=decision.denying_rule_id,
                reason=decision.reason,
            )
        return original_run(*args, **kwargs)

    # Bind the wrapper. We assign directly on the instance so we don't
    # mutate the class; this keeps the wrap scoped to ONE tool instance.
    tool._run = guarded_run  # type: ignore[assignment]
    setattr(tool, _GUARDED_ATTR, True)
    return tool


def wrap_tools(
    tools: list[Any],
    policy: GeneratedPolicy,
    *,
    user_context_fn: Callable[[], dict[str, Any]] | None = None,
    audit_fn: Callable[[str, dict, Any], None] | None = None,
) -> list[Any]:
    """Convenience: apply `wrap_tool` to a list of tools in one call."""
    return [
        wrap_tool(t, policy, user_context_fn=user_context_fn, audit_fn=audit_fn)
        for t in tools
    ]


def _tool_name(tool: Any) -> str:
    n = getattr(tool, "name", None)
    if isinstance(n, str) and n:
        return n
    # CrewAI's BaseTool falls back to class name when .name isn't set
    return type(tool).__name__


def _coerce_args(args: tuple, kwargs: dict[str, Any]) -> dict[str, Any]:
    """CrewAI tools may be called positionally (single string input),
    via the Pydantic-validated `args_schema` (kwargs), or with a single
    dict. Coerce to a flat dict so the evaluator sees the same shape."""
    if kwargs:
        return dict(kwargs)
    if args:
        first = args[0]
        if isinstance(first, dict):
            return dict(first)
        if isinstance(first, str):
            try:
                parsed = json.loads(first)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass
            return {"input": first}
    return {}
