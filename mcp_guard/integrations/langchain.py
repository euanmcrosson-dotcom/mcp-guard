"""LangChain adapter — `MCPGuardCallbackHandler`.

Hooks into LangChain's callback system to evaluate every tool call
through an mcp-guard policy. If the policy denies, raises
`GuardedToolDenied` from `on_tool_start`, which LangChain propagates
as a tool failure (the agent sees the deny reason and can adapt).

We do a deferred import of `langchain_core` so users who haven't
installed it can still `import mcp_guard.integrations.langchain`
without crashing. The error surfaces at handler-construction time
with an actionable message.

Usage:

    from langchain.agents import AgentExecutor
    from mcp_guard import synthesize_default_policy
    from mcp_guard.integrations.langchain import make_callback_handler

    handler = make_callback_handler(
        policy=synthesize_default_policy(),
        user_context_fn=lambda: {"user": {"id": current_user.id, ...}},
    )

    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        callbacks=[handler],   # ← mcp-guard sits in the callback chain
    )
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from uuid import UUID

from ..policy import GeneratedPolicy, evaluate
from . import GuardedToolDenied


_LANGCHAIN_INSTALL_HINT = (
    "langchain_core is not installed. Install with:\n"
    "    pip install 'mcp-guard[langchain]'"
)


def _try_import_lc():
    try:
        from langchain_core.callbacks import BaseCallbackHandler  # type: ignore
        return BaseCallbackHandler
    except ImportError:
        return None


def make_callback_handler(
    policy: GeneratedPolicy,
    *,
    user_context_fn: Callable[[], dict[str, Any]] | None = None,
    audit_fn: Callable[[str, dict, Any], None] | None = None,
):
    """Construct a LangChain `BaseCallbackHandler` that enforces the
    given mcp-guard policy on every tool call.

    :param policy: the GeneratedPolicy to enforce
    :param user_context_fn: optional zero-arg callable returning the
                            user-context dict to pass to `evaluate()`
    :param audit_fn: optional `(tool_name, args, decision) -> None`
                     callback for telemetry / SIEM
    """
    BaseCallbackHandler = _try_import_lc()
    if BaseCallbackHandler is None:
        raise ImportError(_LANGCHAIN_INSTALL_HINT)

    class MCPGuardCallbackHandler(BaseCallbackHandler):  # type: ignore[misc, valid-type]
        """LangChain callback that denies tool calls failing the policy."""

        def __init__(self) -> None:
            super().__init__()
            self.policy = policy
            self.user_context_fn = user_context_fn
            self.audit_fn = audit_fn

        # LangChain's BaseCallbackHandler signature for on_tool_start
        # (positional-only in some versions, keyword in others — we
        # accept *args/**kwargs and pluck what we need defensively).
        def on_tool_start(
            self,
            serialized: dict[str, Any],
            input_str: str,
            *args: Any,
            run_id: UUID | None = None,
            parent_run_id: UUID | None = None,
            tags: list[str] | None = None,
            metadata: dict[str, Any] | None = None,
            **kwargs: Any,
        ) -> None:
            tool_name = (serialized or {}).get("name") or (serialized or {}).get("id") or "<unknown>"
            args_dict = _parse_input_to_dict(input_str)
            ctx = self.user_context_fn() if self.user_context_fn else {}
            decision = evaluate(self.policy, tool_name, args_dict, ctx)
            if self.audit_fn is not None:
                self.audit_fn(tool_name, args_dict, decision)
            if not decision.allowed:
                raise GuardedToolDenied(
                    tool=tool_name,
                    args=args_dict,
                    rule_id=decision.denying_rule_id,
                    reason=decision.reason,
                )

    return MCPGuardCallbackHandler()


def _parse_input_to_dict(input_str: str) -> dict[str, Any]:
    """LangChain tools receive `input_str`, which by convention is
    either a JSON-encoded dict OR a single positional string. We try
    JSON first; on failure, wrap the raw string as `{"input": str}`
    so the evaluator still sees a dict shape."""
    if not isinstance(input_str, str):
        # Some LC versions already pass a dict-like input
        if isinstance(input_str, dict):
            return dict(input_str)
        return {"input": input_str}
    try:
        parsed = json.loads(input_str)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass
    return {"input": input_str}
