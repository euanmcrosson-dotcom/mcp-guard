"""LlamaIndex adapter.

Two integration shapes — pick whichever fits your code:

  1. `make_callback_handler(policy, ...)` — returns a LlamaIndex
     `BaseCallbackHandler` that intercepts `CBEventType.FUNCTION_CALL`
     events before they execute. Wire into your agent / query engine
     via `Settings.callback_manager` or pass per-call.
  2. `wrap_tool(tool, policy, ...)` — monkey-wraps a `BaseTool`'s
     `.call()` method so policy enforcement happens at the tool level
     without needing a callback manager. Useful for ad-hoc tools.

Both raise `GuardedToolDenied` on a deny verdict.

Deferred import of `llama_index.core` so this module imports cleanly
without LlamaIndex installed; the factory raises with an install hint
when called.

Usage:

    from llama_index.core import Settings
    from llama_index.core.callbacks import CallbackManager
    from mcp_guard import synthesize_default_policy
    from mcp_guard.integrations.llamaindex import make_callback_handler

    handler = make_callback_handler(
        policy=synthesize_default_policy(),
        user_context_fn=lambda: {"user": {"id": current_user.id, ...}},
    )
    Settings.callback_manager = CallbackManager([handler])

    # ... your existing agent / query engine code; tool calls are now guarded.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ..policy import GeneratedPolicy, evaluate
from . import GuardedToolDenied


_INSTALL_HINT = (
    "llama_index.core is not installed. Install with:\n"
    "    pip install 'mcp-guard[llamaindex]'"
)


def _try_import_lli():
    """Return (BaseCallbackHandler, CBEventType, EventPayload) or None."""
    try:
        from llama_index.core.callbacks import (  # type: ignore
            BaseCallbackHandler,
            CBEventType,
            EventPayload,
        )
        return BaseCallbackHandler, CBEventType, EventPayload
    except ImportError:
        return None


def make_callback_handler(
    policy: GeneratedPolicy,
    *,
    user_context_fn: Callable[[], dict[str, Any]] | None = None,
    audit_fn: Callable[[str, dict, Any], None] | None = None,
):
    """Construct a LlamaIndex `BaseCallbackHandler` that enforces the
    given mcp-guard policy on every `FUNCTION_CALL` event.

    :param policy: the GeneratedPolicy to enforce
    :param user_context_fn: optional zero-arg callable returning the
                            user-context dict to pass to `evaluate()`
    :param audit_fn: optional `(tool_name, args, decision) -> None`
                     callback for telemetry / SIEM
    """
    imported = _try_import_lli()
    if imported is None:
        raise ImportError(_INSTALL_HINT)
    BaseCallbackHandler, CBEventType, EventPayload = imported

    class MCPGuardLlamaIndexHandler(BaseCallbackHandler):  # type: ignore[misc, valid-type]
        """LlamaIndex callback that denies tool calls failing the policy."""

        def __init__(self) -> None:
            super().__init__(
                event_starts_to_ignore=[],
                event_ends_to_ignore=[],
            )
            self.policy = policy
            self.user_context_fn = user_context_fn
            self.audit_fn = audit_fn

        def on_event_start(
            self,
            event_type: Any,
            payload: dict[str, Any] | None = None,
            event_id: str = "",
            parent_id: str = "",
            **kwargs: Any,
        ) -> str:
            if event_type != CBEventType.FUNCTION_CALL:
                return event_id
            tool_name, args_dict = _extract_tool_call(payload, EventPayload)
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
            return event_id

        def on_event_end(
            self,
            event_type: Any,
            payload: dict[str, Any] | None = None,
            event_id: str = "",
            **kwargs: Any,
        ) -> None:
            return None

        def start_trace(self, trace_id: str | None = None) -> None:
            return None

        def end_trace(self, trace_id: str | None = None, trace_map: Any = None) -> None:
            return None

    return MCPGuardLlamaIndexHandler()


def wrap_tool(
    tool: Any,
    policy: GeneratedPolicy,
    *,
    user_context_fn: Callable[[], dict[str, Any]] | None = None,
    audit_fn: Callable[[str, dict, Any], None] | None = None,
) -> Any:
    """Monkey-wrap a LlamaIndex `BaseTool`'s `.call()` method to enforce
    the policy at tool-call time.

    Works with any tool exposing `.call()` and a `.metadata.name` or
    `.name` attribute. The original tool is mutated in place and also
    returned for chaining.

    Use this when you don't have control of the agent's callback manager
    or want to scope policy enforcement to specific tools.
    """
    original_call = tool.call
    tool_name = _tool_name(tool)

    def guarded_call(*args: Any, **kwargs: Any) -> Any:
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
        return original_call(*args, **kwargs)

    tool.call = guarded_call
    return tool


def _extract_tool_call(payload: dict[str, Any] | None, EventPayload: Any) -> tuple[str, dict[str, Any]]:
    """Pull tool name + args out of a LlamaIndex FUNCTION_CALL payload.

    LlamaIndex's payload shape has evolved across versions; we accept
    several forms defensively and fall back to ('<unknown>', {})."""
    if not payload:
        return "<unknown>", {}

    # Tool name discovery — newer versions
    tool_meta = payload.get(EventPayload.TOOL) if hasattr(EventPayload, "TOOL") else None
    name = None
    if tool_meta is not None:
        name = getattr(tool_meta, "name", None) or (
            tool_meta.get("name") if isinstance(tool_meta, dict) else None
        )
    if name is None:
        name = payload.get("tool_name") or payload.get("name") or "<unknown>"

    # Args discovery — FUNCTION_CALL payload is typically the dict of args
    fc = payload.get(EventPayload.FUNCTION_CALL) if hasattr(EventPayload, "FUNCTION_CALL") else None
    if isinstance(fc, dict):
        return name, fc
    if isinstance(fc, str):
        try:
            parsed = json.loads(fc)
            if isinstance(parsed, dict):
                return name, parsed
        except (json.JSONDecodeError, ValueError):
            pass
        return name, {"input": fc}

    # Fall back to whatever args-shaped key exists
    for k in ("function_call", "arguments", "args"):
        v = payload.get(k)
        if isinstance(v, dict):
            return name, v
    return name, {}


def _tool_name(tool: Any) -> str:
    meta = getattr(tool, "metadata", None)
    if meta is not None:
        n = getattr(meta, "name", None)
        if isinstance(n, str):
            return n
    n = getattr(tool, "name", None)
    return n if isinstance(n, str) else "<unknown>"


def _coerce_args(args: tuple, kwargs: dict[str, Any]) -> dict[str, Any]:
    """LlamaIndex tools may be called with (input: str) or (**kwargs).
    Coerce to a flat dict so the evaluator sees the same shape every
    time."""
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
