"""Anthropic MCP Python SDK adapter.

Provides a small `MCPGuard` object that you call from inside your MCP
server's `@server.call_tool()` handler. It evaluates the policy
against the tool call BEFORE the handler does any real work, and
raises `GuardedToolDenied` on a deny verdict so the handler short-
circuits cleanly.

We deliberately do NOT import the `mcp` package — this adapter is
duck-typed against the MCP SDK's tool-call shape (tool_name + args +
optional user-context dict). That way:

  - The core package keeps zero runtime deps.
  - The adapter is testable without installing the SDK.
  - The same shape works for any MCP-compatible server (Anthropic's
    Python SDK, the TypeScript SDK ported to Python, or a custom
    handler that follows the same protocol).

Usage with the official Anthropic MCP SDK:

    from mcp.server import Server
    from mcp_guard import synthesize_default_policy
    from mcp_guard.integrations.anthropic_mcp import MCPGuard

    server = Server("my-app")
    guard = MCPGuard(policy=synthesize_default_policy())

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        # Raises GuardedToolDenied if the policy denies the call.
        # Returns the Decision on allow so handlers can log it.
        guard.check(name, arguments, user_context=current_user_context())
        return await my_business_logic(name, arguments)

That's the whole integration. No middleware registration, no
monkey-patching, no inheritance.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..policy import Decision, GeneratedPolicy, evaluate
from . import GuardedToolDenied


@dataclass(frozen=True)
class GuardLog:
    """Structured log row emitted by `MCPGuard.check()` when an audit
    callback is configured. Persisted by callers however they like
    (stdout, a log line, a database, a kafka topic)."""

    tool: str
    args: dict[str, Any]
    user_context: dict[str, Any]
    decision: Decision


class MCPGuard:
    """Wrap a deterministic policy + optional audit callback for use
    inside an MCP server's tool-call handler.

    Construct once at server startup, share across handlers.

    :param policy: the GeneratedPolicy (typically `synthesize_default_policy()`)
    :param audit_fn: optional callback invoked on every check with a
                     `GuardLog` record. Use this to forward decisions to
                     a SIEM / audit log / metrics pipeline.
    :param raise_on_deny: when True (default), `check()` raises
                          `GuardedToolDenied`. When False, returns the
                          Decision so the caller can branch.
    """

    def __init__(
        self,
        policy: GeneratedPolicy,
        *,
        audit_fn: Callable[[GuardLog], None] | None = None,
        raise_on_deny: bool = True,
    ) -> None:
        self.policy = policy
        self.audit_fn = audit_fn
        self.raise_on_deny = raise_on_deny

    def check(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        user_context: dict[str, Any] | None = None,
    ) -> Decision:
        """Evaluate a tool call against the policy. Returns the Decision
        always. Raises `GuardedToolDenied` on deny when
        `raise_on_deny=True` (the default)."""
        ctx = user_context if user_context is not None else {}
        decision = evaluate(self.policy, tool_name, args, ctx)
        if self.audit_fn is not None:
            self.audit_fn(GuardLog(
                tool=tool_name,
                args=args,
                user_context=ctx,
                decision=decision,
            ))
        if not decision.allowed and self.raise_on_deny:
            raise GuardedToolDenied(
                tool=tool_name,
                args=args,
                rule_id=decision.denying_rule_id,
                reason=decision.reason,
            )
        return decision

    def wrap_handler(
        self,
        handler: Callable[..., Any] | None = None,
        *,
        user_context_fn: Callable[[], dict[str, Any]] | None = None,
    ) -> Callable[..., Any]:
        """Decorator. Two usage styles:

            @guard.wrap_handler
            async def call_tool(name, arguments): ...

            @guard.wrap_handler(user_context_fn=current_user_context)
            async def call_tool(name, arguments): ...

        Supports both sync and async handlers (auto-detected)."""
        if handler is None:
            # Parameterized form: return a decorator.
            def _decorator(h: Callable[..., Any]) -> Callable[..., Any]:
                return self.wrap_handler(h, user_context_fn=user_context_fn)
            return _decorator

        import functools
        import inspect

        if inspect.iscoroutinefunction(handler):
            @functools.wraps(handler)
            async def async_wrapped(name: str, arguments: dict, *a, **kw):
                ctx = user_context_fn() if user_context_fn else {}
                self.check(name, arguments, user_context=ctx)
                return await handler(name, arguments, *a, **kw)

            return async_wrapped

        @functools.wraps(handler)
        def sync_wrapped(name: str, arguments: dict, *a, **kw):
            ctx = user_context_fn() if user_context_fn else {}
            self.check(name, arguments, user_context=ctx)
            return handler(name, arguments, *a, **kw)

        return sync_wrapped
