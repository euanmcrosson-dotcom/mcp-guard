"""mcp_guard.integrations — drop-in adapters for MCP server frameworks
and agent toolkits.

Each submodule is independent and only requires its underlying
framework to be installed. Use the corresponding optional-dependency
group from pyproject:

    pip install 'mcp-guard[anthropic-mcp]'     # adds: mcp
    pip install 'mcp-guard[langchain]'         # adds: langchain-core
    pip install 'mcp-guard[llm]'               # adds: anthropic (for synthesis fallback)
    pip install 'mcp-guard[all]'               # everything

The core `mcp_guard` package itself has zero runtime dependencies —
only adapters pull in framework deps.

Public surface lives on the submodules:

    from mcp_guard.integrations.anthropic_mcp import MCPGuard, GuardedToolDenied
    from mcp_guard.integrations.langchain import make_callback_handler
"""

from __future__ import annotations

__all__ = [
    "GuardedToolDenied",
]


class GuardedToolDenied(Exception):
    """Raised by adapter dispatch wrappers when the configured policy
    denies a tool call. Carries the offending tool name, the args, the
    rule id that denied, and the human reason — adapters propagate
    this from `evaluate()`'s Decision."""

    def __init__(
        self,
        *,
        tool: str,
        args: dict,
        rule_id: str | None,
        reason: str | None,
    ) -> None:
        self.tool = tool
        self.args = args
        self.rule_id = rule_id
        self.reason = reason
        super().__init__(
            f"mcp-guard denied tool {tool!r}: {reason or '(no reason)'} "
            f"[rule={rule_id or 'unknown'}]"
        )
