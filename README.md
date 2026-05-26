# mcp-guard

[![PyPI](https://img.shields.io/badge/pypi-mcp--guardrails-blue.svg)](https://pypi.org/project/mcp-guardrails/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)
[![Tests: 97 passing (+2 opt-in)](https://img.shields.io/badge/tests-97_passing-success.svg)](tests/)
[![TPR: 1.00 / FPR: 0.01](https://img.shields.io/badge/TPR-1.00_%2F_FPR_0.01-success.svg)](#backtest-corpus)
[![Case studies: 6](https://img.shields.io/badge/case_studies-6-9cf.svg)](case_studies/)

Drop-in deterministic policy layer for MCP-using AI agents.

`mcp-guard` synthesises tool-call policies from observed indirect-
prompt-injection gaps, evaluates each tool call against those
policies at the agent's tool-call boundary, and provides a
backtest harness for measuring false-positive rate against
legitimate traffic before deployment.

> **v0.5.6:** 9 deterministic rule patterns across 122
> rules, **304-case backtest corpus**, TPR 1.00 / FPR 0.01. Four
> framework adapters: Anthropic MCP SDK, LangChain, LlamaIndex,
> CrewAI. LLM-augmented synthesis fallback (mock + real-API
> validated). **Six reproducible real-world [case studies](case_studies/)**:
> EchoLeak indirect injection, MCP tool-description poisoning,
> AWS IMDS SSRF, Log4Shell-class MCP logging, RAG context poisoning,
> agent self-prompting loops. See [CHANGELOG.md](CHANGELOG.md).

This is the defensive companion to the [`purple-scaffold`](https://github.com/euanmcrosson-dotcom/purple-scaffold)
research probes. Findings from those probes feed into policy
synthesis; the resulting policy is what a product-side defender
would ship in front of the agent's tool-call execution gate.

## Why

Most defenses against indirect prompt injection are
classifier-based: pre-process the model input or post-process
the model output, and use a model to decide whether something
looks suspicious. That's useful but probabilistic, hard to
audit, and adds latency.

`mcp-guard` takes the complementary deterministic-policy approach:

- **Synthesise** a policy from observed gaps (e.g., "agent emitted
  `read_text_file('~/.ssh/id_rsa')` after reading a poisoned
  file" → policy: deny `read_text_file` whose path matches a
  sensitive-credential pattern).
- **Evaluate** each tool call against the policy. Pure function:
  `(tool_name, args, user_context) -> Decision`. No I/O, no LLM,
  no ambiguity.
- **Backtest** the policy against a labelled corpus of legitimate
  + attack tool-call cases before deployment. Measure FPR / TPR.
  Iterate until both look acceptable.

The library is not meant to replace classifier-based defenses —
it complements them. Use both: classifier as an early-warning
signal, deterministic policy as the unconditional gate.

## Install

```bash
pip install mcp-guardrails
```

(Python 3.11+. No runtime dependencies beyond the standard library.)

> **Note on the name.** The PyPI distribution is `mcp-guardrails`
> (an unrelated dormant project squats `mcpguard` on PyPI, and
> the similarity check refuses `mcp-guard`). The Python import name
> stays `mcp_guard` so existing code continues to work. Same
> Pillow / PIL pattern. The GitHub repo, the in-code references,
> and the project identity stay `mcp-guard`.

Optional extras for the integrations you actually use:

```bash
pip install 'mcp-guardrails[anthropic-mcp]'   # for the Anthropic MCP SDK adapter
pip install 'mcp-guardrails[langchain]'       # for the LangChain callback handler
pip install 'mcp-guardrails[llamaindex]'      # for the LlamaIndex callback handler / wrap_tool
pip install 'mcp-guardrails[crewai]'          # for the CrewAI wrap_tool
pip install 'mcp-guardrails[llm]'             # for synthesize_with_llm fallback
pip install 'mcp-guardrails[all]'             # everything
```

## Quickstart — Python API

The fastest path to a shippable policy is `synthesize_default_policy()`,
which returns the full ruleset across every built-in pattern:

```python
from mcp_guard import synthesize_default_policy, evaluate, default_corpus, run_backtest

# 1. Load the full deterministic policy (9 patterns, 122 rules)
policy = synthesize_default_policy()

# 2. Evaluate any tool call against it
decision = evaluate(
    policy,
    tool_name="send_email",
    args={"to": "attacker@evil.com", "body": "exfil"},
    user_context={"user": {"contacts": ["bob@corp.example"]}},
)
print(decision)
# Decision(allowed=False,
#          denying_rule_id='tool-policy-email-contact-allowlist--send_email--default',
#          reason='External recipient outside the authenticated user...')

# 3. Backtest against the labelled corpus
metrics = run_backtest(policy, default_corpus())
print(f"TPR: {metrics.true_positive_rate:.4f}, "
      f"FPR: {metrics.false_positive_rate:.4f}")
# TPR: 1.0000, FPR: 0.0769
```

For incident-driven synthesis (one observed gap → narrowly-targeted
policy), use `synthesize_from_text()`:

```python
from mcp_guard import synthesize_from_text

# Synthesise from a free-text gap description
policy = synthesize_from_text(
    "agent emitted send_email to attacker@evil.com when user "
    "asked it to read a ticket",
    technique_id="lab-2026-05-04",
)
print(policy.to_yaml())
```

## Quickstart — CLI

```bash
# Synthesise a policy from gap text → YAML on stdout
mcp-guard synthesize "agent emitted send_email to attacker@evil.com" \
  > policy.yaml

# Evaluate a single tool call against the policy → JSON Decision on stdout
mcp-guard evaluate policy.yaml send_email '{"to":"attacker@evil.com"}' \
  --user-context '{"user":{"contacts":["bob@corp.example"]}}'

# Backtest against the default corpus → metrics JSON
mcp-guard backtest policy.yaml
```

## Wiring into your agent

The evaluator is pure, so you can wire it anywhere — most
naturally at the agent's tool-call boundary:

```python
from mcp_guard import evaluate, GeneratedPolicy

policy: GeneratedPolicy = synthesize_default_policy()

def on_tool_call_attempt(tool_name: str, args: dict, user_ctx: dict) -> bool:
    decision = evaluate(policy, tool_name, args, user_ctx)
    if not decision.allowed:
        log_audit(
            event="tool_call_denied",
            rule=decision.denying_rule_id,
            reason=decision.reason,
            tool=tool_name,
            args=args,
        )
        return False
    return True
```

### Anthropic MCP Python SDK

```python
from mcp.server import Server
from mcp_guard import synthesize_default_policy
from mcp_guard.integrations.anthropic_mcp import MCPGuard

server = Server("my-app")
guard = MCPGuard(policy=synthesize_default_policy())

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    # Raises GuardedToolDenied if the policy denies the call.
    guard.check(name, arguments, user_context=current_user_context())
    return await my_business_logic(name, arguments)
```

Or use the decorator form:

```python
@server.call_tool()
@guard.wrap_handler(user_context_fn=current_user_context)
async def call_tool(name: str, arguments: dict):
    return await my_business_logic(name, arguments)
```

### LangChain

```python
from langchain.agents import AgentExecutor
from mcp_guard import synthesize_default_policy
from mcp_guard.integrations.langchain import make_callback_handler

handler = make_callback_handler(
    policy=synthesize_default_policy(),
    user_context_fn=lambda: {"user": {"id": current_user.id,
                                       "contacts": current_user.contacts}},
)

executor = AgentExecutor(
    agent=agent, tools=tools,
    callbacks=[handler],   # ← mcp-guard sits in the callback chain
)
```

If the policy denies a tool call, the handler raises `GuardedToolDenied`
inside `on_tool_start`, which LangChain surfaces as a tool failure;
the agent's reasoning chain sees the deny reason and can adapt.

### LlamaIndex

```python
from llama_index.core import Settings
from llama_index.core.callbacks import CallbackManager
from mcp_guard import synthesize_default_policy
from mcp_guard.integrations.llamaindex import make_callback_handler

Settings.callback_manager = CallbackManager([
    make_callback_handler(
        policy=synthesize_default_policy(),
        user_context_fn=lambda: {"user": {...}},
    ),
])

# … your existing agent / query engine code; tool calls are now guarded.
```

Per-tool variant (no callback manager required):

```python
from mcp_guard.integrations.llamaindex import wrap_tool

guarded = wrap_tool(my_tool, policy=synthesize_default_policy())
```

### CrewAI

```python
from crewai import Agent
from mcp_guard import synthesize_default_policy
from mcp_guard.integrations.crewai import wrap_tools

agent = Agent(
    role="researcher",
    goal="answer the question",
    tools=wrap_tools(
        my_tools,
        policy=synthesize_default_policy(),
        user_context_fn=lambda: {"user": {...}},
    ),
)
```

`wrap_tool` is idempotent — re-wrapping is a no-op — so it's safe to
apply at agent-construction time without tracking which tools were
already guarded.

### LLM-augmented synthesis for novel gaps

The deterministic synthesiser covers 9 attack-class patterns. For
gap shapes none of them recognise, `synthesize_with_llm` adds an
LLM fallback path that calls Anthropic Claude with a schema-pinned
prompt and validates the response against the full PolicyRule
schema before emitting the rule:

```python
from mcp_guard import synthesize_with_llm

# Deterministic patterns handle this → no LLM call.
p1 = synthesize_with_llm("send_email to attacker@evil.com")

# Novel gap → falls back to Claude (requires [llm] extra)
p2 = synthesize_with_llm(
    "agent invoked custom_tool_xyz with arg target_id pointing to a "
    "privileged service account ID outside the user's tenant",
    fallback=True,
)
```

The validator rejects any response that doesn't match the
PolicyRule schema (invalid operator, missing fields, etc.) and
returns an empty policy on failure — better to miss a rule than
ship a malformed one.

## What kinds of gaps does the synthesiser cover?

The deterministic synthesiser is intentionally pattern-based and
auditable. As of v0.2.0, 9 attack classes map onto 122 rules in the
default policy:

| # | Attack class | What it denies | Tool families covered |
|---|---|---|---|
| 1 | Email contact exfil | `send_email` whose `to` arg is outside the user's `context.user.contacts` | 5 email tool names |
| 2 | Sensitive file read | `read_file` whose `path` matches `~/.ssh/`, `~/.aws/`, `/etc/shadow`, `kubeconfig`, etc. | 6 read tool names |
| 3 | Sensitive file write | `write_file` whose `path` matches `~/.bashrc`, `~/.ssh/authorized_keys`, `/etc/`, `/usr/bin/`, cron, `.git/config`, `.env`, etc. | 5 write tool names |
| 4 | Path traversal | Any path arg containing `../`, `..\`, URL-encoded variants (`%2e%2e`, `%2F`/`%5C`), double-encoded, Unicode division-slash | 17 file-path tool names |
| 5 | SSRF (private host) | `fetch_url` / `http_get` whose `url` targets RFC1918, loopback, link-local, AWS/GCP metadata, IPv6 unique-local | 6 HTTP tool names |
| 6 | Shell command danger | `shell_exec` / `bash` / `run_command` containing chaining (`;`, `&&`), pipe-to-shell, command substitution (`$()`, backticks), `rm -rf /`, `curl|sh`, fork bombs | 8 shell tool names × 5 arg names |
| 7 | SQL danger | `db_query` / `execute_sql` containing `DROP TABLE`, `TRUNCATE`, unbounded `DELETE`/`UPDATE`, `UNION SELECT`, `information_schema` probes, stacked queries, `xp_/sp_` exec, `LOAD_FILE`, `INTO OUTFILE` | 6 SQL tool names × 3 arg names |
| 8 | Network egress private | `tcp_connect` / `socket_connect` whose `host` is private/internal | 5 network tool names |
| 9 | Email body PII / secret exfil | `send_email` whose `body`/`subject` contains AWS keys, OpenAI/Anthropic keys, GitHub PATs, Slack tokens, private-key headers, SSN, JWT, credit-card numbers | 5 email tool names × 4 arg names |

For gap shapes not yet covered, the synthesiser returns an empty
policy (deliberate — we surface "no rule generated" rather than
fabricate a wrong rule). Adding a new gap shape is one
constructor + one test.

LLM-driven synthesis can layer on top later for novel cases the
patterns don't cover; the deterministic path stays as a backstop
because it's auditable from logs alone (no model required at
synthesis time).

## Backtest corpus

`default_corpus()` returns a **124-case** fixture corpus of (tool_name,
args, user_context, expected_verdict) tuples covering every built-in
pattern. v0.4.0 expanded coverage to: post-RCE env recon (env dump,
printenv, secret-keyword grep, secret-extension find), Windows
sensitive paths (Credentials manager, DPAPI keys, hosts file,
scheduled tasks, registry Run keys), Postgres COPY/pg_read_file
RCE, MySQL INTO DUMPFILE, MSSQL xp_cmdshell, jar://ftp://dict://
SSRF schemes, RSA/OpenSSH PEM headers, GitHub PATs, Slack tokens.

**v0.5.0 default-policy metrics:**

```
Corpus size:      304
TP (caught):      106 / 106 attacks   →  TPR 1.0000
FP (over-blocks):   2 / 198 legit     →  FPR 0.0101
```

The FPR drops as the legit denominator grows; the 2 FPs are still
the same architectural floor (legitimate first-time recipients
that contact-allowlist policies block by definition).

The 2 remaining FPs are architecturally inherent to contact-allowlist
policies (legitimate first-time recipients). They are kept in the
corpus on purpose so the FPR is a real number rather than a vanity
zero. Tune by adding allow-list conditions to `user_context` per
recipient class (e.g. distinguish "vendor onboarding" or "interview
candidate" tiers from generic external).

| Category | Legit cases | Attack cases |
|---|---|---|
| Email contact allowlist | 6 (4 in-contacts + 2 FP-risk) | 3 |
| Sensitive file read | 1 | 3 |
| Sensitive file write | 2 | 4 |
| Path traversal | 2 | 3 |
| SSRF | 3 | 4 |
| Shell danger | 3 | 5 |
| SQL danger | 3 | 5 |
| Network egress private | 2 | 3 |
| Email PII exfil | 2 | 5 |
| Misc legit (read_ticket / search_users) | 2 | — |

Real production deployments should replace `default_corpus()` with
a load from a labelled traffic store. The rest of the backtest
pipeline stays the same.

## Relationship to `purple-scaffold`

[`purple-scaffold`](https://github.com/euanmcrosson-dotcom/purple-scaffold)
is the offensive / measurement side: probes that test how
indirect-prompt-injection compliance varies across MCP server
vectors, models, and product wrappers. `mcp-guard` is the
defensive side: deterministic policies that catch the
attack patterns the probes find.

Both repos share the same evaluator core; `mcp-guard` is the
graduation of the policy modules from `purple-scaffold/purple/`
into a standalone package.

## License

MIT. See LICENSE.
