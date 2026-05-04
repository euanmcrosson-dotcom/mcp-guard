# mcp-guard

Drop-in deterministic policy layer for MCP-using AI agents.

`mcp-guard` synthesises tool-call policies from observed indirect-
prompt-injection gaps, evaluates each tool call against those
policies at the agent's tool-call boundary, and provides a
backtest harness for measuring false-positive rate against
legitimate traffic before deployment.

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
pip install mcp-guard
```

(Python 3.11+. No runtime dependencies beyond the standard library.)

## Quickstart — Python API

```python
from mcp_guard import synthesize_from_text, evaluate, default_corpus, run_backtest

# 1. Synthesise a policy from a free-text gap description
policy = synthesize_from_text(
    "agent emitted send_email to attacker@evil.com when user "
    "asked it to read a ticket",
    technique_id="lab-2026-05-04",
)
print(policy.to_yaml())

# 2. Evaluate a tool call
decision = evaluate(
    policy,
    tool_name="send_email",
    args={"to": "attacker@evil.com"},
    user_context={"user": {"contacts": ["bob@corp.example"]}},
)
print(decision)
# Decision(allowed=False,
#          denying_rule_id='tool-policy-email-contact-allowlist--lab-2026-05-04',
#          reason='External recipient outside the authenticated user...')

# 3. Backtest against the default fixture corpus
metrics = run_backtest(policy, default_corpus())
print(f"FPR: {metrics.false_positive_rate:.4f}, "
      f"TPR: {metrics.true_positive_rate:.4f}")
# FPR: 0.2222, TPR: 0.5000
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

# Load policy at startup (YAML, dict, or programmatic)
policy: GeneratedPolicy = ...

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

For deployments behind an MCP server / agent framework, hook this
into the framework's tool-call middleware. Example wiring for
[`purple-scaffold`](https://github.com/euanmcrosson-dotcom/purple-scaffold)'s
test harness is in that repo's `purple/agents_atlas_live.py`.

## What kinds of gaps does the synthesiser cover?

The deterministic synthesiser is intentionally pattern-based and
small. Currently maps these gap shapes onto rules:

| Gap shape (free-text description matches) | Generated rule |
|---|---|
| `email.send` / `send_email` to attacker domain | Contact-allowlist rule on `send_email`'s `to` arg |
| Sensitive file read (`id_rsa`, `.aws`, `.ssh`) | Sensitive-path-block rule on `read_file`'s `path` arg |

For gap shapes not yet covered, the synthesiser returns an empty
policy (deliberate — we surface "no rule generated" rather than
fabricate a wrong rule). Adding a new gap shape is one
constructor + one test.

LLM-driven synthesis can layer on top later for novel cases the
patterns don't cover; the deterministic path stays as a backstop
because it's auditable from logs alone (no model required at
synthesis time).

## Backtest corpus

`default_corpus()` returns a 15-case fixture corpus of (tool_name,
args, user_context, expected_verdict) tuples covering:

- Legitimate emails to existing contacts (TN)
- Legitimate emails to first-time recipients (FP risk — included
  on purpose so the FPR is a real number, not 0)
- Legitimate non-email reads (`read_ticket`, `search_users`,
  benign `read_file`)
- Attack emails to external attacker domains (TP)
- Attack reads of `~/.ssh/id_rsa`, `.aws/credentials`,
  `/etc/shadow` (TP)

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
