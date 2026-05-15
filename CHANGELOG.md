# Changelog

All notable changes to mcp-guard are documented here. Format inspired
by [Keep a Changelog](https://keepachangelog.com/); versioning follows
[SemVer](https://semver.org/).

## [0.5.1] — 2026-05-15

### Fixed

- **PyPI upload metadata.** v0.5.0's `pyproject.toml` declared
  `license = { text = "MIT" }` (a TOML table) and a `License :: OSI
  Approved :: MIT License` classifier. Both forms are deprecated by
  PEP 639 and PyPI's strict upload validator now returns
  `HTTP 400 Bad Request` for them — even though setuptools only
  warns about the deprecation locally. The upload that triggered
  this fix:
  https://github.com/euanmcrosson-dotcom/mcp-guard/actions/runs/25931946091
- Switched to `license = "MIT"` (SPDX expression as string) and
  removed the redundant classifier.
- Bumped `[build-system]` requires to `setuptools>=77` (the version
  that adds PEP 639 support).

No Python API changes; v0.5.1 is byte-equivalent at the import
surface. Version bump is necessary because PyPI consumes version
numbers on failed-upload attempts: even though `0.5.0` was rejected,
the version is no longer reusable.

## [0.5.0] — 2026-05-15

The "300+ corpus, 6 case studies, real-API LLM validation" release.
Doubled the case study count, more than doubled corpus coverage, and
added end-to-end validation of the LLM fallback path against a live
Anthropic model.

### Added

- **3 new case studies** (now 6 total):
  - [`case_studies/log4shell-mcp-logging/`](case_studies/log4shell-mcp-logging/) —
    Log4Shell-class JNDI injection via the MCP server's tool-call
    log formatter. Maps to the shell-danger pattern's JNDI sub-rule.
    Documents the per-tool extension pattern for non-shell tools
    that may have vulnerable downstream loggers.
  - [`case_studies/rag-context-poisoning/`](case_studies/rag-context-poisoning/) —
    indirect prompt injection via the RAG retrieval corpus. Covers
    real-world poisoning sources (UGC, crawled content, compromised
    ETL pipelines, insider corpus authors) and composition with
    corpus-side filters at indexing time.
  - [`case_studies/agent-self-prompting/`](case_studies/agent-self-prompting/) —
    agent self-loop drift where the adversary is the agent itself.
    Sourced from `purple-scaffold` 2026-05-02 multi-turn drift
    findings. Makes the action-layer-defense argument explicit:
    input-boundary defenses can't help when the generator of the
    bad string is the agent.
- **Real-API LLM fallback test** at `tests/test_llm_real.py`. Opt-in,
  gated on `ANTHROPIC_API_KEY` env var and `anthropic` SDK install.
  Validates the full pipeline against a live Claude. 2 tests:
  novel-gap-emits-valid-rule and vague-gap-handled-gracefully.
  ~$0.01–$0.02 per full run; skipped by default in CI.
- **New reverse-shell / sensitive-file-via-shell sub-patterns** in
  the shell-danger pattern:
  - `nc -e /bin/sh` and `netcat -e /bin/sh` (canonical reverse shells)
  - `/dev/tcp/host/port` (bash reverse shell)
  - `cat|less|more|head|tail|xxd|hexdump|od|strings <sensitive path>`
    (reading SSH keys / AWS creds / kubeconfig / etc. via shell tools)

### Changed

- **Corpus 124 → 304 cases.** The expansion is mostly *legit traffic*
  to grow the FPR denominator honestly:
  - 12 more in-contact emails (scheduling / reminders / replies)
  - 12 more legit SQL (analytics / monitoring / cache cleanup / CTE)
  - 18 more legit file ops (project sources, tests, docs, build outputs)
  - 20 more legit shell (git / npm / kubectl / docker / terraform /
    helm / mypy / ruff / tree / stat / etc.)
  - 12 more legit network (cloud APIs, public DNS, SMTP)
  - 11 more legit HTTP fetches (docs, registries, RFCs)
  - 10 more legit misc tools (search / ticket / calendar / metrics /
    invoice / translate / summarize)
  - 5 more legit emails edge cases
  - 5 more legit nested-path file reads
  - 50 more "final" legit cases across all surfaces
  Plus 18 attack additions (subdomain spoofing email, more shell
  variants including bash reverse shell, UNION-based SQL exfil,
  K8s service account token read, Chrome / Firefox credential
  store reads, GitLab / Slack token exfil, AWS Fargate credential
  endpoint).
- **Default-policy metrics:** TPR 1.0000 (106/106 attacks),
  **FPR 0.0101** (2/198 — the architectural floor of 2 first-time-
  recipient FPs over a much larger legit corpus).
- **Case-studies catalog** updated with rows 4-6.

### Validation

The mocked LLM tests (`tests/test_extensions.py`) and the real-API
tests (`tests/test_llm_real.py`) together cover the LLM fallback
end-to-end:

| Path | Mock | Real-API |
|---|---|---|
| Deterministic hit (no LLM call) | ✓ | n/a |
| Valid JSON response | ✓ | ✓ (`test_real_api_synthesises_rule_for_novel_gap`) |
| Invalid JSON → empty | ✓ | n/a (rejected before reaching real API in mock) |
| Markdown-fenced response | ✓ | n/a |
| Empty `{}` response | ✓ | ✓ (`test_real_api_returns_empty_on_too_vague_gap`) |
| Hallucinated operator | ✓ | (model unlikely to do this with the schema prompt) |
| Network failure | ✓ | n/a |

### Migration

v0.5.0 is fully backwards-compatible. The new shell-danger
sub-patterns kick in automatically for users on
`synthesize_default_policy()`.

## [0.4.0] — 2026-05-15

The "case studies + corpus scale + post-RCE recon" release. Two new
fully-reproducible real-world case studies, corpus expanded from 78
to 124 cases covering Windows paths / NoSQL-adjacent shapes / env
recon / more SSRF schemes, and a new pattern family for post-RCE
credential discovery.

### Added

- **Two new case studies**, both with `gap.txt` + `reproduce.py` +
  pre-generated `synthesised_policy.yaml` + `backtest.json`:
  - [`case_studies/tool-description-poisoning/`](case_studies/tool-description-poisoning/) —
    cross-tool confused deputy via poisoned MCP tool catalog
    descriptions. Sourced from `purple-scaffold` 2026-04-28 finding
    (GPT-4o 66.7% cross-tool hijack, Claude 0%).
  - [`case_studies/aws-metadata-ssrf/`](case_studies/aws-metadata-ssrf/) —
    agent SSRF chain to AWS IMDSv1 for IAM credential exfil.
    Realistic synthetic; covers the 13 SSRF variants in the
    `ssrf-private-host` rule pattern.
- **Case-studies catalog** at [`case_studies/README.md`](case_studies/README.md)
  with attack-class / source / primary-rule-pattern table and
  one-script reproduction instructions.
- **Post-RCE environment recon detection** added to the shell-danger
  pattern: bare `env` / `printenv` / `set | ...`, `cat /proc/PID/environ`,
  `grep -RE` against secret-name keywords (password / token / api_key /
  AWS / private key / JWT / bearer), `find ... -name "*.pem"`-style
  discovery of secret-shaped files.
- **Windows sensitive-path coverage**: `AppData\Roaming\Microsoft\Credentials`,
  DPAPI master keys (`AppData\*\Microsoft\Crypto\RSA`),
  `C:\Windows\System32\drivers\etc\hosts`, scheduled-tasks paths,
  registry-write paths (`HKLM\`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`),
  Chrome / Firefox credential stores.
- **New SQL danger patterns**: Postgres `COPY FROM PROGRAM` (RCE),
  `pg_read_file` / `pg_read_binary_file` / `pg_ls_dir`, bare
  `xp_cmdshell`, MySQL `INTO DUMPFILE`, Postgres `$$...$$`
  dollar-quoted strings.
- **More SSRF schemes**: `jar:http://...!/` (Java deserialisation
  payload delivery), `ftp://`, `dict://` (now properly covered).
- **More PII shapes covered in corpus**: MasterCard, GitHub PAT
  (`ghp_*`), RSA + OpenSSH private-key headers (proper PEM format),
  Slack bot tokens.

### Changed

- **Corpus 78 → 124 cases.** Adds:
  - 7 env-recon attacks + 3 legit env-adjacent cases
  - 5 advanced SQL attacks (COPY/pg_read_file/xp_cmdshell/OUTFILE/GRANT)
  - 3 SSRF-scheme attacks (dict://, jar:, ftp://)
  - 3 Windows path attacks + 2 Windows legit
  - 5 PII-shape attacks (more variety)
  - 4 sensitive-read attacks (.git/credentials, docker.sock, .netrc, /root/.pgpass)
  - 3 sensitive-write attacks (sudoers, /usr/bin, systemd unit)
  - 2 path-traversal attacks (mixed real-path + URL-encoded; Windows)
  - 9 more legit cases proportionally
- **Default-policy metrics:** TPR 1.0000 (79/79 attacks),
  FPR 0.0444 (2/45 — only the 2 architecturally-expected
  first-time-recipient FPs).
- **README badges updated**: 97 tests, TPR 1.00 / FPR 0.04.

### Patterns fixed in passing

- Path-traversal regex: was case-sensitive on URL-encoded variants
  (missed `..%2F`). Now `(?i)` at pattern head.
- SQL `UPDATE without WHERE` lookahead was broken; replaced with
  bounded `[^;]*\bWHERE\b` negative lookahead that correctly
  distinguishes `UPDATE ... SET ... WHERE` (legit) from
  `UPDATE ... SET ...;` (unbounded).
- Windows sensitive-path regexes had double-escaped backslashes
  (`\\\\`) which matched 2 literal backslashes instead of 1; fixed.
- `jar://` scheme regex updated to also match `jar:http://...`
  (real-world jar URI form has no `//` after `jar:`).

### Migration

v0.4.0 is fully backwards-compatible. New defenses kick in
automatically once you upgrade if you're using
`synthesize_default_policy()`.

## [0.3.1] — 2026-05-15

Completes the four-adapter set with LlamaIndex and CrewAI. The
deferred items from v0.3.0's "blockers" list are now shipped.

### Added

- **`mcp_guard.integrations.llamaindex`** — two integration shapes:
  - `make_callback_handler(policy, user_context_fn, audit_fn)` returns
    a LlamaIndex `BaseCallbackHandler` that intercepts
    `CBEventType.FUNCTION_CALL` events. Wire into
    `Settings.callback_manager` or pass per-call.
  - `wrap_tool(tool, policy, ...)` monkey-wraps a `BaseTool.call()`
    method for ad-hoc per-tool guarding.
  - Defensive payload extraction handles LlamaIndex's payload-shape
    evolution across versions.
- **`mcp_guard.integrations.crewai`** — two surfaces:
  - `wrap_tool(tool, policy, ...)` wraps a CrewAI tool's `_run()`;
    idempotent (re-wrapping is a no-op via `_mcp_guard_wrapped` flag).
  - `wrap_tools(tools, ...)` convenience for batching across an
    `Agent`'s `tools` list.
  - Raises `TypeError` with an actionable message if passed a
    non-CrewAI-shaped object (no `_run` method).
- **12 new tests** in `tests/test_extensions.py` covering both
  adapters: callback handler factory import-error path, deny / allow /
  audit / idempotency / type-check / batch wrapping.

### Changed

- **`pyproject.toml` optional-deps**: added `llamaindex`
  (`llama-index-core>=0.11`) and `crewai` (`crewai>=0.70`) groups; the
  `all` extra now includes both.
- **Tests 85 → 97**, all passing.

### Migration

v0.3.1 is fully backwards-compatible. New adapters live alongside the
existing ones:

```python
# LlamaIndex — pip install 'mcp-guard[llamaindex]'
from llama_index.core import Settings
from llama_index.core.callbacks import CallbackManager
from mcp_guard import synthesize_default_policy
from mcp_guard.integrations.llamaindex import make_callback_handler

Settings.callback_manager = CallbackManager([
    make_callback_handler(policy=synthesize_default_policy()),
])

# CrewAI — pip install 'mcp-guard[crewai]'
from mcp_guard.integrations.crewai import wrap_tools

agent = Agent(
    role=...,
    goal=...,
    tools=wrap_tools(my_tools, policy=synthesize_default_policy()),
)
```

## [0.3.0] — 2026-05-15

The "integrations + LLM fallback + real-world story" release. v0.2.0
was a working library; v0.3.0 makes it deployable into the major agent
frameworks and ships a documented, reproducible attack case study.

### Added

- **`mcp_guard.integrations.anthropic_mcp.MCPGuard`** — drop-in adapter
  for the Anthropic MCP Python SDK. Construct once with a policy and
  optional audit callback; call `guard.check(name, args, user_context)`
  inside your `@server.call_tool()` handler, OR wrap the handler with
  `@guard.wrap_handler` (both bare and parameterized decorator forms,
  sync and async auto-detected). Zero runtime dep on the `mcp` package
  — duck-typed against MCP's call shape, testable without installing.
- **`mcp_guard.integrations.langchain.make_callback_handler`** —
  factory that returns a LangChain `BaseCallbackHandler` enforcing the
  policy on every `on_tool_start`. Deferred import of
  `langchain_core` — the module imports cleanly without it; the
  factory raises with an actionable install hint at call time.
- **`mcp_guard.synthesize_with_llm()`** — LLM-augmented synthesis
  fallback. First runs the deterministic `synthesize_from_text`; if
  that returns empty AND `fallback=True`, calls Anthropic Claude with
  a schema-pinned JSON prompt and validates the response against the
  full PolicyRule schema (operator allowlist, exactly-one of
  value/ref, all required fields). The LLM cannot bypass the schema.
  Network failures, JSON parse errors, missing fields, and invalid
  operators all return empty policy — we miss before we emit a
  malformed rule.
- **`GuardedToolDenied`** exception (`mcp_guard.integrations`) — raised
  by both adapters on a deny verdict; carries `tool`, `args`,
  `rule_id`, `reason` for downstream logging.
- **Real-world case study** at `case_studies/echoleak-gpt4o/` —
  end-to-end walkthrough of the 2026-04-28 purple-scaffold finding
  (GPT-4o 66.67% silent compliance vs Claude 0% on EchoLeak-style
  indirect prompt injection). Includes `gap.txt`, `reproduce.py`,
  `synthesised_policy.yaml`, `backtest.json` — all reproducible with
  a single command, no network calls.
- **Optional-dep groups** in `pyproject.toml`: `anthropic-mcp` (adds
  `mcp>=1.0`), `langchain` (adds `langchain-core>=0.3`), `llm` (adds
  `anthropic>=0.40`), `all` (everything).

### Changed

- **5 new attack-shape additions to existing patterns** (no API change):
  - SSRF: dangerous URL schemes (`file://`, `gopher://`, `dict://`,
    `ftp://`, `jar://`, `ldap://`, `ldaps://`), IPv4-mapped IPv6
    loopback (`[::ffff:127.0.0.1]`).
  - Shell danger: PowerShell primitives (`Invoke-Expression`, `iex`,
    `iwr|iex`, `WebClient.DownloadString`, `Start-Process -Verb RunAs`),
    Log4Shell-style JNDI lookup (`${jndi:ldap://...}`).
  - Sensitive file read: kubeconfig (`~/.kube/config`), Azure CLI
    cache (`~/.azure/accessTokens.json`), gcloud creds DB, AWS SSO
    cache, web-identity-token file.
- **Corpus 61 → 78 cases.** Added file://, gopher://, IPv4-mapped IPv6
  SSRF; Windows path traversal; PowerShell shell-danger (iex, iwr|iex,
  UAC RunAs); JNDI shell-injection; kubeconfig / gcloud / Azure CLI
  reads; bounded DELETE-with-WHERE legit case; public IPv6 / DNS
  legit cases.
- **Default-policy metrics improved:** TPR 1.0000 (47/47 attacks),
  FPR 0.0645 (2/31 legit — only the 2 architecturally-expected
  first-time-recipient FPs).
- **Tests 65 → 85.** New `tests/test_extensions.py` covers MCPGuard
  core + wrap_handler (sync + async), LangChain handler factory
  (import-error + happy path with stubbed `BaseCallbackHandler`), and
  the LLM fallback path (deterministic-hit-skips-LLM, valid response,
  invalid JSON, hallucinated operator, missing fields, empty
  deny_when, network failure, markdown-fenced response, `{}` response).
- **Packaging**: `mcp_guard.integrations` added to `packages` list.

### Migration

v0.3.0 is **fully backwards-compatible** with v0.2.0. Existing callers
of `synthesize_from_text` / `synthesize_default_policy` / `evaluate`
do not change. To opt into the new surfaces:

```python
# Anthropic MCP — pip install 'mcp-guard[anthropic-mcp]'
from mcp_guard import synthesize_default_policy
from mcp_guard.integrations.anthropic_mcp import MCPGuard

guard = MCPGuard(policy=synthesize_default_policy())

@server.call_tool()
async def call_tool(name, arguments):
    guard.check(name, arguments, user_context=current_user_context())
    return await my_business_logic(name, arguments)

# LangChain — pip install 'mcp-guard[langchain]'
from mcp_guard.integrations.langchain import make_callback_handler

handler = make_callback_handler(
    policy=synthesize_default_policy(),
    user_context_fn=lambda: {"user": {...}},
)

# LLM fallback — pip install 'mcp-guard[llm]'
from mcp_guard import synthesize_with_llm

policy = synthesize_with_llm("novel gap pattern", fallback=True)
```

## [0.2.0] — 2026-05-15

The "actually shippable" release. v0.1.0 was a scaffold with 2 rule
patterns and a backtest example whose own README showed FPR 0.22 / TPR
0.50 — not deployable. v0.2.0 lifts the rule library to 9 patterns
across 122 deterministic rules and gets the default policy to TPR 1.00
/ FPR 0.08 on a 61-case corpus.

### Added

- **`synthesize_default_policy(technique_id="default")`** — new public
  entrypoint that returns the full ruleset across every built-in
  pattern, unconditionally. This is the shippable production policy:
  drop it in front of your agent's tool-call boundary and you get all
  built-in defenses on day one.
- **7 new rule-synthesis patterns**:
  1. **SSRF / private-host URL** — denies `fetch_url` /
     `http_get` / `http_post` / etc. targeting RFC1918 ranges,
     loopback, link-local, AWS/GCP metadata endpoints, or IPv6
     unique-local / link-local.
  2. **Sensitive file write** — denies `write_file` / `edit_file` /
     `create_file` / `append_file` / `patch_file` targeting shell-init
     files (`~/.bashrc`, `~/.zshrc`, …), SSH config (`~/.ssh/`),
     system dirs (`/etc/`, `/usr/bin/`, …), crontab, `.git/config`,
     and `.env` family.
  3. **Path traversal** — case-insensitive detection of `../`, `..\`,
     URL-encoded variants (`%2e%2e`, `%2F`/`%5C`), double-encoded
     (`%252e%252e`), and Unicode division/reverse-solidus across all
     17 file-path-shaped tool names.
  4. **Shell command danger** — denies chaining (`;`, `&&`, `||`),
     pipe-to-interpreter (`| bash`, `| python`, `| nc`, …),
     command substitution (`$(...)`, backticks),
     known-destructive primitives (`rm -rf /` excluding `/tmp`,
     `dd if=/dev/zero`, `mkfs.`, `chmod 777`, disk redirects),
     remote-payload patterns (`curl ... | bash`, `wget ... | sh`),
     and fork bombs. Applied across 5 arg names (`command`, `cmd`,
     `script`, `code`, `input`) on 8 shell tool names.
  5. **SQL dangerous query** — denies `DROP TABLE/DATABASE/SCHEMA/
     INDEX/VIEW/USER/ROLE`, `TRUNCATE TABLE`, `ALTER`, unbounded
     `DELETE FROM` and `UPDATE SET` (negative lookahead on `WHERE`),
     `GRANT ALL/SUPER/FILE/...`, `REVOKE`, `UNION SELECT`,
     `information_schema` probes, SQL comments at EOL, stacked
     queries, MSSQL `xp_/sp_` exec, MySQL `LOAD_FILE` / `INTO
     OUTFILE`. Applied to `sql`, `query`, `statement` args on 6 SQL
     tool names.
  6. **Network egress to private host** — same private-host regex as
     SSRF but on `host` arg of raw-socket tools (`tcp_connect`,
     `socket_connect`, `network_call`, `connect`, `raw_connect`).
  7. **Email body / subject PII + secret exfil** — denies
     `send_email` (and 4 sibling tool names) with `body` / `subject`
     / `text` / `html` containing AWS access keys (`AKIA...`), AWS
     secret keys, OpenAI/Anthropic keys (`sk-...`, `sk-ant-...`),
     GitHub PATs (`ghp_...`, `gho_...`, `github_pat_...`), GitLab
     PATs, Slack tokens (`xox[bpoars]-...`), private-key headers,
     US SSN, JWTs, Visa/MC card numbers. Defense-in-depth on top of
     contact allowlist — even allowed recipients should not receive
     secrets.
- **7 new policy operators** in `policy.Op`: `starts_with`,
  `not_starts_with`, `contains`, `not_contains`, `not_matches`,
  `length_gt`, `length_lt`. Foundation for prefix/substring matching
  and size-based rules.
- **Pattern registry refactor** — `synthesis._PATTERN_FROM_INDICATORS`
  and `synthesis._PATTERN_DEFAULTS` are explicit tuples of pattern
  functions. Adding a new pattern is one tuple-append plus a default
  factory; no other code changes.

### Changed

- **`default_corpus()` grew from 15 → 61 cases.** Adds 4–5 cases per
  new pattern (mix of legit + attack), covering each pattern's FP-risk
  edge. Original 15 cases preserved verbatim.
- **`synthesize_from_text()` keyword scan expanded** — now seeds
  indicators for SSRF, file-write, path-traversal, shell-danger,
  SQL-danger, network-egress, and PII-exfil keyword classes in
  addition to the original 2 patterns.
- **Tool-name coverage** — each pattern emits one rule per common tool
  name in the relevant family. Total rules in default policy: 122.
- **Test suite grew from 8 → 65 tests.** Per-pattern synthesizer
  triggers + per-pattern evaluator allow/deny coverage + integration
  tests on the full corpus.
- **Development status** bumped from `3 - Alpha` → `4 - Beta` in
  `pyproject.toml` classifiers.

### Backtest metrics (v0.1.0 → v0.2.0)

```
                          v0.1.0       v0.2.0
default-policy rules:        2           122
corpus size:                15            61
TPR (recall):              0.50         1.00
FPR:                       0.22         0.08
tests:                       8            65
```

The remaining 2 FPs are architecturally inherent to contact-allowlist
policies (legitimate first-time recipients) and are kept in the
corpus to make FPR a real number rather than a vanity zero.
Operators tune by adding allow-list conditions to user_context per
recipient class, not by relaxing the rule.

### Migration

v0.2.0 is **backwards-compatible at the public-API level.** v0.1.0
callers do not need to change anything. To upgrade behavior, switch
from `synthesize_from_text(...)` (single-pattern derived from one gap
description) to `synthesize_default_policy()` (full ruleset).

```python
# v0.1.0 style — still works
policy = synthesize_from_text("send_email to attacker@evil.com")

# v0.2.0 — production-ready full policy
from mcp_guard import synthesize_default_policy
policy = synthesize_default_policy()
```

## [0.1.0] — 2026-05-04

Initial release. Graduated from `purple-scaffold/purple/policy*.py`
into a standalone, zero-runtime-dependency package.

### Added

- Public API: `synthesize_from_text`, `synthesize`, `evaluate`,
  `default_corpus`, `run_backtest`.
- 2 deterministic rule patterns: email contact allowlist + sensitive
  file read.
- 5 policy operators: `in`, `not_in`, `equals`, `not_equals`,
  `matches`.
- CLI: `mcp-guard synthesize / evaluate / backtest`.
- 8 smoke tests across the public API and CLI round-trip.
- GitHub Actions: tests on push/PR (Python 3.11/3.12/3.13) + PyPI
  publish on release.
