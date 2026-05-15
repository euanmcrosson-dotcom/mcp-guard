# Changelog

All notable changes to mcp-guard are documented here. Format inspired
by [Keep a Changelog](https://keepachangelog.com/); versioning follows
[SemVer](https://semver.org/).

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
