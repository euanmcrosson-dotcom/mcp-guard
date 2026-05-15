# Case Studies

Real-world (and realistic-synthetic) attack findings, walked through
mcp-guard's full pipeline: **gap → synthesised policy → backtest →
deployed rule**. Each case study is reproducible with one command, no
network calls, no API keys.

## Catalog

| # | Case study | Attack class | Primary rule pattern | Source |
|---|---|---|---|---|
| 1 | [echoleak-gpt4o](echoleak-gpt4o/) | Indirect prompt injection via document content (email exfil) | email contact allowlist + PII exfil | [`purple-scaffold` 2026-04-28](https://github.com/euanmcrosson-dotcom/purple-scaffold) — GPT-4o 66.7% silent compliance |
| 2 | [tool-description-poisoning](tool-description-poisoning/) | Cross-tool confused deputy via MCP tool catalog metadata | email contact allowlist | [`purple-scaffold` 2026-04-28](https://github.com/euanmcrosson-dotcom/purple-scaffold) — GPT-4o 66.7% cross-tool hijack |
| 3 | [aws-metadata-ssrf](aws-metadata-ssrf/) | SSRF chain to AWS IMDS for credential exfil | ssrf-private-host | Realistic synthetic (IMDSv1 pattern) |

## Reproduce all case studies

```bash
for d in case_studies/*/reproduce.py; do
    python "$d"
done
```

Or PowerShell:

```powershell
Get-ChildItem case_studies/*/reproduce.py | ForEach-Object { python $_.FullName }
```

Each script regenerates its directory's `synthesised_policy.yaml` and
`backtest.json` from the gap description, so the artifacts in this
directory are always in sync with the current mcp-guard code.

## What each case study is good for

- **Reading on its own:** the README walks the attack, the gap, the
  synthesised policy, the residual risks, and the deployment story.
  No need to clone anything to follow along.
- **Reviewing the synthesiser:** the `gap.txt` + `synthesised_policy.yaml`
  pair shows exactly what rule the deterministic synthesiser
  produces from one free-text gap. Useful for sanity-checking that
  your own gap descriptions will produce sensible rules.
- **Reviewer evidence:** the `backtest.json` is a structured artifact
  with TPR/FPR for both the targeted policy (one gap → narrow rule)
  and the default policy (full ruleset across all 9 patterns), against
  the corpus that ships with this repo.
- **Marketing:** the READMEs are the substance of "mcp-guard catches
  real attacks." When linking to mcp-guard from a blog post, a Show HN,
  or a sales conversation, point at the case study directly.

## Anatomy of a case study

Every case study directory contains:

```
case_studies/<slug>/
├── README.md                    # the human-readable walkthrough
├── gap.txt                      # free-text gap description (input)
├── reproduce.py                 # one-script reproducer
├── synthesised_policy.yaml      # output: policy generated from gap
└── backtest.json                # output: TPR/FPR against default corpus
```

The two output files are committed so the case study is browsable
without running anything. `reproduce.py` regenerates them from
source.

## Adding a new case study

The easiest path:

1. Find or write a believable gap description in `gap.txt`. Real
   findings from `purple-scaffold/findings/` are the ideal source;
   public CVEs (especially Log4Shell, AWS metadata SSRF variants,
   indirect-injection findings against frontier models) are the
   secondary source.
2. Copy `aws-metadata-ssrf/reproduce.py` as a template; change the
   `technique_id` and `attack_class` strings.
3. Run `python case_studies/<slug>/reproduce.py` to produce the YAML
   and JSON artifacts.
4. Write the README walkthrough (gap → synthesiser → defended dispatch
   → residual risks → reproduce).
5. Add a row to the catalog table above.

## Related repos

- **[`purple-scaffold`](https://github.com/euanmcrosson-dotcom/purple-scaffold)** — the offensive / measurement side. Probes that produce the gap descriptions used here.
- **[`mcp-recon`](https://github.com/euanmcrosson-dotcom/mcp-recon)** — surface-area audit. Run BEFORE integrating any third-party MCP server to flag suspicious tool descriptions / authority levels.
- **[`capnagent`](https://github.com/euanmcrosson-dotcom/capnagent)** — capability tokens. mcp-guard catches the action; capnagent prevents the authority from being held in the first place. Defense in depth.
