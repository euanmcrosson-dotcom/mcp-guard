"""Reproduce the Log4Shell-style MCP-server logging case study.

Run from the repo root:

    python case_studies/log4shell-mcp-logging/reproduce.py

Regenerates synthesised_policy.yaml and backtest.json from gap.txt.
No network calls — fully deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp_guard import (
    default_corpus,
    run_backtest,
    synthesize_default_policy,
    synthesize_from_text,
)


HERE = Path(__file__).resolve().parent


def main() -> None:
    gap = (HERE / "gap.txt").read_text(encoding="utf-8").strip()

    targeted = synthesize_from_text(gap, technique_id="log4shell-mcp-2026-05-15")
    (HERE / "synthesised_policy.yaml").write_text(
        targeted.to_yaml(), encoding="utf-8"
    )
    print(f"wrote {HERE / 'synthesised_policy.yaml'}")

    tm = run_backtest(targeted, default_corpus())
    dm = run_backtest(synthesize_default_policy(), default_corpus())

    out = {
        "attack_class": "Log4Shell-class JNDI lookup injection (CVE-2021-44228 family)",
        "primary_rule_pattern": "shell-danger (JNDI sub-rule)",
        "carrier": "agent passes user-controlled string to a tool whose downstream logger / formatter does reference resolution",
        "real_world_anchors": [
            "CVE-2021-44228 — original Log4Shell",
            "CVE-2021-45046 — Log4Shell variant",
            "OWASP LLM01 (Prompt Injection) — the parent class for indirect injection in agent tool args",
        ],
        "targeted_policy": {
            "rule_count": len(targeted.rules),
            "tp": tm.tp, "fp": tm.fp, "tn": tm.tn, "fn": tm.fn,
            "tpr": round(tm.true_positive_rate, 4),
            "fpr": round(tm.false_positive_rate, 4),
        },
        "default_policy": {
            "rule_count": len(synthesize_default_policy().rules),
            "tp": dm.tp, "fp": dm.fp, "tn": dm.tn, "fn": dm.fn,
            "tpr": round(dm.true_positive_rate, 4),
            "fpr": round(dm.false_positive_rate, 4),
        },
        "corpus_size": tm.corpus_size,
        "production_recommendation": (
            "Add a per-tool JNDI rule for any string-accepting tool whose "
            "backend / logger chain is not fully under your control. The "
            "default policy catches JNDI strings in shell-tool args; "
            "extending it to non-shell tools is a 5-line PolicyRule append."
        ),
    }

    (HERE / "backtest.json").write_text(
        json.dumps(out, indent=2), encoding="utf-8"
    )
    print(f"wrote {HERE / 'backtest.json'}")
    print()
    print("Summary:")
    print(f"  targeted: {out['targeted_policy']['rule_count']} rules → "
          f"TPR {out['targeted_policy']['tpr']:.4f}, "
          f"FPR {out['targeted_policy']['fpr']:.4f}")
    print(f"  default:  {out['default_policy']['rule_count']} rules → "
          f"TPR {out['default_policy']['tpr']:.4f}, "
          f"FPR {out['default_policy']['fpr']:.4f}")


if __name__ == "__main__":
    main()
