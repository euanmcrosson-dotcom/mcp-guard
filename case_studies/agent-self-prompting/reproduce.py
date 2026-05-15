"""Reproduce the agent self-prompting loop case study.

Run from the repo root:

    python case_studies/agent-self-prompting/reproduce.py

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

    targeted = synthesize_from_text(gap, technique_id="agent-self-prompt-2026-05-15")
    (HERE / "synthesised_policy.yaml").write_text(
        targeted.to_yaml(), encoding="utf-8"
    )
    print(f"wrote {HERE / 'synthesised_policy.yaml'}")

    tm = run_backtest(targeted, default_corpus())
    dm = run_backtest(synthesize_default_policy(), default_corpus())

    out = {
        "attack_class": "agent self-prompting loop drift",
        "adversary": "the agent itself (hallucinated or persisted prior-turn content)",
        "primary_rule_pattern": "email contact allowlist + PII exfil",
        "key_observation": (
            "Input-boundary defenses (classifiers, filters, allow-lists) "
            "do not apply — the generator of the bad string IS the agent. "
            "Action-layer policy is the primary defense."
        ),
        "composing_defenses": [
            "Cap conversation length / force fresh context after N turns",
            "Tag scratchpad vs. user turns with provenance",
            "Periodic in-scratchpad policy re-evaluation",
            "Action-class diff between turns for anomaly logging",
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
