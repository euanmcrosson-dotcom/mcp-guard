"""Reproduce the EchoLeak case study end-to-end.

Run from the repo root:

    python case_studies/echoleak-gpt4o/reproduce.py

Regenerates synthesised_policy.yaml and backtest.json from gap.txt.
No network calls — fully deterministic.
"""

from __future__ import annotations

import json
from dataclasses import asdict
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

    # 1. Synthesise from the single observed gap.
    targeted_policy = synthesize_from_text(
        gap, technique_id="echoleak-gpt4o-2026-04-28"
    )
    (HERE / "synthesised_policy.yaml").write_text(
        targeted_policy.to_yaml(), encoding="utf-8"
    )
    print(f"wrote {HERE / 'synthesised_policy.yaml'}")

    # 2. Backtest BOTH policies for comparison:
    #    - the rule synthesised from this single gap
    #    - the full default policy (every built-in pattern)
    targeted_metrics = run_backtest(targeted_policy, default_corpus())
    default_metrics = run_backtest(synthesize_default_policy(), default_corpus())

    out = {
        "targeted_policy": {
            "rule_count": len(targeted_policy.rules),
            "tp": targeted_metrics.tp,
            "fp": targeted_metrics.fp,
            "tn": targeted_metrics.tn,
            "fn": targeted_metrics.fn,
            "tpr": round(targeted_metrics.true_positive_rate, 4),
            "fpr": round(targeted_metrics.false_positive_rate, 4),
        },
        "default_policy": {
            "rule_count": len(synthesize_default_policy().rules),
            "tp": default_metrics.tp,
            "fp": default_metrics.fp,
            "tn": default_metrics.tn,
            "fn": default_metrics.fn,
            "tpr": round(default_metrics.true_positive_rate, 4),
            "fpr": round(default_metrics.false_positive_rate, 4),
        },
        "corpus_size": targeted_metrics.corpus_size,
    }

    (HERE / "backtest.json").write_text(
        json.dumps(out, indent=2), encoding="utf-8"
    )
    print(f"wrote {HERE / 'backtest.json'}")
    print()
    print("Summary:")
    print(f"  targeted policy: {out['targeted_policy']['rule_count']} rules → "
          f"TPR {out['targeted_policy']['tpr']:.4f}, "
          f"FPR {out['targeted_policy']['fpr']:.4f}")
    print(f"  default policy:  {out['default_policy']['rule_count']} rules → "
          f"TPR {out['default_policy']['tpr']:.4f}, "
          f"FPR {out['default_policy']['fpr']:.4f}")


if __name__ == "__main__":
    main()
