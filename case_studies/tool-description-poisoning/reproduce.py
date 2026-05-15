"""Reproduce the MCP tool-description poisoning case study end-to-end.

Run from the repo root:

    python case_studies/tool-description-poisoning/reproduce.py

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

    targeted = synthesize_from_text(gap, technique_id="mcp-tool-poisoning-2026-04-28")
    (HERE / "synthesised_policy.yaml").write_text(
        targeted.to_yaml(), encoding="utf-8"
    )
    print(f"wrote {HERE / 'synthesised_policy.yaml'}")

    tm = run_backtest(targeted, default_corpus())
    dm = run_backtest(synthesize_default_policy(), default_corpus())

    out = {
        "attack_class": "cross-tool confused deputy via MCP tool-description poisoning",
        "source_finding": "purple-scaffold/findings/2026-04-28-gpt4o-mcp-tool-description-poisoning.md",
        "vulnerable_provider": "GPT-4o (6/9 = 66.7% cross-tool hijack)",
        "resistant_provider": "Claude Opus 4.7 (0/9)",
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
