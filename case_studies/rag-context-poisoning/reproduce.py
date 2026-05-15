"""Reproduce the RAG context-poisoning case study.

Run from the repo root:

    python case_studies/rag-context-poisoning/reproduce.py

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

    targeted = synthesize_from_text(gap, technique_id="rag-poison-2026-05-15")
    (HERE / "synthesised_policy.yaml").write_text(
        targeted.to_yaml(), encoding="utf-8"
    )
    print(f"wrote {HERE / 'synthesised_policy.yaml'}")

    tm = run_backtest(targeted, default_corpus())
    dm = run_backtest(synthesize_default_policy(), default_corpus())

    out = {
        "attack_class": "indirect prompt injection via RAG corpus poisoning",
        "primary_rule_pattern": "email contact allowlist + PII exfil",
        "injection_vector": "retrieved passages from vector store",
        "parent_classes": ["OWASP LLM01 (Prompt Injection)",
                           "OWASP LLM03 (Training Data Poisoning) — adjacent"],
        "real_world_corpus_sources": [
            "User-generated content (wikis, tickets, reviews)",
            "Crawled web content (anyone who ranks for the crawler keyword)",
            "Compromised ETL pipelines into the vector DB",
            "Insider authors of 'internal docs'",
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
        "defense_in_depth_recommendations": [
            "Restrict corpus write access; don't index untrusted UGC",
            "Tag retrieved passages with provenance; weight by trust",
            "Run injection-pattern regex on passages at indexing time",
            "Run mcp-recon over the retrieval tool to confirm its authority surface",
        ],
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
