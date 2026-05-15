"""Reproduce the AWS metadata SSRF case study end-to-end.

Run from the repo root:

    python case_studies/aws-metadata-ssrf/reproduce.py

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

    targeted = synthesize_from_text(gap, technique_id="aws-imds-ssrf-2026-05-15")
    (HERE / "synthesised_policy.yaml").write_text(
        targeted.to_yaml(), encoding="utf-8"
    )
    print(f"wrote {HERE / 'synthesised_policy.yaml'}")

    tm = run_backtest(targeted, default_corpus())
    dm = run_backtest(synthesize_default_policy(), default_corpus())

    out = {
        "attack_class": "SSRF to cloud metadata service / private host",
        "primary_rule_pattern": "ssrf-private-host",
        "ssrf_variants_covered": [
            "AWS IMDS (169.254.169.254)",
            "GCP metadata (metadata.google.internal)",
            "Azure IMDS",
            "Loopback (127.0.0.1)",
            "RFC1918 private (10.x, 192.168.x, 172.16-31.x)",
            "Link-local IPv4 (169.254.x.x)",
            "IPv4-mapped IPv6 loopback ([::ffff:127.0.0.1])",
            "IPv6 unique-local (fc..) / link-local (fe80:)",
            "file:// scheme",
            "gopher:// scheme",
            "dict:// scheme",
            "ldap://, ldaps:// schemes (JNDI-adjacent)",
            "ftp://, jar:// schemes",
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
        "residual_risks": [
            "DNS rebinding (requires IP-pinning HTTP client)",
            "302 redirect chains (requires per-hop re-evaluation OR disabled redirects)",
            "IMDSv1 still enabled (enable IMDSv2 with --http-tokens required)",
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
