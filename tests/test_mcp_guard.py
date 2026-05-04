"""Smoke tests for mcp_guard.

These tests are deliberately small — the policy / synthesis /
backtest internals are tested more thoroughly in the
`purple-scaffold` repo where they originated. Here we exercise:

  - The public API imports cleanly
  - synthesize_from_text + evaluate round-trip works
  - run_backtest produces sensible metrics on the default corpus
  - The CLI entry point dispatches without crashing
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_guard import (
    Condition, Decision, GeneratedPolicy, PolicyRule,
    SynthesisInput, evaluate, synthesize, synthesize_from_text,
    BacktestCase, BacktestMetrics, default_corpus, run_backtest,
)
from mcp_guard.synthesis import GapDescription


def test_public_api_imports():
    assert callable(evaluate)
    assert callable(synthesize)
    assert callable(synthesize_from_text)
    assert callable(default_corpus)
    assert callable(run_backtest)


def test_synthesize_from_text_email_pattern():
    policy = synthesize_from_text(
        "send_email to attacker@evil.com",
        technique_id="t1",
    )
    assert len(policy.rules) == 1
    assert policy.rules[0].tool == "send_email"


def test_synthesize_no_match_returns_empty():
    policy = synthesize_from_text(
        "totally novel attack class with no patterns",
        technique_id="t2",
    )
    assert policy.rules == ()


def test_evaluate_denies_attacker():
    policy = synthesize_from_text("send_email to attacker@evil.com")
    decision = evaluate(
        policy,
        "send_email",
        {"to": "attacker@evil.com"},
        {"user": {"contacts": ["bob@corp"]}},
    )
    assert decision.allowed is False
    assert decision.denying_rule_id


def test_evaluate_allows_in_contacts():
    policy = synthesize_from_text("send_email to attacker@evil.com")
    decision = evaluate(
        policy,
        "send_email",
        {"to": "bob@corp"},
        {"user": {"contacts": ["bob@corp"]}},
    )
    assert decision.allowed is True


def test_default_corpus_size():
    corpus = default_corpus()
    assert len(corpus) >= 10
    # Mixed legit + attack
    expecteds = {c.expected for c in corpus}
    assert "allow" in expecteds
    assert "deny" in expecteds


def test_run_backtest_email_only_rule():
    policy = synthesize_from_text(
        "send_email to attacker@evil.com", technique_id="t"
    )
    metrics = run_backtest(policy, default_corpus())
    # The email rule only catches email attacks (3 of them); the
    # 3 file-read attacks are FN.
    assert metrics.tp == 3
    assert metrics.fn == 3
    # The 2 first-time-recipient legit emails are FP.
    assert metrics.fp == 2


def test_yaml_round_trip_via_cli(tmp_path: Path):
    """Round-trip: synthesize via CLI → emit YAML → re-load via CLI
    evaluate → expect deny on the attack case."""
    policy_path = tmp_path / "policy.yaml"

    # synthesize
    syn = subprocess.run(
        [sys.executable, "-m", "mcp_guard.cli", "synthesize",
         "send_email to attacker@evil.com"],
        capture_output=True, text=True, check=True,
    )
    policy_path.write_text(syn.stdout, encoding="utf-8")

    # evaluate (attacker recipient → deny → exit 2)
    eva = subprocess.run(
        [sys.executable, "-m", "mcp_guard.cli", "evaluate",
         str(policy_path), "send_email", '{"to":"attacker@evil.com"}',
         "--user-context", '{"user":{"contacts":[]}}'],
        capture_output=True, text=True,
    )
    assert eva.returncode == 2  # denied
    decision = json.loads(eva.stdout)
    assert decision["allowed"] is False

    # backtest
    bt = subprocess.run(
        [sys.executable, "-m", "mcp_guard.cli", "backtest", str(policy_path)],
        capture_output=True, text=True, check=True,
    )
    metrics = json.loads(bt.stdout)
    assert metrics["corpus_size"] >= 10
    assert metrics["tp"] >= 1
