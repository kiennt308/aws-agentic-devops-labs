# Copyright (c) 2026 Kien Nguyen (Apache-2.0)
"""Pytest suite for Prompt Caching, FOCUS 1.2 SQL, and 20-pt PRR."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

CH09_DIR = Path(__file__).resolve().parent


def _load_mod(name: str, filename: str) -> object:
    path = CH09_DIR / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


BENCH = _load_mod("bench_ch09", "01-bedrock-prompt-cache-benchmark.py")
FINOPS = _load_mod("finops_ch09", "03-focus12-sqlite-finops.py")
DATASET_PATH = CH09_DIR / "02-focus12-agentic-dataset.json"
PRR_READY_PATH = CH09_DIR / "04-aws-agentic-prr-ready.json"
PRR_BLOCKED_PATH = CH09_DIR / "05-aws-agentic-prr-blocked-negative.json"


def test_prompt_caching_discount_and_ttft_math() -> None:
    explicit = BENCH.benchmark_prompt_caching(mode="EXPLICIT")
    implicit = BENCH.benchmark_prompt_caching(mode="IMPLICIT")
    assert explicit.prefix_unit_discount_pct == 90.0
    assert explicit.ttft_improvement_pct == 85.0
    assert explicit.cache_read_tokens == 4000 * 11
    assert explicit.cached_cost_usd < explicit.uncached_cost_usd
    assert explicit.total_cost_savings_pct > 60.0
    assert implicit.cached_cost_usd < implicit.uncached_cost_usd
    assert explicit.cached_cost_usd <= implicit.cached_cost_usd


def test_model_tiering_and_cross_region_throughput() -> None:
    tiering = BENCH.benchmark_model_tiering(1000, routine_share=0.70)
    assert tiering["routine_nova_micro_count"] == 700
    assert tiering["escalated_nova_pro_count"] == 300
    assert tiering["tiered_daily_usd"] < tiering["all_pro_daily_usd"]
    assert tiering["tiering_savings_pct"] > 50.0

    cris = BENCH.benchmark_cross_region_throughput()
    assert cris["cris_pooled_rpm"] == 1200
    assert cris["cris_throttled_rpm"] == 0
    assert cris["single_region_throttled_rpm"] == 500
    assert cris["throughput_gain_pct"] == 125.0


def test_focus12_schema_and_sql_unit_economics() -> None:
    raw = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    assert raw["focus_version"] == "1.2"
    assert raw["table_name"] == "FOCUS_1_2_AWS"
    required_cols = {
        "ServiceName",
        "ChargeCategory",
        "ListCost",
        "ContractedCost",
        "BilledCost",
        "EffectiveCost",
        "InvoiceId",
        "CapacityReservationId",
        "Tags",
    }
    for rec in raw["records"]:
        assert required_cols.issubset(rec.keys())
        assert "orderflow_team" in rec["Tags"]
        assert "agent_space_id" in rec["Tags"]

    report = FINOPS.run_finops_queries()
    by_team = {
        row["orderflow_team"]: row
        for row in report["team_unit_economics"]
    }
    assert set(by_team.keys()) == {
        "checkout-sre",
        "payments-platform",
        "data-reliability",
    }
    assert by_team["checkout-sre"]["total_effective_cost"] == 216.0
    assert by_team["checkout-sre"]["cost_per_incident_resolved"] == 1.2
    assert by_team["payments-platform"]["total_effective_cost"] == 144.0
    assert (
        by_team["payments-platform"]["cost_per_incident_resolved"] == 1.2
    )
    assert by_team["data-reliability"]["total_effective_cost"] == 117.0
    assert (
        by_team["data-reliability"]["cost_per_incident_resolved"] == 1.3
    )

    by_cache = {
        row["cache_mode"]: row for row in report["cache_reconciliation"]
    }
    assert by_cache["explicit_cached"]["cache_savings_usd"] == 397.2
    assert by_cache["explicit_cached"]["cache_savings_pct"] > 75.0
    assert by_cache["implicit_cached"]["cache_savings_usd"] == 72.0


def test_prr_scorecard_20_of_20_gates() -> None:
    ready = json.loads(PRR_READY_PATH.read_text(encoding="utf-8"))
    assert ready["finops_prr"] is True
    assert ready["prompt_caching_enabled"] is True
    assert ready["focus_version"] == "1.2"
    assert ready["prr_score"] == 20
    assert len(ready["checklist"]) == 20
    assert all(item["passed"] is True for item in ready["checklist"])

    blocked = json.loads(PRR_BLOCKED_PATH.read_text(encoding="utf-8"))
    assert blocked["finops_prr"] is True
    assert blocked["prompt_caching_enabled"] is False
    assert blocked["focus_version"] != "1.2"
    assert blocked["prr_score"] < 20
