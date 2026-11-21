# Copyright (c) 2026 Kien Nguyen (Apache-2.0)
"""Bedrock Prompt Caching, Model Tiering & CRIS FinOps benchmark."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

# Illustrative per-1M-token USD rates for OrderFlow FinOps modeling
MODEL_RATES_PER_1M: dict[str, dict[str, float]] = {
    "us.amazon.nova-pro-v1:0": {
        "input": 0.80,
        "cache_write": 0.80,
        "cache_read": 0.08,  # 90% discount vs standard input
        "output": 3.20,
    },
    "us.amazon.nova-micro-v1:0": {
        "input": 0.035,
        "cache_write": 0.035,
        "cache_read": 0.0035,  # 90% discount vs standard input
        "output": 0.14,
    },
}


@dataclass(frozen=True)
class CacheBenchmarkResult:
    """Cost and latency comparison across caching modes."""

    mode: str
    turns: int
    uncached_input_tokens: int
    cache_write_tokens: int
    cache_read_tokens: int
    uncached_cost_usd: float
    cached_cost_usd: float
    prefix_unit_discount_pct: float
    total_cost_savings_pct: float
    uncached_ttft_ms: float
    cached_ttft_ms: float
    ttft_improvement_pct: float


def benchmark_prompt_caching(
    model_id: str = "us.amazon.nova-pro-v1:0",
    prefix_tokens: int = 4000,
    dynamic_input_per_turn: int = 300,
    output_per_turn: int = 180,
    turns: int = 12,
    mode: str = "EXPLICIT",
    uncached_ttft_ms: float = 1200.0,
    cached_ttft_ms: float = 180.0,
) -> CacheBenchmarkResult:
    """Compare uncached vs Implicit/Explicit Bedrock Prompt Caching."""
    rates = MODEL_RATES_PER_1M[model_id]
    per_m = 1_000_000.0

    raw_input = (prefix_tokens + dynamic_input_per_turn) * turns
    total_output = output_per_turn * turns
    uncached_cost = (
        (raw_input / per_m) * rates["input"]
        + (total_output / per_m) * rates["output"]
    )

    if mode == "EXPLICIT":
        cache_write = prefix_tokens
        cache_read = prefix_tokens * max(turns - 1, 0)
        fresh_input = dynamic_input_per_turn * turns
        avg_cached_ttft = (
            uncached_ttft_ms + cached_ttft_ms * max(turns - 1, 0)
        ) / max(turns, 1)
    elif mode == "IMPLICIT":
        hit_turns = max(turns - 2, 0)
        miss_turns = turns - hit_turns
        cache_write = 0
        cache_read = prefix_tokens * hit_turns
        fresh_input = (
            prefix_tokens * miss_turns + dynamic_input_per_turn * turns
        )
        avg_cached_ttft = (
            uncached_ttft_ms * miss_turns + cached_ttft_ms * hit_turns
        ) / max(turns, 1)
    else:
        raise ValueError(f"Unsupported cache mode: {mode}")

    cached_cost = (
        (fresh_input / per_m) * rates["input"]
        + (cache_write / per_m) * rates["cache_write"]
        + (cache_read / per_m) * rates["cache_read"]
        + (total_output / per_m) * rates["output"]
    )
    prefix_discount = (
        1.0 - (rates["cache_read"] / rates["input"])
    ) * 100.0
    savings_pct = ((uncached_cost - cached_cost) / uncached_cost) * 100.0
    steady_ttft_gain = (
        (uncached_ttft_ms - cached_ttft_ms) / uncached_ttft_ms
    ) * 100.0

    return CacheBenchmarkResult(
        mode=mode,
        turns=turns,
        uncached_input_tokens=raw_input,
        cache_write_tokens=cache_write,
        cache_read_tokens=cache_read,
        uncached_cost_usd=round(uncached_cost, 6),
        cached_cost_usd=round(cached_cost, 6),
        prefix_unit_discount_pct=round(prefix_discount, 2),
        total_cost_savings_pct=round(savings_pct, 2),
        uncached_ttft_ms=round(uncached_ttft_ms, 2),
        cached_ttft_ms=round(avg_cached_ttft, 2),
        ttft_improvement_pct=round(steady_ttft_gain, 2),
    )


def benchmark_model_tiering(
    incidents_per_day: int = 1000,
    routine_share: float = 0.70,
) -> dict[str, Any]:
    """Compare all-Pro vs Nova Micro/Pro tiered triage routing."""
    pro = benchmark_prompt_caching("us.amazon.nova-pro-v1:0")
    micro = benchmark_prompt_caching("us.amazon.nova-micro-v1:0")

    all_pro_usd = incidents_per_day * pro.cached_cost_usd
    routine_cnt = int(round(incidents_per_day * routine_share))
    escalated_cnt = incidents_per_day - routine_cnt
    tiered_usd = (
        routine_cnt * micro.cached_cost_usd
        + escalated_cnt * pro.cached_cost_usd
    )
    savings_pct = ((all_pro_usd - tiered_usd) / all_pro_usd) * 100.0
    return {
        "incidents_per_day": incidents_per_day,
        "routine_nova_micro_count": routine_cnt,
        "escalated_nova_pro_count": escalated_cnt,
        "all_pro_daily_usd": round(all_pro_usd, 4),
        "tiered_daily_usd": round(tiered_usd, 4),
        "tiering_savings_pct": round(savings_pct, 2),
    }


def benchmark_cross_region_throughput(
    single_region_rpm: int = 400,
    cris_regions: tuple[str, ...] = (
        "us-east-1",
        "us-east-2",
        "us-west-2",
    ),
    burst_rpm: int = 900,
) -> dict[str, Any]:
    """Model Cross-Region Inference (CRIS) pooled RPM headroom."""
    pooled_rpm = single_region_rpm * len(cris_regions)
    single_throttled = max(burst_rpm - single_region_rpm, 0)
    cris_throttled = max(burst_rpm - pooled_rpm, 0)
    effective_single = min(burst_rpm, single_region_rpm)
    effective_cris = min(burst_rpm, pooled_rpm)
    gain_pct = (
        (effective_cris - effective_single) / effective_single
    ) * 100.0
    return {
        "inference_profile": "us.amazon.nova-pro-v1:0",
        "cris_regions": list(cris_regions),
        "single_region_rpm": single_region_rpm,
        "cris_pooled_rpm": pooled_rpm,
        "burst_demand_rpm": burst_rpm,
        "single_region_throttled_rpm": single_throttled,
        "cris_throttled_rpm": cris_throttled,
        "throughput_gain_pct": round(gain_pct, 2),
    }


def main() -> None:
    """Print deterministic Bedrock FinOps benchmark report."""
    explicit = benchmark_prompt_caching(mode="EXPLICIT")
    implicit = benchmark_prompt_caching(mode="IMPLICIT")
    tiering = benchmark_model_tiering()
    cris = benchmark_cross_region_throughput()
    print(
        json.dumps(
            {
                "explicit_caching": explicit.__dict__,
                "implicit_caching": implicit.__dict__,
                "model_tiering": tiering,
                "cross_region_inference": cris,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
