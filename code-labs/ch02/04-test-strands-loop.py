"""Pytest suite for Strands v1.64.0 loop, middleware, S3 Vectors, cancel.

Copyright (c) 2026 Kien Nguyen
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import pytest

CH02_DIR = Path(__file__).resolve().parent
AGENT_FILE = CH02_DIR / "01-strands-triage-agent.py"

_spec = importlib.util.spec_from_file_location(
    "strands_triage_agent", AGENT_FILE
)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
sys.modules["strands_triage_agent"] = _mod
_spec.loader.exec_module(_mod)

S3VectorsRunbookStore = _mod.S3VectorsRunbookStore
StrandsTriageAgent = _mod.StrandsTriageAgent
TokenBudgetExceededError = _mod.TokenBudgetExceededError
TriageSummary = _mod.TriageSummary
lookup_s3_vector_runbooks = _mod.lookup_s3_vector_runbooks


def test_tool_schema_and_structured_triage_summary() -> None:
    """Verify @tool metadata and typed TriageSummary output."""
    spec = getattr(lookup_s3_vector_runbooks, "_strands_tool_spec")
    assert spec["name"] == "lookup_s3_vector_runbooks"
    assert "symptom_query" in spec["parameters"]

    agent = StrandsTriageAgent()
    result = agent.run(
        incident_id="INC-STRANDS-01",
        symptom="Aurora pg_locks cascade blocking writer pool",
    )
    assert isinstance(result, TriageSummary)
    assert result.status == "COMPLETED"
    assert result.agent_id == "orderflow-aws-triage-agent"
    assert result.root_cause_service == "aurora-pg18"
    assert result.runbook_id == "rb-aurora-pg18-lock"
    assert result.turns_executed == 3
    assert len(result.tool_trace) == 2


def test_middleware_redacts_secrets_and_enforces_token_cap() -> None:
    """Middleware masks AKIA/Bearer/password and blocks token overrun."""
    seen_prompts: list[str] = []

    class CaptureMiddleware:
        def before_model(
            self, agent: StrandsTriageAgent, text: str, tokens: int
        ) -> str:
            seen_prompts.append(text)
            return text

        def after_tool(
            self, agent: StrandsTriageAgent, tool_name: str, result: str
        ) -> str:
            return result

    agent = StrandsTriageAgent(
        max_input_tokens_budget=24000,
        middlewares=[CaptureMiddleware()],
    )
    leaked = (
        "Aurora pg_locks issue AKIA1234567890ABCDEF "
        "Bearer eyJabc.def.ghi password=supersecret"
    )
    result = agent.run(incident_id="INC-REDACT-02", symptom=leaked)
    assert result.redacted_findings >= 3
    assert "AKIA1234567890ABCDEF" not in seen_prompts[0]
    assert "supersecret" not in seen_prompts[0]
    assert "[REDACTED_AWS_KEY]" in seen_prompts[0]

    tight_agent = StrandsTriageAgent(max_input_tokens_budget=600)
    with pytest.raises(TokenBudgetExceededError):
        tight_agent.run(
            incident_id="INC-BUDGET-03",
            symptom="Aurora pg_locks failure",
        )


def test_s3_vectors_topk_matches_distinct_services() -> None:
    """Offline S3 Vectors ranks Aurora and VPC Lattice accurately."""
    store = S3VectorsRunbookStore()
    aurora_hits = store.query_top_k(
        "Aurora pg_locks writer lock wait cascade", top_k=2
    )
    lattice_hits = store.query_top_k(
        "VPC Lattice target group 5xx routing drift", top_k=2
    )
    assert aurora_hits[0]["runbook_id"] == "rb-aurora-pg18-lock"
    assert aurora_hits[0]["score"] > aurora_hits[1]["score"]
    assert lattice_hits[0]["runbook_id"] == "rb-vpc-lattice-5xx"
    assert lattice_hits[0]["score"] > lattice_hits[1]["score"]


def test_agent_cancel_aborts_safely_pre_and_mid_loop() -> None:
    """agent.cancel() halts cleanly before start or after turn 1."""
    pre_agent = StrandsTriageAgent()
    pre_agent.cancel(reason="human_takeover")
    pre_res = pre_agent.run(
        incident_id="INC-CANCEL-PRE",
        symptom="Aurora pg_locks spike",
    )
    assert pre_res.status == "CANCELLED"
    assert pre_res.turns_executed == 0
    assert pre_res.cancel_reason == "human_takeover"

    class MidLoopCancelMiddleware:
        def before_model(
            self, agent: StrandsTriageAgent, text: str, tokens: int
        ) -> str:
            return text

        def after_tool(
            self, agent: StrandsTriageAgent, tool_name: str, result: str
        ) -> str:
            agent.cancel(reason="mid_flight_abort")
            return result

    mid_agent = StrandsTriageAgent(
        middlewares=[MidLoopCancelMiddleware()]
    )
    mid_res = mid_agent.run(
        incident_id="INC-CANCEL-MID",
        symptom="Aurora pg_locks spike",
    )
    assert mid_res.status == "CANCELLED"
    assert mid_res.turns_executed == 1
    assert mid_res.cancel_reason == "mid_flight_abort"
