"""OrderFlow Strands Agents SDK v1.64.0-pattern cloud ops triage agent.

Copyright (c) 2026 Kien Nguyen
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
import functools
import inspect
import json
import math
import os
from pathlib import Path
import re
import threading
from typing import Any, Callable, Protocol, TypedDict

HERE = Path(__file__).resolve().parent
DEFAULT_INDEX = HERE / "05-s3-vectors-runbook-index.json"

_AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+\b")
_PWD_RE = re.compile(r"(?i)(password|secret|token)\s*=\s*[^\s,;]+")


class ToolSpec(TypedDict):
    """Schema descriptor attached by the @tool decorator."""

    name: str
    description: str
    parameters: list[str]


class RunbookHit(TypedDict):
    """Single S3 Vectors cosine similarity search hit."""

    runbook_id: str
    service: str
    title: str
    recommended_tool: str
    score: float


@dataclass(frozen=True)
class TriageSummary:
    """Typed structured output returned by StrandsTriageAgent."""

    agent_id: str
    status: str
    incident_id: str
    root_cause_service: str
    runbook_id: str
    recommended_action: str
    turns_executed: int
    tokens_consumed: int
    top_runbooks: list[RunbookHit] = field(default_factory=list)
    tool_trace: list[dict[str, Any]] = field(default_factory=list)
    redacted_findings: int = 0
    cancel_reason: str | None = None


class TokenBudgetExceededError(RuntimeError):
    """Raised when cumulative input tokens exceed budget."""


class StrandsMiddleware(Protocol):
    """Public middleware hook contract (Strands SDK v1.62.0+)."""

    def before_model(
        self, agent: "StrandsTriageAgent", text: str, tokens: int
    ) -> str:
        """Transform or validate prompt text before model turn."""

    def after_tool(
        self, agent: "StrandsTriageAgent", tool_name: str, result: str
    ) -> str:
        """Transform or sanitize tool output after execution."""


def tool(
    fn: Callable[..., Any] | None = None,
    *,
    name: str | None = None,
    description: str | None = None,
) -> Callable[..., Any]:
    """Register an in-SDK @tool without deprecated external tools."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(func)
        spec: ToolSpec = {
            "name": name or func.__name__,
            "description": (func.__doc__ or description or "").strip(),
            "parameters": list(sig.parameters.keys()),
        }

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        setattr(wrapper, "_strands_tool_spec", spec)
        return wrapper

    if fn is not None:
        return decorator(fn)
    return decorator


def redact_secrets(text: str) -> tuple[str, int]:
    """Redact AWS access keys, bearer tokens, and inline passwords."""
    count = 0
    for pattern, repl in (
        (_AKIA_RE, "[REDACTED_AWS_KEY]"),
        (_BEARER_RE, "Bearer [REDACTED_TOKEN]"),
        (_PWD_RE, r"\1=[REDACTED_SECRET]"),
    ):
        text, hits = pattern.subn(repl, text)
        count += hits
    return text, count


class SecretRedactorMiddleware:
    """Sanitize prompt inputs and tool outputs before trace logging."""

    def __init__(self) -> None:
        self.redaction_count = 0

    def before_model(
        self, agent: "StrandsTriageAgent", text: str, tokens: int
    ) -> str:
        clean, hits = redact_secrets(text)
        self.redaction_count += hits
        return clean

    def after_tool(
        self, agent: "StrandsTriageAgent", tool_name: str, result: str
    ) -> str:
        clean, hits = redact_secrets(result)
        self.redaction_count += hits
        return clean


class TokenBudgetMiddleware:
    """Enforce cumulative max_input_tokens_budget across loop turns."""

    def __init__(self, max_input_tokens_budget: int = 24000) -> None:
        if max_input_tokens_budget <= 0:
            raise ValueError("max_input_tokens_budget must be positive")
        self.budget = max_input_tokens_budget
        self.consumed = 0

    def before_model(
        self, agent: "StrandsTriageAgent", text: str, tokens: int
    ) -> str:
        if self.consumed + tokens > self.budget:
            raise TokenBudgetExceededError(
                f"Token cap exceeded: {self.consumed + tokens} > "
                f"{self.budget}"
            )
        self.consumed += tokens
        return text

    def after_tool(
        self, agent: "StrandsTriageAgent", tool_name: str, result: str
    ) -> str:
        return result


def embed_incident_query(query: str) -> list[float]:
    """Embed operational query into 6-D OrderFlow S3 Vectors space."""
    q = query.lower()
    vec = [
        1.0 if any(k in q for k in ("aurora", "pg_locks", "db")) else 0.1,
        1.0 if any(k in q for k in ("lattice", "5xx", "target")) else 0.1,
        1.0 if any(k in q for k in ("lambda", "throttle")) else 0.1,
        1.0 if any(k in q for k in ("valkey", "redis", "cache")) else 0.1,
        0.7 if any(k in q for k in ("lock", "latency", "drift")) else 0.2,
        0.25 if any(k in q for k in ("iam", "quota", "limit")) else 0.05,
    ]
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [round(v / norm, 6) for v in vec]


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two equal-length vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return round(dot / (na * nb), 6)


class S3VectorsRunbookStore:
    """Offline S3 Vectors index client for OrderFlow runbook lookup."""

    def __init__(self, index_path: Path = DEFAULT_INDEX) -> None:
        raw = json.loads(index_path.read_text(encoding="utf-8"))
        self.index_name: str = raw["index_name"]
        self.documents: list[dict[str, Any]] = raw["documents"]

    def query_top_k(self, query: str, top_k: int = 2) -> list[RunbookHit]:
        """Return top-k runbooks ordered by descending cosine score."""
        qvec = embed_incident_query(query)
        scored: list[RunbookHit] = []
        for doc in self.documents:
            score = _cosine_similarity(qvec, doc["vector"])
            scored.append(
                {
                    "runbook_id": doc["runbook_id"],
                    "service": doc["service"],
                    "title": doc["title"],
                    "recommended_tool": doc["recommended_tool"],
                    "score": score,
                }
            )
        scored.sort(key=lambda item: item["score"], reverse=True)
        return scored[:top_k]


@tool
def lookup_s3_vector_runbooks(
    symptom_query: str, top_k: int = 2
) -> str:
    """Search offline S3 Vectors index for matching AWS runbooks."""
    store = S3VectorsRunbookStore()
    hits = store.query_top_k(symptom_query, top_k=top_k)
    return json.dumps({"index": store.index_name, "hits": hits})


@tool
def aurora_describe_db_clusters(
    db_cluster_identifier: str = "orderflow-pg18",
) -> str:
    """Return read-only Aurora PG18 cluster and lock telemetry."""
    return json.dumps(
        {
            "cluster": db_cluster_identifier,
            "engine": "aurora-postgresql",
            "engine_version": "18.3",
            "writer_connections": 412,
            "blocked_sessions": 42,
            "top_wait_event": "Lock:relation",
        }
    )


@tool
def cloudwatch_get_metric_data(
    namespace: str = "AWS/VpcLattice",
    metric_name: str = "HTTPCode_Target_5XX_Count",
) -> str:
    """Return read-only CloudWatch metrics for OrderFlow services."""
    return json.dumps(
        {
            "namespace": namespace,
            "metric_name": metric_name,
            "latest_value": 184.0,
            "unit": "Count",
        }
    )


class SystemOneDecisionModel:
    """Deterministic local decision policy with replay/Ollama env hook."""

    def __init__(self) -> None:
        self.endpoint = os.getenv("LLM_BASE_URL", "replay://local-mock")

    def plan_next_step(
        self,
        turn: int,
        symptom: str,
        hits: list[RunbookHit],
    ) -> dict[str, Any]:
        """Select next deterministic tool action or finalize summary."""
        if turn == 1:
            return {
                "action": "call_tool",
                "tool": "lookup_s3_vector_runbooks",
                "args": {"symptom_query": symptom, "top_k": 2},
                "tokens": 420,
            }
        if turn == 2 and hits:
            top = hits[0]
            if top["service"] == "aurora-pg18":
                return {
                    "action": "call_tool",
                    "tool": "aurora_describe_db_clusters",
                    "args": {"db_cluster_identifier": "orderflow-pg18"},
                    "tokens": 510,
                }
            return {
                "action": "call_tool",
                "tool": "cloudwatch_get_metric_data",
                "args": {
                    "namespace": "AWS/VpcLattice",
                    "metric_name": "HTTPCode_Target_5XX_Count",
                },
                "tokens": 490,
            }
        top_svc = hits[0]["service"] if hits else "unknown"
        top_rb = hits[0]["runbook_id"] if hits else "none"
        return {
            "action": "finish",
            "root_cause_service": top_svc,
            "runbook_id": top_rb,
            "recommended_action": (
                "Drain long-running migration lock and verify writer pool"
            ),
            "tokens": 310,
        }


class StrandsTriageAgent:
    """Bounded Strands v1.64.0-pattern operational triage agent."""

    def __init__(
        self,
        agent_id: str = "orderflow-aws-triage-agent",
        max_turns: int = 8,
        max_input_tokens_budget: int = 24000,
        middlewares: list[Any] | None = None,
    ) -> None:
        if max_turns <= 0 or max_turns > 12:
            raise ValueError("max_turns must be between 1 and 12")
        self.agent_id = agent_id
        self.max_turns = max_turns
        self.redactor = SecretRedactorMiddleware()
        self.budget = TokenBudgetMiddleware(max_input_tokens_budget)
        self.middlewares: list[Any] = [self.redactor, self.budget]
        if middlewares:
            self.middlewares.extend(middlewares)
        self.model = SystemOneDecisionModel()
        self._cancel_event = threading.Event()
        self._cancel_reason: str | None = None
        self.tools: dict[str, Callable[..., Any]] = {
            "lookup_s3_vector_runbooks": lookup_s3_vector_runbooks,
            "aurora_describe_db_clusters": aurora_describe_db_clusters,
            "cloudwatch_get_metric_data": cloudwatch_get_metric_data,
        }

    def cancel(self, reason: str = "operator_cancel") -> None:
        """Signal safe interruption of the active agent loop."""
        self._cancel_reason = reason
        self._cancel_event.set()

    def reset_cancel(self) -> None:
        """Clear cancellation flag before a fresh run."""
        self._cancel_reason = None
        self._cancel_event.clear()

    def _cancelled_summary(
        self,
        incident_id: str,
        turns: int,
        hits: list[RunbookHit],
        trace: list[dict[str, Any]],
    ) -> TriageSummary:
        return TriageSummary(
            agent_id=self.agent_id,
            status="CANCELLED",
            incident_id=incident_id,
            root_cause_service=hits[0]["service"] if hits else "aborted",
            runbook_id=hits[0]["runbook_id"] if hits else "none",
            recommended_action="Aborted safely via agent.cancel()",
            turns_executed=turns,
            tokens_consumed=self.budget.consumed,
            top_runbooks=hits,
            tool_trace=trace,
            redacted_findings=self.redactor.redaction_count,
            cancel_reason=self._cancel_reason or "operator_cancel",
        )

    def run(self, incident_id: str, symptom: str) -> TriageSummary:
        """Execute bounded Strands triage loop with middleware."""
        hits: list[RunbookHit] = []
        trace: list[dict[str, Any]] = []
        turns = 0
        clean_symptom = symptom

        for turn in range(1, self.max_turns + 1):
            if self._cancel_event.is_set():
                return self._cancelled_summary(
                    incident_id, turns, hits, trace
                )

            plan = self.model.plan_next_step(turn, clean_symptom, hits)
            step_tokens = int(plan.get("tokens", 300))
            for mw in self.middlewares:
                clean_symptom = mw.before_model(
                    self, clean_symptom, step_tokens
                )

            if self._cancel_event.is_set():
                return self._cancelled_summary(
                    incident_id, turns, hits, trace
                )

            turns = turn
            if plan["action"] == "finish":
                return TriageSummary(
                    agent_id=self.agent_id,
                    status="COMPLETED",
                    incident_id=incident_id,
                    root_cause_service=plan["root_cause_service"],
                    runbook_id=plan["runbook_id"],
                    recommended_action=plan["recommended_action"],
                    turns_executed=turns,
                    tokens_consumed=self.budget.consumed,
                    top_runbooks=hits,
                    tool_trace=trace,
                    redacted_findings=self.redactor.redaction_count,
                )

            tool_name = plan["tool"]
            tool_fn = self.tools[tool_name]
            raw_out = str(tool_fn(**plan["args"]))
            for mw in self.middlewares:
                raw_out = mw.after_tool(self, tool_name, raw_out)

            parsed = json.loads(raw_out)
            if tool_name == "lookup_s3_vector_runbooks":
                hits = parsed["hits"]
            trace.append(
                {"turn": turn, "tool": tool_name, "output": parsed}
            )

            if self._cancel_event.is_set():
                return self._cancelled_summary(
                    incident_id, turns, hits, trace
                )

        return self._cancelled_summary(incident_id, turns, hits, trace)


def main() -> int:
    """Run deterministic offline triage demonstration."""
    agent = StrandsTriageAgent()
    summary = agent.run(
        incident_id="INC-2026-1120-01",
        symptom=(
            "Aurora pg_locks cascade blocked writer connections on "
            "orderflow-pg18 with AKIAIOSFODNN7EXAMPLE leaked in log"
        ),
    )
    print(json.dumps(summary.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
