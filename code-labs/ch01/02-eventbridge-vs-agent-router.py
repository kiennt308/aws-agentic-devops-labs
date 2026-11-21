"""Decision router: static EventBridge vs. managed AWS Agentic Ops.

Separates deterministic single-step rules from multi-account/multi-hop
root-cause correlation requiring Bedrock AgentCore isolation.
"""

from __future__ import annotations

import json
from typing import Any


def route_aws_signal(event: dict[str, Any]) -> dict[str, Any]:
    """Route an OrderFlow Global signal to deterministic or agentic."""
    detail_type = event.get("detail-type", "")
    detail = event.get("detail", {})
    affected_accounts = len(detail.get("accounts", []))
    cross_service_hops = len(detail.get("correlated_services", []))
    reversible_single = detail.get("single_target_deterministic", False)

    if reversible_single and cross_service_hops <= 1:
        return {
            "event_id": event.get("id", "unknown"),
            "detail_type": detail_type,
            "lane": "STATIC_EVENTBRIDGE_LAMBDA",
            "reason": "Single-account deterministic threshold met",
            "estimated_agent_seconds": 0,
        }

    return {
        "event_id": event.get("id", "unknown"),
        "detail_type": detail_type,
        "lane": "MANAGED_AWS_AGENTIC_OPS",
        "agent_space": detail.get(
            "agent_space", "orderflow-prod-ops-space"
        ),
        "gateway_target": "orderflow-ops-gw",
        "reason": (
            f"Multi-signal triage across {affected_accounts} account(s) "
            f"and {cross_service_hops} correlated services"
        ),
        "max_agent_seconds": 300,
    }


def main() -> None:
    sample_events = [
        {
            "id": "evt-s3-block-01",
            "detail-type": "S3 Public Access Drift",
            "detail": {
                "accounts": ["111122223333"],
                "correlated_services": ["s3"],
                "single_target_deterministic": True,
            },
        },
        {
            "id": "evt-aurora-lattice-02",
            "detail-type": "OrderFlowCheckoutLatencyBurn",
            "detail": {
                "agent_space": "orderflow-prod-ops-space",
                "accounts": ["111122223333", "444455556666"],
                "correlated_services": [
                    "aurora-pg18",
                    "vpc-lattice",
                    "lambda-checkout",
                ],
                "single_target_deterministic": False,
            },
        },
    ]
    results = [route_aws_signal(ev) for ev in sample_events]
    assert results[0]["lane"] == "STATIC_EVENTBRIDGE_LAMBDA"
    assert results[1]["lane"] == "MANAGED_AWS_AGENTIC_OPS"
    print(json.dumps({"routed": results}, indent=2))


if __name__ == "__main__":
    main()
