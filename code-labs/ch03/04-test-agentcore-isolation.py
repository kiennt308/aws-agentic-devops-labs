"""Pytest suite for AgentCore Gateway JWT auth & Memory isolation.

Copyright (c) 2026 Kien Nguyen
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import sys
import pytest

CH03_DIR = Path(__file__).resolve().parent
PROXY_FILE = CH03_DIR / "03-agentcore-gateway-auth-proxy.py"

_spec = importlib.util.spec_from_file_location(
    "agentcore_gateway_proxy", PROXY_FILE
)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
sys.modules["agentcore_gateway_proxy"] = _mod
_spec.loader.exec_module(_mod)

AgentCoreGatewayProxy = _mod.AgentCoreGatewayProxy
AgentCoreMemoryStore = _mod.AgentCoreMemoryStore
CrossTenantAccessError = _mod.CrossTenantAccessError
GatewayAuthError = _mod.GatewayAuthError
GatewayRoutingError = _mod.GatewayRoutingError
authenticate_token = _mod.authenticate_token
issue_gateway_token = _mod.issue_gateway_token


def test_valid_oauth_and_iam_gateway_routing() -> None:
    """OAuthUser and IamEntity tokens route valid <Target>___<Tool>."""
    proxy = AgentCoreGatewayProxy()
    oauth_tok = issue_gateway_token(
        subject="sre-triage-bot",
        principal_type="AgentCore::OAuthUser",
        account_id="111122223333",
        environment="prod",
        allowed_actions=["aurora___describe_db_clusters"],
    )
    iam_tok = issue_gateway_token(
        subject="arn:aws:iam::222233334444:role/stg-ops-agent",
        principal_type="AgentCore::IamEntity",
        account_id="222233334444",
        environment="staging",
        allowed_actions=["cloudwatch___get_metric_data"],
    )

    prod_res = proxy.invoke(
        token=oauth_tok,
        action="aurora___describe_db_clusters",
        target_account_id="111122223333",
        arguments={"db_cluster_identifier": "orderflow-pg18"},
    )
    assert prod_res["status"] == "INVOKED_ISOLATED"
    assert prod_res["principal_type"] == "AgentCore::OAuthUser"
    assert prod_res["target"] == "aurora"
    assert prod_res["tool"] == "describe_db_clusters"

    stg_res = proxy.invoke(
        token=iam_tok,
        action="cloudwatch___get_metric_data",
        target_account_id="222233334444",
        arguments={"namespace": "AWS/RDS"},
    )
    assert stg_res["principal_type"] == "AgentCore::IamEntity"
    assert stg_res["account_id"] == "222233334444"


def test_tampered_alg_none_expired_and_destructive_blocked() -> None:
    """Tampered JWTs, alg=none, expired tokens, and wildcards fail."""
    proxy = AgentCoreGatewayProxy()
    tok = issue_gateway_token(
        subject="sre-triage-bot",
        principal_type="AgentCore::OAuthUser",
        account_id="111122223333",
        environment="prod",
        allowed_actions=["aurora___describe_db_clusters"],
    )
    hdr, body, sig = tok.split(".")

    padded = body + "=" * (-len(body) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    claims["account_id"] = "222233334444"
    tampered_body = (
        base64.urlsafe_b64encode(json.dumps(claims).encode())
        .decode()
        .rstrip("=")
    )
    with pytest.raises(GatewayAuthError):
        authenticate_token(f"{hdr}.{tampered_body}.{sig}")

    none_hdr = (
        base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}')
        .decode()
        .rstrip("=")
    )
    with pytest.raises(GatewayAuthError):
        authenticate_token(f"{none_hdr}.{body}.")

    expired_tok = issue_gateway_token(
        subject="sre-triage-bot",
        principal_type="AgentCore::OAuthUser",
        account_id="111122223333",
        environment="prod",
        allowed_actions=["aurora___describe_db_clusters"],
        ttl_seconds=-10,
    )
    with pytest.raises(GatewayAuthError):
        authenticate_token(expired_tok)

    with pytest.raises(GatewayRoutingError):
        proxy.invoke(
            token=tok,
            action="aurora___delete_db_cluster",
            target_account_id="111122223333",
        )


def test_zero_memory_cross_contamination_between_accounts() -> None:
    """Staging 222233334444 never leaks into Prod 111122223333."""
    memory = AgentCoreMemoryStore()
    proxy = AgentCoreGatewayProxy(memory=memory)

    prod_tok = issue_gateway_token(
        subject="prod-ops",
        principal_type="AgentCore::OAuthUser",
        account_id="111122223333",
        environment="prod",
        allowed_actions=["cloudwatch___get_metric_data"],
    )
    stg_tok = issue_gateway_token(
        subject="stg-ops",
        principal_type="AgentCore::IamEntity",
        account_id="222233334444",
        environment="staging",
        allowed_actions=["cloudwatch___get_metric_data"],
    )

    prod_p = authenticate_token(prod_tok)
    stg_p = authenticate_token(stg_tok)

    memory.put_record(
        stg_p,
        "222233334444",
        "ops-context",
        "staging_incident_note",
        {"detail": "staging synthetic load test"},
    )
    memory.put_record(
        prod_p,
        "111122223333",
        "ops-context",
        "prod_incident_note",
        {"detail": "prod aurora lock alert"},
    )

    prod_visible = memory.query_records(
        prod_p, "111122223333", "ops-context"
    )
    stg_visible = memory.query_records(
        stg_p, "222233334444", "ops-context"
    )
    assert list(prod_visible.keys()) == ["prod_incident_note"]
    assert list(stg_visible.keys()) == ["staging_incident_note"]

    res = proxy.invoke(
        token=prod_tok,
        action="cloudwatch___get_metric_data",
        target_account_id="111122223333",
    )
    assert res["memory_keys_visible"] == ["prod_incident_note"]

    with pytest.raises(CrossTenantAccessError):
        memory.query_records(prod_p, "222233334444", "ops-context")
    with pytest.raises(CrossTenantAccessError):
        proxy.invoke(
            token=stg_tok,
            action="cloudwatch___get_metric_data",
            target_account_id="111122223333",
        )
