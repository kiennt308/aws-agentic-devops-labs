# Copyright (c) 2026 Kien Nguyen (Apache-2.0)
"""Pytest suite for Cedar v4.15 AgentCore Gateway authorization."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import yaml

CH06_DIR = Path(__file__).resolve().parent
ENGINE_PATH = CH06_DIR / "03-cedar-policy-engine.py"
SPEC = importlib.util.spec_from_file_location("cedar_engine", ENGINE_PATH)
assert SPEC is not None and SPEC.loader is not None
ENGINE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ENGINE
SPEC.loader.exec_module(ENGINE)

SCHEMA_PATH = CH06_DIR / "01-orderflow-agentcore.cedarschema.json"
POLICY_PATH = CH06_DIR / "02-orderflow-gateway.cedar"
VALID_CFG_PATH = CH06_DIR / "05-cedar-gateway-config-valid.yaml"
NEG_CFG_PATH = CH06_DIR / "06-cedar-wildcard-bypass-negative.yaml"


def test_cedar_schema_has_no_wildcards_and_all_actions() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    ns = schema["AgentCore"]
    assert set(ns["entityTypes"].keys()) == {
        "OAuthUser",
        "IamEntity",
        "Gateway",
    }
    expected_actions = {
        "cloudwatch___get_metric_data",
        "aurora___describe_db_clusters",
        "eks___list_insights",
        "devopsagent___list_journal_records",
        "aurora___delete_db_cluster",
        "kms___schedule_key_deletion",
        "iam___attach_role_policy",
    }
    actions = ns["actions"]
    assert set(actions.keys()) == expected_actions
    for name, cfg in actions.items():
        assert "*" not in name
        applies = cfg["appliesTo"]
        assert applies["principalTypes"] == ["OAuthUser", "IamEntity"]
        assert applies["resourceTypes"] == ["Gateway"]


def test_benign_diagnostics_allowed_for_oauth_and_iam() -> None:
    engine = ENGINE.CedarPolicyEngine.from_file(
        POLICY_PATH, mode="ENFORCE"
    )
    gw = ENGINE.build_default_gateway()
    oauth_agent = ENGINE.Entity(
        "AgentCore::OAuthUser",
        "orderflow-triage-oauth",
        {"sub": "svc-triage", "scope": "ops:read"},
    )
    iam_agent = ENGINE.Entity(
        "AgentCore::IamEntity",
        "orderflow-triage-iam",
        {
            "arn": "arn:aws:iam::111122223333:role/ops-agent",
            "scope": "ops:read",
            "account_id": "111122223333",
        },
    )
    for caller in (oauth_agent, iam_agent):
        for act in (
            "cloudwatch___get_metric_data",
            "aurora___describe_db_clusters",
            "eks___list_insights",
            "devopsagent___list_journal_records",
        ):
            res = engine.evaluate(
                caller, act, gw, {"region": "us-east-1"}
            )
            assert res.decision == "ALLOW"
            assert res.cedar_verdict == "ALLOW"


def test_prompt_injection_destructive_actions_blocked() -> None:
    engine = ENGINE.CedarPolicyEngine.from_file(
        POLICY_PATH, mode="ENFORCE"
    )
    gw = ENGINE.build_default_gateway()
    attacker = ENGINE.Entity(
        "AgentCore::OAuthUser",
        "hijacked-agent",
        {"sub": "agent-01", "scope": "ops:read"},
    )
    payloads = [
        ("aurora___delete_db_cluster", {"skip_final_snapshot": True}),
        ("kms___schedule_key_deletion", {"pending_window_in_days": 3}),
        (
            "iam___attach_role_policy",
            {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        ),
        (
            "aurora___describe_db_clusters",
            {"allow_destructive": True, "skip_final_snapshot": True},
        ),
    ]
    for action, ctx in payloads:
        res = engine.evaluate(attacker, action, gw, ctx)
        assert res.decision == "DENY"
        assert res.cedar_verdict == "DENY"
        assert len(res.matched_forbids) >= 1


def test_wrong_scope_and_untrusted_gateway_default_deny() -> None:
    engine = ENGINE.CedarPolicyEngine.from_file(
        POLICY_PATH, mode="ENFORCE"
    )
    gw = ENGINE.build_default_gateway()
    wrong_scope = ENGINE.Entity(
        "AgentCore::OAuthUser",
        "reader-bot",
        {"sub": "bot-02", "scope": "ops:write"},
    )
    res_scope = engine.evaluate(
        wrong_scope, "eks___list_insights", gw, {}
    )
    assert res_scope.decision == "DENY"
    assert res_scope.matched_permits == ()

    untrusted_gw = ENGINE.Entity(
        "AgentCore::Gateway",
        "arn:aws:bedrock-agentcore:us-east-1:999988887777:gateway/rogue",
        {
            "gateway_id": "rogue",
            "gateway_arn": (
                "arn:aws:bedrock-agentcore:us-east-1:"
                "999988887777:gateway/rogue"
            ),
            "account_id": "999988887777",
            "region": "us-east-1",
            "environment": "production",
        },
    )
    valid_user = ENGINE.Entity(
        "AgentCore::OAuthUser",
        "orderflow-triage-oauth",
        {"sub": "svc-triage", "scope": "ops:read"},
    )
    res_gw = engine.evaluate(
        valid_user, "cloudwatch___get_metric_data", untrusted_gw, {}
    )
    assert res_gw.decision == "DENY"


def test_log_only_mode_allows_while_auditing_deny() -> None:
    engine = ENGINE.CedarPolicyEngine.from_file(
        POLICY_PATH, mode="LOG_ONLY"
    )
    gw = ENGINE.build_default_gateway()
    caller = ENGINE.Entity(
        "AgentCore::OAuthUser",
        "orderflow-triage-oauth",
        {"sub": "svc-triage", "scope": "ops:read"},
    )
    res = engine.evaluate(
        caller,
        "aurora___delete_db_cluster",
        gw,
        {"skip_final_snapshot": True},
    )
    assert res.decision == "ALLOW_WITH_AUDIT_DENY"
    assert res.cedar_verdict == "DENY"
    assert len(engine.audit_log) == 1
    assert engine.audit_log[0]["action"] == "aurora___delete_db_cluster"


def test_gateway_yaml_fixtures_match_rego_policy_contract() -> None:
    valid = yaml.safe_load(VALID_CFG_PATH.read_text(encoding="utf-8"))
    spec = valid["spec"]
    assert spec["policy_engine"] == "agentcore-cedar"
    assert spec["enforcement_mode"] == "ENFORCE"
    assert all("*" not in act for act in spec["permitted_actions"])
    assert {
        "aurora___delete_db_cluster",
        "kms___schedule_key_deletion",
        "iam___attach_role_policy",
    }.issubset(set(spec["forbidden_actions"]))

    neg = yaml.safe_load(NEG_CFG_PATH.read_text(encoding="utf-8"))["spec"]
    assert any("*" in act for act in neg["permitted_actions"])
    assert neg["enforcement_mode"] not in {"LOG_ONLY", "ENFORCE"}
    assert "aurora___delete_db_cluster" not in neg["forbidden_actions"]
