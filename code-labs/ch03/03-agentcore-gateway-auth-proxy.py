"""Amazon Bedrock AgentCore Gateway auth proxy & Memory scope guard.

Copyright (c) 2026 Kien Nguyen
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import time
from typing import Any
import jwt

GATEWAY_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:111122223333:"
    "gateway/orderflow-ops-gw"
)
ISSUER = "https://identity.orderflow.internal"
DEFAULT_DEV_HS256_KEY = "orderflow-offline-agentcore-gateway-hmac-2026"
VALID_PRINCIPAL_TYPES = {
    "AgentCore::OAuthUser",
    "AgentCore::IamEntity",
}
_ACCOUNT_RE = re.compile(r"^\d{12}$")

ALLOWED_TARGET_TOOLS: dict[str, set[str]] = {
    "cloudwatch": {"get_metric_data"},
    "aurora": {"describe_db_clusters"},
    "eks": {"list_insights"},
    "devopsagent": {"list_journal_records"},
}


class GatewayAuthError(PermissionError):
    """Raised on missing, invalid, expired, or tampered JWT claims."""


class GatewayRoutingError(PermissionError):
    """Raised on malformed, unauthorized, or forbidden target calls."""


class CrossTenantAccessError(PermissionError):
    """Raised when a caller attempts cross-account Memory access."""


@dataclass(frozen=True)
class GatewayPrincipal:
    """Verified AgentCore caller identity extracted from JWT claims."""

    subject: str
    principal_type: str
    account_id: str
    environment: str
    allowed_actions: tuple[str, ...]


def _signing_key() -> str:
    """Resolve HS256 verification key from env or offline lab constant."""
    return os.getenv("AGENTCORE_DEV_JWT_KEY", DEFAULT_DEV_HS256_KEY)


def issue_gateway_token(
    *,
    subject: str,
    principal_type: str,
    account_id: str,
    environment: str,
    allowed_actions: list[str],
    ttl_seconds: int = 300,
    signing_key: str | None = None,
) -> str:
    """Mint a deterministic HS256 AgentCore Gateway delegation JWT."""
    if principal_type not in VALID_PRINCIPAL_TYPES:
        raise GatewayAuthError(f"Unsupported type: {principal_type}")
    if not _ACCOUNT_RE.match(account_id):
        raise GatewayAuthError(f"Invalid AWS account_id: {account_id}")

    now = int(time.time())
    payload = {
        "sub": subject,
        "iss": ISSUER,
        "aud": GATEWAY_ARN,
        "iat": now,
        "exp": now + ttl_seconds,
        "principal_type": principal_type,
        "account_id": account_id,
        "environment": environment,
        "allowed_actions": allowed_actions,
    }
    key = signing_key or _signing_key()
    return str(jwt.encode(payload, key, algorithm="HS256"))


def authenticate_token(
    token: str, signing_key: str | None = None
) -> GatewayPrincipal:
    """Verify HS256 JWT signature, issuer, audience, and claims."""
    if not token or token.count(".") != 2:
        raise GatewayAuthError("Malformed JWT structure")

    header = jwt.get_unverified_header(token)
    if header.get("alg") != "HS256":
        raise GatewayAuthError(
            f"Disallowed JWT alg: {header.get('alg')}"
        )

    key = signing_key or _signing_key()
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["HS256"],
            audience=GATEWAY_ARN,
            issuer=ISSUER,
            options={
                "require": [
                    "sub",
                    "iss",
                    "aud",
                    "exp",
                    "iat",
                    "principal_type",
                    "account_id",
                    "allowed_actions",
                ]
            },
        )
    except jwt.PyJWTError as exc:
        raise GatewayAuthError(f"JWT validation failed: {exc}") from exc

    ptype = str(claims["principal_type"])
    account_id = str(claims["account_id"])
    if ptype not in VALID_PRINCIPAL_TYPES:
        raise GatewayAuthError(f"Invalid principal_type: {ptype}")
    if not _ACCOUNT_RE.match(account_id):
        raise GatewayAuthError(f"Invalid account_id: {account_id}")

    actions = tuple(str(a) for a in claims["allowed_actions"])
    return GatewayPrincipal(
        subject=str(claims["sub"]),
        principal_type=ptype,
        account_id=account_id,
        environment=str(claims.get("environment", "unknown")),
        allowed_actions=actions,
    )


class AgentCoreMemoryStore:
    """Account-partitioned AgentCore Memory store (no tenant mixing)."""

    def __init__(self) -> None:
        self._partitions: dict[str, dict[str, dict[str, Any]]] = {}

    @staticmethod
    def _namespace(account_id: str, scope: str) -> str:
        return f"acct/{account_id}/{scope}"

    def put_record(
        self,
        principal: GatewayPrincipal,
        target_account_id: str,
        scope: str,
        key: str,
        value: dict[str, Any],
    ) -> str:
        """Persist memory record strictly inside principal's account."""
        if target_account_id != principal.account_id:
            raise CrossTenantAccessError(
                f"TENANT_MEMORY_ISOLATION_VIOLATION: "
                f"{principal.account_id} cannot write {target_account_id}"
            )
        ns = self._namespace(principal.account_id, scope)
        bucket = self._partitions.setdefault(ns, {})
        bucket[key] = dict(value)
        return ns

    def query_records(
        self,
        principal: GatewayPrincipal,
        target_account_id: str,
        scope: str,
    ) -> dict[str, dict[str, Any]]:
        """Read memory records strictly from principal's account."""
        if target_account_id != principal.account_id:
            raise CrossTenantAccessError(
                f"TENANT_MEMORY_ISOLATION_VIOLATION: "
                f"{principal.account_id} cannot read {target_account_id}"
            )
        ns = self._namespace(principal.account_id, scope)
        return dict(self._partitions.get(ns, {}))


class AgentCoreGatewayProxy:
    """Routes <Target>___<Tool> invocations after JWT + tenant checks."""

    def __init__(
        self, memory: AgentCoreMemoryStore | None = None
    ) -> None:
        self.gateway_arn = GATEWAY_ARN
        self.memory = memory or AgentCoreMemoryStore()

    @staticmethod
    def parse_action(action: str) -> tuple[str, str]:
        """Parse and validate strict <Target>___<Tool> action string."""
        if "*" in action or action.count("___") != 1:
            raise GatewayRoutingError(
                f"Invalid <Target>___<Tool> action: {action}"
            )
        target, tool_name = action.split("___", 1)
        if not target or not tool_name:
            raise GatewayRoutingError(f"Empty target or tool: {action}")
        return target, tool_name

    def invoke(
        self,
        *,
        token: str,
        action: str,
        target_account_id: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Authenticate token, verify target scope, and dispatch tool."""
        principal = authenticate_token(token)
        if target_account_id != principal.account_id:
            raise CrossTenantAccessError(
                f"Cross-account blocked: token {principal.account_id}"
                f" != target {target_account_id}"
            )

        target, tool_name = self.parse_action(action)
        allowed_for_target = ALLOWED_TARGET_TOOLS.get(target, set())
        if tool_name not in allowed_for_target:
            raise GatewayRoutingError(
                f"Tool denied by Gateway registry: {action}"
            )
        if action not in principal.allowed_actions:
            raise GatewayRoutingError(
                f"Caller {principal.subject} lacks scope for {action}"
            )

        args = arguments or {}
        mem = self.memory.query_records(
            principal, principal.account_id, "ops-context"
        )
        return {
            "gateway_arn": self.gateway_arn,
            "principal_type": principal.principal_type,
            "subject": principal.subject,
            "account_id": principal.account_id,
            "target": target,
            "tool": tool_name,
            "memory_keys_visible": sorted(mem.keys()),
            "arguments": args,
            "status": "INVOKED_ISOLATED",
        }


def main() -> int:
    """Demonstrate Gateway JWT auth, routing, and tenant isolation."""
    memory = AgentCoreMemoryStore()
    proxy = AgentCoreGatewayProxy(memory=memory)

    prod_tok = issue_gateway_token(
        subject="orderflow-aws-triage-agent",
        principal_type="AgentCore::OAuthUser",
        account_id="111122223333",
        environment="prod",
        allowed_actions=[
            "cloudwatch___get_metric_data",
            "aurora___describe_db_clusters",
        ],
    )
    stg_tok = issue_gateway_token(
        subject="arn:aws:iam::222233334444:role/orderflow-stg-ops",
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
        "stg_chaos_note",
        {"secret_staging_ip": "10.99.4.12"},
    )
    memory.put_record(
        prod_p,
        "111122223333",
        "ops-context",
        "prod_aurora_status",
        {"cluster": "orderflow-pg18", "state": "available"},
    )
    res = proxy.invoke(
        token=prod_tok,
        action="aurora___describe_db_clusters",
        target_account_id="111122223333",
        arguments={"db_cluster_identifier": "orderflow-pg18"},
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
