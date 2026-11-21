"""OrderFlow awslabs/mcp Streamable HTTP Server (MCP 2026-07-28).

Copyright (c) 2026 Kien Nguyen
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
from typing import Any
from mcp.server.mcpserver import MCPServer, ResourceSecurity

mcp = MCPServer(
    name="orderflow-awslabs-mcp",
    title="OrderFlow AWS Grounded Ops MCP Server",
    version="1.0.0",
    resource_security=ResourceSecurity(
        reject_path_traversal=True,
        reject_absolute_paths=True,
        reject_null_bytes=True,
    ),
)

CFN_SCHEMA_DOCS: dict[str, dict[str, Any]] = {
    "AWS::S3::Bucket": {
        "status": "ACTIVE",
        "allowed_properties": [
            "BucketName",
            "BucketEncryption",
            "PublicAccessBlockConfiguration",
            "OwnershipControls",
            "VersioningConfiguration",
            "Tags",
        ],
        "deprecated_properties": {
            "AccessControl": (
                "Legacy bucket ACLs are banned; use "
                "OwnershipControls=BucketOwnerEnforced."
            )
        },
    },
    "AWS::KMS::Key": {
        "status": "ACTIVE",
        "allowed_properties": [
            "Description",
            "EnableKeyRotation",
            "Enabled",
            "KeyPolicy",
            "KeySpec",
            "KeyUsage",
            "MultiRegion",
            "PendingWindowInDays",
            "Tags",
        ],
        "deprecated_properties": {},
    },
    "AWS::Events::EventBus": {
        "status": "ACTIVE",
        "allowed_properties": [
            "Name",
            "Description",
            "KmsKeyIdentifier",
            "DeadLetterConfig",
            "Tags",
        ],
        "deprecated_properties": {},
    },
    "AWS::CloudTrail::EventDataStore": {
        "status": "RETIRED",
        "reason": (
            "CloudTrail Lake closed to new accounts May 31, 2026; "
            "route trails to KMS-encrypted multi-region S3 instead."
        ),
        "allowed_properties": [],
        "deprecated_properties": {},
    },
}


@mcp.tool()
def aws_docs_lookup_cfn_property(
    resource_type: str,
    property_name: str = "",
) -> str:
    """Validate CloudFormation resource types and property names."""
    schema = CFN_SCHEMA_DOCS.get(resource_type)
    if schema is None:
        return json.dumps(
            {
                "resource_type": resource_type,
                "property_name": property_name,
                "valid": False,
                "retired": False,
                "hallucinated": True,
                "reason": f"Unknown CFN resource type: {resource_type}",
            }
        )

    if schema["status"] == "RETIRED":
        return json.dumps(
            {
                "resource_type": resource_type,
                "property_name": property_name,
                "valid": False,
                "retired": True,
                "hallucinated": False,
                "reason": schema["reason"],
            }
        )

    allowed = schema["allowed_properties"]
    deprecated = schema["deprecated_properties"]
    if not property_name:
        return json.dumps(
            {
                "resource_type": resource_type,
                "valid": True,
                "retired": False,
                "allowed_properties": allowed,
            }
        )

    if property_name in deprecated:
        return json.dumps(
            {
                "resource_type": resource_type,
                "property_name": property_name,
                "valid": False,
                "retired": True,
                "hallucinated": False,
                "reason": deprecated[property_name],
                "allowed_properties": allowed,
            }
        )

    is_valid = property_name in allowed
    return json.dumps(
        {
            "resource_type": resource_type,
            "property_name": property_name,
            "valid": is_valid,
            "retired": False,
            "hallucinated": not is_valid,
            "allowed_properties": allowed,
            "reason": (
                "Grounded in official CFN spec"
                if is_valid
                else f"Hallucinated property: {property_name}"
            ),
        }
    )


@mcp.tool()
def cloudwatch_get_metric_data(
    namespace: str = "AWS/RDS",
    metric_name: str = "DatabaseConnections",
    resource_id: str = "orderflow-pg18",
) -> str:
    """Return offline grounded CloudWatch metric datapoints."""
    series: dict[tuple[str, str], list[dict[str, Any]]] = {
        ("AWS/RDS", "DatabaseConnections"): [
            {"timestamp": "2026-11-20T01:55:00Z", "value": 118.0},
            {"timestamp": "2026-11-20T02:00:00Z", "value": 412.0},
        ],
        ("AWS/VpcLattice", "HTTPCode_Target_5XX_Count"): [
            {"timestamp": "2026-11-20T01:55:00Z", "value": 1.0},
            {"timestamp": "2026-11-20T02:00:00Z", "value": 184.0},
        ],
        ("AWS/Lambda", "Throttles"): [
            {"timestamp": "2026-11-20T01:55:00Z", "value": 0.0},
            {"timestamp": "2026-11-20T02:00:00Z", "value": 37.0},
        ],
    }
    points = series.get(
        (namespace, metric_name),
        [{"timestamp": "2026-11-20T02:00:00Z", "value": 0.0}],
    )
    return json.dumps(
        {
            "namespace": namespace,
            "metric_name": metric_name,
            "resource_id": resource_id,
            "datapoints": points,
        }
    )


@mcp.tool()
def eks_list_insights(
    cluster_name: str = "orderflow-eks-prod",
) -> str:
    """Return EKS cluster upgrade and Lattice readiness insights."""
    return json.dumps(
        {
            "cluster_name": cluster_name,
            "insight_count": 2,
            "insights": [
                {
                    "id": "ins-eks-k8s-api-01",
                    "category": "UPGRADE_READINESS",
                    "status": "PASSING",
                    "summary": "Zero deprecated Kubernetes APIs used",
                },
                {
                    "id": "ins-eks-lattice-02",
                    "category": "CONFIGURATION",
                    "status": "WARNING",
                    "summary": "Target group orderflow-checkout 5xx",
                },
            ],
        }
    )


def build_stateless_http_app():
    """Return stateless Streamable HTTP ASGI app for MCP 2026-07-28."""
    return mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )


if __name__ == "__main__":
    port = int(os.getenv("MCP_PORT", "18804"))
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=port,
        stateless_http=True,
        json_response=True,
    )
