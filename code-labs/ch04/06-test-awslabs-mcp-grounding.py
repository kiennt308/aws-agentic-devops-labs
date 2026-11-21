"""Live Streamable HTTP MCP grounding test for OrderFlow CFN IaC.

Copyright (c) 2026 Kien Nguyen
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import asyncio
from importlib import util
import json
from pathlib import Path
import socket
import sys
import threading
import time
from typing import Any
from mcp import Client
import pytest
import uvicorn
import yaml

CH04_DIR = Path(__file__).resolve().parent
SERVER_FILE = CH04_DIR / "01-orderflow-awslabs-mcp-server.py"
VALID_IAC = CH04_DIR / "02-orderflow-iac-valid.yaml"
INVALID_IAC = CH04_DIR / "04-hallucinated-iac-negative.yaml"
DEFAULT_PORT = 18804


def _load_server_module():
    """Dynamically load 01-orderflow-awslabs-mcp-server.py."""
    spec = util.spec_from_file_location("orderflow_mcp_srv", SERVER_FILE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {SERVER_FILE}")
    mod = util.module_from_spec(spec)
    sys.modules["orderflow_mcp_srv"] = mod
    spec.loader.exec_module(mod)
    return mod


def _pick_port(preferred: int = DEFAULT_PORT) -> int:
    """Bind preferred port 18804 if free, else an ephemeral port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])


def _wait_port(host: str, port: int, timeout: float = 5.0) -> None:
    """Wait until background Uvicorn socket accepts connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"MCP server failed to bind {host}:{port}")


class _CfnYamlLoader(yaml.SafeLoader):
    """SafeLoader supporting CloudFormation intrinsic tags if used."""


def _cfn_tag_passthrough(loader: yaml.Loader, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


for _tag in ("!Ref", "!GetAtt", "!Sub", "!Join", "!If"):
    _CfnYamlLoader.add_constructor(_tag, _cfn_tag_passthrough)


def _load_cfn_template(path: Path) -> dict[str, Any]:
    """Load CloudFormation YAML safely into a Python dictionary."""
    data = yaml.load(
        path.read_text(encoding="utf-8"), Loader=_CfnYamlLoader
    )
    assert isinstance(data, dict)
    return data


async def _validate_template_via_mcp(
    client: Client, template_path: Path
) -> dict[str, Any]:
    """Validate every resource and property via live MCP tool calls."""
    doc = _load_cfn_template(template_path)
    resources: dict[str, Any] = doc.get("Resources", {})
    failures: list[dict[str, Any]] = []
    checked_count = 0

    for logical_id, res in resources.items():
        res_type = res["Type"]
        props = res.get("Properties", {}) or {}
        if not props:
            res_msg = await client.call_tool(
                "aws_docs_lookup_cfn_property",
                {"resource_type": res_type},
            )
            payload = json.loads(res_msg.content[0].text)
            checked_count += 1
            if not payload["valid"]:
                failures.append({"logical_id": logical_id, **payload})
            continue

        for prop_name in props:
            res_msg = await client.call_tool(
                "aws_docs_lookup_cfn_property",
                {
                    "resource_type": res_type,
                    "property_name": prop_name,
                },
            )
            assert res_msg.is_error is False
            payload = json.loads(res_msg.content[0].text)
            checked_count += 1
            if not payload["valid"]:
                failures.append({"logical_id": logical_id, **payload})

    return {
        "template": template_path.name,
        "checked": checked_count,
        "passed": len(failures) == 0,
        "failures": failures,
    }


class LiveMcpServerRunner:
    """Thread-hosted Uvicorn lifecycle for Streamable HTTP MCP server."""

    def __init__(self, preferred_port: int = DEFAULT_PORT) -> None:
        self.mod = _load_server_module()
        self.port = _pick_port(preferred_port)
        app = self.mod.build_stateless_http_app()
        cfg = uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_level="error"
        )
        self.server = uvicorn.Server(cfg)
        self.thread = threading.Thread(
            target=self.server.run, daemon=True
        )

    def __enter__(self) -> str:
        self.thread.start()
        _wait_port("127.0.0.1", self.port)
        return f"http://127.0.0.1:{self.port}/mcp"

    def __exit__(self, *args: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=3.0)


@pytest.fixture(scope="module")
def mcp_url():
    """Boot live 01-orderflow-awslabs-mcp-server.py for module tests."""
    with LiveMcpServerRunner(DEFAULT_PORT) as url:
        yield url


def test_mcp_protocol_and_ops_tools(mcp_url: str) -> None:
    """Verify MCP 2026-07-28 tools over Streamable HTTP."""

    async def _run() -> None:
        async with Client(mcp_url) as client:
            assert client.protocol_version == "2026-07-28"
            listed = await client.list_tools()
            names = sorted(t.name for t in listed.tools)
            assert names == [
                "aws_docs_lookup_cfn_property",
                "cloudwatch_get_metric_data",
                "eks_list_insights",
            ]
            cw = await client.call_tool(
                "cloudwatch_get_metric_data",
                {
                    "namespace": "AWS/RDS",
                    "metric_name": "DatabaseConnections",
                    "resource_id": "orderflow-pg18",
                },
            )
            cw_data = json.loads(cw.content[0].text)
            assert cw_data["datapoints"][-1]["value"] == 412.0

            eks = await client.call_tool(
                "eks_list_insights",
                {"cluster_name": "orderflow-eks-prod"},
            )
            eks_data = json.loads(eks.content[0].text)
            assert eks_data["insight_count"] == 2

    asyncio.run(_run())


def test_valid_iac_passes_and_hallucinated_iac_fails(
    mcp_url: str,
) -> None:
    """Valid CFN passes grounding while hallucinated template fails."""

    async def _run() -> tuple[dict[str, Any], dict[str, Any]]:
        async with Client(mcp_url) as client:
            ok = await _validate_template_via_mcp(client, VALID_IAC)
            bad = await _validate_template_via_mcp(client, INVALID_IAC)
            return ok, bad

    ok_res, bad_res = asyncio.run(_run())
    assert ok_res["passed"] is True
    assert ok_res["failures"] == []

    assert bad_res["passed"] is False
    bad_props = {f.get("property_name") for f in bad_res["failures"]}
    bad_types = {f.get("resource_type") for f in bad_res["failures"]}
    assert "AutoMagicEncrypt" in bad_props
    assert "AccessControl" in bad_props
    assert "AWS::CloudTrail::EventDataStore" in bad_types


def main() -> int:
    """Run live MCP schema grounding verification as standalone script."""

    async def _run(url: str) -> dict[str, Any]:
        async with Client(url) as client:
            ok = await _validate_template_via_mcp(client, VALID_IAC)
            bad = await _validate_template_via_mcp(client, INVALID_IAC)
            return {
                "mcp_url": url,
                "protocol": client.protocol_version,
                "valid_check": ok,
                "negative_check": bad,
            }

    with LiveMcpServerRunner(DEFAULT_PORT) as url:
        report = asyncio.run(_run(url))

    assert report["valid_check"]["passed"] is True
    assert report["negative_check"]["passed"] is False
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
