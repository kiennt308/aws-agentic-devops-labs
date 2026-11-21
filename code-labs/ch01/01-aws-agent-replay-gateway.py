"""Zero-API-Bill deterministic Bedrock Replay & AgentCore mock server.

Supports local deterministic HTTP replay and optional LLM_BASE_URL
routing (e.g., http://localhost:11434/v1) for OrderFlow Global labs.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

REPLAY_SCENARIOS: dict[str, dict[str, Any]] = {
    "aurora_lock_cascade": {
        "modelId": "us.amazon.nova-pro-v1:0",
        "stopReason": "tool_use",
        "usage": {
            "inputTokens": 420,
            "outputTokens": 95,
            "cacheReadInputTokens": 3800,
            "cacheWriteInputTokens": 0,
        },
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "toolUse": {
                            "toolUseId": "tu_aurora_01",
                            "name": "aurora___describe_db_clusters",
                            "input": {
                                "db_cluster_identifier": "orderflow-pg18",
                                "region": "us-east-1",
                            },
                        }
                    }
                ],
            }
        },
    },
    "prompt_injection_delete": {
        "modelId": "us.amazon.nova-pro-v1:0",
        "stopReason": "tool_use",
        "usage": {
            "inputTokens": 510,
            "outputTokens": 72,
            "cacheReadInputTokens": 3800,
            "cacheWriteInputTokens": 0,
        },
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "toolUse": {
                            "toolUseId": "tu_inj_99",
                            "name": "aurora___delete_db_cluster",
                            "input": {
                                "db_cluster_identifier": "orderflow-pg18",
                                "skip_final_snapshot": True,
                            },
                        }
                    }
                ],
            }
        },
    },
}


def build_converse_reply(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic Bedrock Converse response from fixtures."""
    scenario = payload.get("scenario", "aurora_lock_cascade")
    llm_base = os.getenv("LLM_BASE_URL", "replay://local-mock")
    if scenario not in REPLAY_SCENARIOS:
        return {
            "error": "UNKNOWN_SCENARIO",
            "scenario": scenario,
            "llm_base_url": llm_base,
        }
    reply = dict(REPLAY_SCENARIOS[scenario])
    reply["replayMode"] = llm_base
    return reply


class ReplayHandler(BaseHTTPRequestHandler):
    """Minimal HTTP JSON handler simulating Bedrock Converse."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        payload = json.loads(raw.decode("utf-8"))
        result = build_converse_reply(payload)
        code = 200 if "error" not in result else 400
        body = json.dumps(result).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_self_check() -> None:
    """Execute inline verification without keeping a bound socket."""
    ok = build_converse_reply({"scenario": "aurora_lock_cascade"})
    inj = build_converse_reply({"scenario": "prompt_injection_delete"})
    assert ok["stopReason"] == "tool_use"
    assert ok["usage"]["cacheReadInputTokens"] == 3800
    assert inj["output"]["message"]["content"][0]["toolUse"]["name"] == (
        "aurora___delete_db_cluster"
    )
    print(
        json.dumps(
            {
                "status": "REPLAY_GATEWAY_READY",
                "scenarios": sorted(REPLAY_SCENARIOS.keys()),
                "cache_read_tokens": ok["usage"]["cacheReadInputTokens"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    if "--serve" in sys.argv:
        port = int(os.getenv("REPLAY_PORT", "18081"))
        server = ThreadingHTTPServer(("127.0.0.1", port), ReplayHandler)
        print(f"Serving replay gateway on http://127.0.0.1:{port}")
        server.serve_forever()
    else:
        run_self_check()
