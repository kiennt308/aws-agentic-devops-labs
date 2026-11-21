# Copyright (c) 2026 Kien Nguyen (Apache-2.0)
"""In-memory SQLite correlator for Security Hub AI & OCSF 2004."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

CH08_DIR = Path(__file__).resolve().parent
INVENTORY_PATH = CH08_DIR / "01-security-hub-ai-inventory.json"
OCSF_PATH = CH08_DIR / "02-ocsf-findings-dataset.json"

SCHEMA_SQL = """
CREATE TABLE ai_inventory (
    asset_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    service TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    discovery_source TEXT NOT NULL,
    approval_status TEXT NOT NULL,
    sbom_packages TEXT NOT NULL,
    queried_domain TEXT,
    dst_ip TEXT
);
CREATE TABLE ocsf_findings (
    finding_uid TEXT PRIMARY KEY,
    class_uid INTEGER NOT NULL,
    ocsf_version TEXT NOT NULL,
    upstream_ext TEXT NOT NULL,
    severity TEXT NOT NULL,
    account_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    delegator_arn TEXT NOT NULL,
    title TEXT NOT NULL
);
CREATE TABLE guardduty_ai_alerts (
    alert_id TEXT PRIMARY KEY,
    finding_type TEXT NOT NULL,
    category TEXT NOT NULL,
    account_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    model_id TEXT NOT NULL,
    anomalous_tokens INTEGER NOT NULL,
    estimated_burst_usd REAL NOT NULL
);
CREATE TABLE cloudtrail_sessions (
    event_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    session_id TEXT NOT NULL,
    access_key_id TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL
);
CREATE TABLE vpc_flow_logs (
    flow_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    action TEXT NOT NULL
);
"""

SHADOW_AI_SQL = """
SELECT
    asset_id,
    account_id,
    region,
    service,
    resource_id,
    discovery_source,
    approval_status,
    sbom_packages,
    queried_domain,
    dst_ip
FROM ai_inventory
WHERE approval_status != 'APPROVED'
  AND (
      sbom_packages LIKE '%ollama%'
      OR sbom_packages LIKE '%vllm%'
      OR discovery_source = 'GUARDDUTY_DNS'
  )
ORDER BY asset_id;
"""

CORRELATE_THREAT_SQL = """
SELECT
    o.finding_uid,
    o.class_uid,
    o.ocsf_version,
    o.upstream_ext,
    o.agent_id,
    o.delegator_arn,
    g.finding_type,
    g.category,
    g.anomalous_tokens,
    g.estimated_burst_usd,
    c.principal_arn,
    c.session_id,
    c.access_key_id,
    v.src_ip,
    v.dst_ip,
    v.dst_port,
    v.bytes_sent,
    i.queried_domain
FROM ocsf_findings AS o
JOIN guardduty_ai_alerts AS g
  ON o.account_id = g.account_id
 AND o.principal_arn = g.principal_arn
 AND o.src_ip = g.src_ip
JOIN cloudtrail_sessions AS c
  ON o.account_id = c.account_id
 AND o.principal_arn = c.principal_arn
 AND o.session_id = c.session_id
JOIN vpc_flow_logs AS v
  ON o.account_id = v.account_id
 AND o.src_ip = v.src_ip
LEFT JOIN ai_inventory AS i
  ON o.account_id = i.account_id
 AND v.dst_ip = i.dst_ip
WHERE o.class_uid = 2004
  AND g.category = 'cost_harvesting'
  AND v.action = 'ACCEPT';
"""


def load_in_memory_db(
    inventory_path: Path = INVENTORY_PATH,
    ocsf_path: Path = OCSF_PATH,
) -> sqlite3.Connection:
    """Create ephemeral :memory: SQLite DB and ingest security feeds."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_SQL)

    inv = json.loads(inventory_path.read_text(encoding="utf-8"))
    for item in inv["assets"]:
        conn.execute(
            """
            INSERT INTO ai_inventory VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item["asset_id"],
                item["account_id"],
                item["region"],
                item["service"],
                item["resource_id"],
                item["discovery_source"],
                item["approval_status"],
                ",".join(item.get("sbom_packages", [])),
                item.get("queried_domain"),
                item.get("dst_ip"),
            ),
        )

    data = json.loads(ocsf_path.read_text(encoding="utf-8"))
    for f in data["ocsf_detection_findings"]:
        conn.execute(
            """
            INSERT INTO ocsf_findings VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f["finding_uid"],
                f["class_uid"],
                f["ocsf_version"],
                f["upstream_extensions_version"],
                f["severity"],
                f["account_id"],
                f["principal_arn"],
                f["src_ip"],
                f["ai_agent"]["agent_id"],
                f["ai_agent"]["session_id"],
                f["delegation"]["delegator_arn"],
                f["title"],
            ),
        )

    for g in data["guardduty_ai_alerts"]:
        conn.execute(
            """
            INSERT INTO guardduty_ai_alerts VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                g["alert_id"],
                g["finding_type"],
                g["category"],
                g["account_id"],
                g["principal_arn"],
                g["src_ip"],
                g["model_id"],
                g["anomalous_tokens"],
                g["estimated_burst_usd"],
            ),
        )

    for c in data["cloudtrail_iam_sessions"]:
        conn.execute(
            """
            INSERT INTO cloudtrail_sessions VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                c["event_id"],
                c["account_id"],
                c["principal_arn"],
                c["session_id"],
                c["access_key_id"],
                c["src_ip"],
                c["user_agent"],
            ),
        )

    for v in data["vpc_flow_logs"]:
        conn.execute(
            "INSERT INTO vpc_flow_logs VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                v["flow_id"],
                v["account_id"],
                v["src_ip"],
                v["dst_ip"],
                v["dst_port"],
                v["bytes_sent"],
                v["action"],
            ),
        )
    conn.commit()
    return conn


def run_correlation(
    inventory_path: Path = INVENTORY_PATH,
    ocsf_path: Path = OCSF_PATH,
) -> dict[str, Any]:
    """Flag shadow AI assets and return OCSF 2004 SQL correlation."""
    conn = load_in_memory_db(inventory_path, ocsf_path)
    try:
        shadow = [
            dict(row) for row in conn.execute(SHADOW_AI_SQL).fetchall()
        ]
        correlated = [
            dict(row)
            for row in conn.execute(CORRELATE_THREAT_SQL).fetchall()
        ]
    finally:
        conn.close()
    return {
        "shadow_ai_findings": shadow,
        "correlated_incidents": correlated,
    }


def interactive_shell(conn: sqlite3.Connection) -> None:
    """Optional SQL REPL over in-memory OCSF and Security Hub tables."""
    print("Enter SQL query (or 'quit' to exit):")
    while True:
        try:
            line = input("ocsf-sql> ").strip()
        except EOFError:
            break
        if not line or line.lower() in {"quit", "exit"}:
            break
        try:
            rows = [dict(r) for r in conn.execute(line).fetchall()]
            print(json.dumps(rows, indent=2))
        except sqlite3.Error as exc:
            print(f"SQL error: {exc}")


def main() -> None:
    """Execute correlation queries and verify expected security hits."""
    parser = argparse.ArgumentParser(description="OCSF SQLite correlator")
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Open an interactive SQLite prompt after summary.",
    )
    args = parser.parse_args()

    report = run_correlation()
    assert len(report["shadow_ai_findings"]) == 3
    assert len(report["correlated_incidents"]) == 1
    hit = report["correlated_incidents"][0]
    assert hit["class_uid"] == 2004
    assert hit["dst_ip"] == "198.51.100.77"
    assert hit["queried_domain"] == "api.unapproved-llm.example"
    print(json.dumps(report, indent=2))

    if args.interactive:
        conn = load_in_memory_db()
        try:
            interactive_shell(conn)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
