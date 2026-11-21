# Copyright (c) 2026 Kien Nguyen (Apache-2.0)
"""In-memory SQLite engine for FOCUS 1.2 AWS Agentic FinOps."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

CH09_DIR = Path(__file__).resolve().parent
DATASET_PATH = CH09_DIR / "02-focus12-agentic-dataset.json"

SCHEMA_SQL = """
CREATE TABLE focus_1_2_aws (
    ChargeId TEXT PRIMARY KEY,
    ServiceName TEXT NOT NULL,
    ChargeCategory TEXT NOT NULL,
    UsageUnit TEXT NOT NULL,
    UsageQuantity REAL NOT NULL,
    ListCost REAL NOT NULL,
    ContractedCost REAL NOT NULL,
    BilledCost REAL NOT NULL,
    EffectiveCost REAL NOT NULL,
    UncachedBaselineCost REAL NOT NULL,
    InvoiceId TEXT NOT NULL,
    CapacityReservationId TEXT NOT NULL,
    orderflow_team TEXT NOT NULL,
    agent_space_id TEXT NOT NULL,
    cache_mode TEXT NOT NULL
);
CREATE TABLE team_outcomes (
    orderflow_team TEXT PRIMARY KEY,
    agent_space_id TEXT NOT NULL,
    incidents_resolved INTEGER NOT NULL
);
"""

TEAM_UNIT_ECONOMICS_SQL = """
SELECT
    f.orderflow_team,
    o.agent_space_id,
    o.incidents_resolved,
    ROUND(SUM(f.ListCost), 2) AS total_list_cost,
    ROUND(SUM(f.ContractedCost), 2) AS total_contracted_cost,
    ROUND(SUM(f.BilledCost), 2) AS total_billed_cost,
    ROUND(SUM(f.EffectiveCost), 2) AS total_effective_cost,
    ROUND(SUM(f.EffectiveCost) / o.incidents_resolved, 4)
        AS cost_per_incident_resolved
FROM focus_1_2_aws AS f
JOIN team_outcomes AS o
  ON f.orderflow_team = o.orderflow_team
GROUP BY f.orderflow_team, o.agent_space_id, o.incidents_resolved
ORDER BY total_effective_cost DESC;
"""

CACHE_RECONCILIATION_SQL = """
SELECT
    ServiceName,
    cache_mode,
    COUNT(*) AS line_items,
    ROUND(SUM(UncachedBaselineCost), 2) AS uncached_baseline_usd,
    ROUND(SUM(EffectiveCost), 2) AS cached_effective_usd,
    ROUND(SUM(UncachedBaselineCost - EffectiveCost), 2)
        AS cache_savings_usd,
    ROUND(
        100.0 * SUM(UncachedBaselineCost - EffectiveCost)
        / SUM(UncachedBaselineCost),
        2
    ) AS cache_savings_pct
FROM focus_1_2_aws
WHERE ServiceName = 'Amazon Bedrock'
GROUP BY ServiceName, cache_mode
ORDER BY cache_savings_usd DESC;
"""


def load_focus_db(
    dataset_path: Path = DATASET_PATH,
) -> sqlite3.Connection:
    """Ingest FOCUS 1.2 dataset into ephemeral :memory: SQLite DB."""
    raw = json.loads(dataset_path.read_text(encoding="utf-8"))
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_SQL)

    for outcome in raw["team_outcomes"]:
        conn.execute(
            "INSERT INTO team_outcomes VALUES (?, ?, ?)",
            (
                outcome["orderflow_team"],
                outcome["agent_space_id"],
                outcome["incidents_resolved"],
            ),
        )

    for row in raw["records"]:
        tags = row["Tags"]
        conn.execute(
            """
            INSERT INTO focus_1_2_aws VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["ChargeId"],
                row["ServiceName"],
                row["ChargeCategory"],
                row["UsageUnit"],
                row["UsageQuantity"],
                row["ListCost"],
                row["ContractedCost"],
                row["BilledCost"],
                row["EffectiveCost"],
                row["UncachedBaselineCost"],
                row["InvoiceId"],
                row["CapacityReservationId"],
                tags["orderflow_team"],
                tags["agent_space_id"],
                tags["cache_mode"],
            ),
        )
    conn.commit()
    return conn


def run_finops_queries(
    dataset_path: Path = DATASET_PATH,
) -> dict[str, Any]:
    """Compute FOCUS 1.2 team unit economics and cache reconciliation."""
    conn = load_focus_db(dataset_path)
    try:
        teams = [
            dict(r)
            for r in conn.execute(TEAM_UNIT_ECONOMICS_SQL).fetchall()
        ]
        cache_recon = [
            dict(r)
            for r in conn.execute(CACHE_RECONCILIATION_SQL).fetchall()
        ]
    finally:
        conn.close()
    total_eff = round(sum(t["total_effective_cost"] for t in teams), 2)
    total_inc = sum(t["incidents_resolved"] for t in teams)
    return {
        "team_unit_economics": teams,
        "cache_reconciliation": cache_recon,
        "fleet_cost_per_incident_usd": round(total_eff / total_inc, 4),
    }


def main() -> None:
    """Execute FOCUS 1.2 FinOps analytics and print JSON report."""
    report = run_finops_queries()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
