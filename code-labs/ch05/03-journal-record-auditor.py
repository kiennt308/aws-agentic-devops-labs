"""Immutable JournalRecord SHA-256 hash-chain auditor for DevOps Agent.

Copyright (c) 2026 Kien Nguyen
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
DEFAULT_TRACE = HERE / "04-journal-records-valid.json"
GENESIS_HASH = "sha256:" + ("0" * 43)

REQUIRED_FIELDS = (
    "agentSpaceId",
    "executionId",
    "recordId",
    "recordType",
    "content",
    "createdAt",
)


class JournalAuditError(ValueError):
    """Raised when JournalRecord schema or SHA-256 hash chain fails."""


@dataclass(frozen=True)
class AuditReport:
    """Verification summary produced by audit_journal_records()."""

    agent_space_id: str
    execution_id: str
    record_count: int
    head_hash: str
    chain_valid: bool


def compute_record_hash(record: dict[str, Any]) -> str:
    """Compute canonical SHA-256 digest for a single JournalRecord."""
    payload: dict[str, Any] = {
        field: record[field] for field in REQUIRED_FIELDS
    }
    payload["prevHash"] = record["prevHash"]
    if "userReference" in record:
        payload["userReference"] = record["userReference"]

    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"sha256:{encoded}"


def _parse_iso_utc(raw: str) -> datetime:
    """Parse ISO-8601 UTC timestamp string strictly."""
    if not isinstance(raw, str) or not raw.strip():
        raise JournalAuditError("createdAt must be a non-empty string")
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def audit_journal_records(records: list[dict[str, Any]]) -> AuditReport:
    """Verify required fields, timestamps, space scope, & hash chain."""
    if not records:
        raise JournalAuditError("JournalRecord trace cannot be empty")

    expected_prev = GENESIS_HASH
    first_space = str(records[0].get("agentSpaceId", "")).strip()
    first_exec = str(records[0].get("executionId", "")).strip()
    prev_ts: datetime | None = None
    seen_ids: set[str] = set()

    for idx, rec in enumerate(records):
        for field in REQUIRED_FIELDS:
            val = rec.get(field)
            if not isinstance(val, str) or not val.strip():
                raise JournalAuditError(
                    f"Record {idx} missing/empty required field: {field}"
                )

        if "userReference" in rec:
            uref = rec["userReference"]
            if not isinstance(uref, str) or not uref.strip():
                raise JournalAuditError(
                    f"Record {idx} has invalid userReference"
                )

        if rec["agentSpaceId"] != first_space:
            raise JournalAuditError(
                f"Record {idx} agentSpaceId mismatch: "
                f"{rec['agentSpaceId']} != {first_space}"
            )
        if rec["executionId"] != first_exec:
            raise JournalAuditError(
                f"Record {idx} executionId mismatch: "
                f"{rec['executionId']} != {first_exec}"
            )

        rid = rec["recordId"]
        if rid in seen_ids:
            raise JournalAuditError(f"Duplicate recordId: {rid}")
        seen_ids.add(rid)

        ts = _parse_iso_utc(rec["createdAt"])
        if prev_ts is not None and ts < prev_ts:
            raise JournalAuditError(
                f"Record {rid} timestamp moves backward"
            )
        prev_ts = ts

        if rec.get("prevHash") != expected_prev:
            raise JournalAuditError(
                f"Hash chain broken at {rid}: prevHash mismatch"
            )

        expected_hash = compute_record_hash(rec)
        if rec.get("recordHash") != expected_hash:
            raise JournalAuditError(
                f"Tampered record digest at {rid}"
            )
        expected_prev = expected_hash

    return AuditReport(
        agent_space_id=first_space,
        execution_id=first_exec,
        record_count=len(records),
        head_hash=expected_prev,
        chain_valid=True,
    )


def main() -> int:
    """Verify 04-journal-records-valid.json and in-memory tamper catch."""
    records = json.loads(DEFAULT_TRACE.read_text(encoding="utf-8"))
    report = audit_journal_records(records)

    tampered = [dict(r) for r in records]
    tampered[1]["content"] = "Mutated diagnostic content"
    tamper_caught = False
    try:
        audit_journal_records(tampered)
    except JournalAuditError:
        tamper_caught = True

    assert tamper_caught is True
    print(
        json.dumps(
            {
                **report.__dict__,
                "tamper_detection_verified": tamper_caught,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
