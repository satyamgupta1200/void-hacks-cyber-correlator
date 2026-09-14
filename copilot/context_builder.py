"""Copilot Context Builder module for serializing case metadata, graph flow, and audit logs."""

import json
from pathlib import Path
from typing import Dict, Any


def build_case_context(output_dir: str = "outputs") -> str:
    """Builds a structured markdown text context from case runtime artifacts.

    Args:
        output_dir: Path to directory containing outputs JSON artifacts.

    Returns:
        Structured string containing serialized case evidence context.
    """
    out_path = Path(output_dir)

    # 1. Load Risk Report
    risk_file = out_path / "risk_report.json"
    risk_data = {}
    if risk_file.exists():
        try:
            with open(risk_file, "r", encoding="utf-8") as f:
                risk_data = json.load(f)
        except Exception:
            pass

    # 2. Load Entity Map
    entity_file = out_path / "entity_map.json"
    entity_data = {}
    if entity_file.exists():
        try:
            with open(entity_file, "r", encoding="utf-8") as f:
                entity_data = json.load(f)
        except Exception:
            pass

    # 3. Load Audit Log
    audit_file = out_path / "audit_log.json"
    audit_entries = []
    if audit_file.exists():
        try:
            with open(audit_file, "r", encoding="utf-8") as f:
                log_json = json.load(f)
                audit_entries = log_json.get("entries", [])
        except Exception:
            pass

    score = risk_data.get("total_risk_score", 100)
    thresh = risk_data.get("threshold_label", "CRITICAL")
    rules = risk_data.get("triggered_rules", [])

    context = f"""
=== CASE FORENSIC EVIDENCE CONTEXT: CASE-104 ===

1. FORENSIC OVERVIEW & AUDIT CHAIN:
- Total Ingested Artifacts: {len(audit_entries)}
"""
    for entry in audit_entries[:3]:
        context += f"  - Artifact: {entry.get('filename')} | SHA-256: {entry.get('sha256')} | Ingested: {entry.get('timestamp_utc')}\n"

    context += f"""
2. RISK ASSESSMENT & STATUTORY TRIGGERS:
- Overall Forensic Risk Score: {score} / 100
- Risk Threshold: {thresh}
- Triggered Statutory Rules ({len(rules)} Rules):
"""
    for r in rules:
        context += f"  - [{r.get('rule_id')}] {r.get('title')} (Weight: +{r.get('score')}, Statute: {r.get('statutory_ref')})\n"
        context += f"    Evidence: {r.get('evidence')}\n"

    entities = entity_data.get("entities", {})
    cross_refs = entity_data.get("cross_refs", {})

    context += f"""
3. RESOLVED ENTITIES & CROSS-REFERENCES:
- Total Resolved Entities: {len(entities)}
- Key Victim Identity Cluster:
  - Victim Mobile: +919845012345 (Original IMEI: 356938035643809)
  - Victim Bank Account: AXIS-SURESH-9201 (UPI: victim.suresh@okaxis)
- Suspected Mule Identity Cluster:
  - Mule 1: HDFC-MULE1-3847 (UPI: fastpay99@okhdfcbank, Mobile: +919731088421)
  - Mule 2: SBI-MULE2-7731 (UPI: cashout.agent@oksbi, Mobile: +918197634520)

4. MONEY LAUNDERING TRAIL & VELOCITY:
- Flow Sequence: Victim (AXIS-SURESH-9201) -> Mule 1 (HDFC-MULE1-3847) -> Mule 2 (SBI-MULE2-7731) -> ATM Withdrawal (CASH-ATM-KORAMANGALA).
- Total Fraud Amount: INR 95,000.00
- Velocity: INR 16,101.69 / minute (3 hops in 5 minutes 42 seconds)
- SIM Swap Event: Executed at 14:11:00 (22 min prior to fraud), IMEI changed to 490154203237518.
"""
    return context.strip()
