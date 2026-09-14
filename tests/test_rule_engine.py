"""Pytest test suite for Forensic Rule Engine and SIM Swap Detector."""

import pytest
from mock_data.generator import generate_case_104_data
from parsers.cdr_parser import CDRParser
from parsers.bank_parser import BankParser
from parsers.apk_parser import APKParser
from parsers.email_parser import EmailParser
from engine.entity_resolver import resolve_entities
from engine.sim_swap_detector import detect_sim_swaps
from engine.rule_engine import RuleEngine


@pytest.fixture(scope="module")
def case_104_data(tmp_path_factory):
    """Fixture providing all case 104 data."""
    data_dir = tmp_path_factory.mktemp("case_104_rules")
    generate_case_104_data(str(data_dir))

    p1 = CDRParser("sha_cdr").parse(str(data_dir / "cdr_records.csv"))
    p2 = BankParser("sha_bank").parse(str(data_dir / "bank_statement.csv"))
    p3 = APKParser("sha_apk").parse(str(data_dir / "apk_dump.json"))
    p4 = EmailParser("sha_email").parse(str(data_dir / "phishing_email.eml"))

    results = [p1, p2, p3, p4]
    entity_map = resolve_entities(results, str(data_dir / "outputs"))

    all_events = []
    for r in results:
        all_events.extend(r.events)

    return {
        "entity_map": entity_map,
        "all_events": all_events,
        "cdr_events": p1.events,
        "bank_events": p2.events,
        "data_dir": data_dir,
    }


def test_sim_swap_detector(case_104_data):
    """Tests SIM swap anomaly detection on Case 104 CDR dataset."""
    swaps = detect_sim_swaps(case_104_data["cdr_events"], case_104_data["bank_events"])

    assert len(swaps) > 0
    victim_swap = swaps[0]

    assert victim_swap["msisdn"] == "+919845012345"
    assert victim_swap["old_imei"] == "356938035643809"
    assert victim_swap["new_imei"] == "490154203237518"
    assert victim_swap["minutes_before_next_transaction"] <= 30


def test_rule_engine_risk_report(case_104_data, tmp_path):
    """Tests Rule Engine evaluation and asserts risk score >= 80 (CRITICAL threshold)."""
    engine = RuleEngine()
    out_dir = tmp_path / "outputs"
    report = engine.evaluate(case_104_data["entity_map"], case_104_data["all_events"], str(out_dir))

    assert report["total_risk_score"] >= 80
    assert report["threshold_label"] == "CRITICAL"
    assert (out_dir / "risk_report.json").exists()

    triggered_ids = [r["rule_id"] for r in report["triggered_rules"]]
    assert "R-001" in triggered_ids
    assert "R-002" in triggered_ids
    assert "R-004" in triggered_ids
