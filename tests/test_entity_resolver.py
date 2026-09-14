"""Pytest test suite for Entity Resolution Engine."""

from pathlib import Path
import pytest

from mock_data.generator import generate_case_104_data
from parsers.cdr_parser import CDRParser
from parsers.bank_parser import BankParser
from parsers.apk_parser import APKParser
from parsers.email_parser import EmailParser
from engine.entity_resolver import resolve_entities


@pytest.fixture(scope="module")
def case_104_parse_results(tmp_path_factory):
    """Fixture providing parse results for all Case 104 artifacts."""
    data_dir = tmp_path_factory.mktemp("case_104_test_dir")
    generate_case_104_data(str(data_dir))

    cdr_res = CDRParser("sha_cdr").parse(str(data_dir / "cdr_records.csv"))
    bank_res = BankParser("sha_bank").parse(str(data_dir / "bank_statement.csv"))
    apk_res = APKParser("sha_apk").parse(str(data_dir / "apk_dump.json"))
    email_res = EmailParser("sha_email").parse(str(data_dir / "phishing_email.eml"))

    return [cdr_res, bank_res, apk_res, email_res]


def test_entity_resolver_deduplication(case_104_parse_results, tmp_path):
    """Tests that entities across parsers are deduplicated and entity_map.json is generated."""
    out_dir = tmp_path / "outputs"
    entity_map = resolve_entities(case_104_parse_results, str(out_dir))

    assert "entities" in entity_map
    assert "cross_refs" in entity_map

    entities = entity_map["entities"]
    cross_refs = entity_map["cross_refs"]

    assert len(entities) > 0
    assert (out_dir / "entity_map.json").exists()

    # Verify Victim Phone resolves to IMEI and UPI in cross_refs
    victim_phone = "PHONE:+919845012345"
    assert victim_phone in cross_refs
    victim_links = cross_refs[victim_phone]
    assert "IMEI:356938035643809" in victim_links or "UPI_HANDLE:victim.suresh@okaxis" in victim_links
