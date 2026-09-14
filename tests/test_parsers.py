"""Pytest test suite for Phase 1 parsers, forensic hasher, and mock data."""

import json
import tempfile
from pathlib import Path
import pytest

from mock_data.generator import generate_case_104_data
from parsers.hasher import hash_file, verify_file, get_audit_log, TamperDetectedError
from parsers.cdr_parser import CDRParser
from parsers.bank_parser import BankParser
from parsers.apk_parser import APKParser
from parsers.email_parser import EmailParser


@pytest.fixture(scope="module")
def case_104_dir(tmp_path_factory):
    """Fixture ensuring Case 104 mock data exists."""
    data_dir = tmp_path_factory.mktemp("case_104_data")
    generate_case_104_data(str(data_dir))
    return data_dir


def test_hasher_and_audit_log(tmp_path):
    """Tests file hashing, audit log creation, and chained prev_entry_hash."""
    test_file = tmp_path / "sample.txt"
    test_file.write_text("Forensic artifact test data", encoding="utf-8")

    out_dir = tmp_path / "outputs"
    entry1 = hash_file(str(test_file), case_id="CASE-100", officer_id="IO-01", output_dir=str(out_dir))

    assert entry1["filename"] == "sample.txt"
    assert entry1["prev_entry_hash"] is None
    assert len(entry1["sha256"]) == 64

    # Second hash file to verify chaining
    test_file2 = tmp_path / "sample2.txt"
    test_file2.write_text("Second forensic file", encoding="utf-8")
    entry2 = hash_file(str(test_file2), case_id="CASE-100", officer_id="IO-01", output_dir=str(out_dir))

    assert entry2["sequence"] == 2
    assert entry2["prev_entry_hash"] == entry1["sha256"]

    audit_entries = get_audit_log(str(out_dir))
    assert len(audit_entries) == 2


def test_cdr_parser(case_104_dir):
    """Tests parsing of CDR CSV records."""
    cdr_path = case_104_dir / "cdr_records.csv"
    assert cdr_path.exists()

    parser = CDRParser(source_sha256="fake_sha256_cdr")
    result = parser.parse(str(cdr_path))

    assert result.record_count >= 55
    assert len(result.entities) >= 10

    # Assert IMEI entities present
    imei_entities = [e for e in result.entities if e.entity_type == "IMEI"]
    assert len(imei_entities) > 0
    imei_values = [e.normalized_value for e in imei_entities]
    assert "490154203237518" in imei_values or "356938035643809" in imei_values

    # Assert phone normalization (+91 prefix for 10-digit mobile numbers)
    phone_entities = [e for e in result.entities if e.entity_type == "PHONE"]
    for p in phone_entities:
        if len(p.normalized_value) > 5:
            assert p.normalized_value.startswith("+91")


def test_bank_parser(case_104_dir):
    """Tests parsing of Bank statement CSV records."""
    bank_path = case_104_dir / "bank_statement.csv"
    assert bank_path.exists()

    parser = BankParser(source_sha256="fake_sha256_bank")
    result = parser.parse(str(bank_path))

    assert result.record_count >= 35

    # Assert UPI handles are normalized to lowercase
    upi_entities = [e for e in result.entities if e.entity_type == "UPI_HANDLE"]
    assert len(upi_entities) > 0
    for upi in upi_entities:
        assert upi.normalized_value == upi.normalized_value.lower()

    upi_values = [e.normalized_value for e in upi_entities]
    assert "victim.suresh@okaxis" in upi_values
    assert "fastpay99@okhdfcbank" in upi_values


def test_apk_parser(case_104_dir):
    """Tests parsing of APK dump JSON."""
    apk_path = case_104_dir / "apk_dump.json"
    assert apk_path.exists()

    parser = APKParser(source_sha256="fake_sha256_apk")
    result = parser.parse(str(apk_path))

    assert len(result.warnings) > 0
    warning_text = " ".join(result.warnings)
    assert "sideloaded" in warning_text.lower()
    assert "dangerous" in warning_text.lower() or "perms" in warning_text.lower()

    app_entities = [e for e in result.entities if e.entity_type == "APP"]
    sideloaded_apps = [a for a in app_entities if a.attributes.get("is_sideloaded")]
    assert len(sideloaded_apps) > 0


def test_email_parser(case_104_dir):
    """Tests parsing of EML phishing email."""
    eml_path = case_104_dir / "phishing_email.eml"
    assert eml_path.exists()

    parser = EmailParser(source_sha256="fake_sha256_email")
    result = parser.parse(str(eml_path))

    assert len(result.events) == 1
    email_event = result.events[0]

    assert email_event["spf"] == "fail"
    assert email_event["originating_ip"] == "196.216.2.45"
    assert len(email_event["urls"]) > 0
    assert any("hdfcbank-kyc-update.xyz" in url for url in email_event["urls"])

    ip_entities = [e for e in result.entities if e.entity_type == "IP_ADDRESS"]
    ip_values = [e.normalized_value for e in ip_entities]
    assert "196.216.2.45" in ip_values


def test_tamper_detection(tmp_path):
    """Tests that modifying a file after hashing triggers TamperDetectedError."""
    target = tmp_path / "tamper_target.txt"
    target.write_text("Original content", encoding="utf-8")

    out_dir = tmp_path / "outputs"
    entry = hash_file(str(target), case_id="CASE-104", officer_id="IO-01", output_dir=str(out_dir))
    original_sha = entry["sha256"]

    # Verify original passes
    assert verify_file(str(target), original_sha) is True

    # Tamper with the file content
    target.write_text("Tampered content modified!", encoding="utf-8")

    with pytest.raises(TamperDetectedError) as exc_info:
        verify_file(str(target), original_sha)

    assert "Tamper detected" in str(exc_info.value)
