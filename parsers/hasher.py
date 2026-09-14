"""Forensic SHA-256 hasher module with chained audit log integrity."""

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from engine.audit_logger import (
    load_audit_log,
    append_audit_entry,
    get_last_entry_hash,
)


class TamperDetectedError(Exception):
    """Custom exception raised when a file's hash does not match expected SHA-256."""

    def __init__(self, filename: str, expected: str, actual: str):
        self.filename = filename
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Tamper detected in file '{filename}'! Expected SHA-256: {expected}, Actual: {actual}"
        )


def hash_file(
    filepath: str,
    case_id: str,
    officer_id: str,
    output_dir: str = "outputs",
) -> Dict[str, Any]:
    """Computes SHA-256 hash of a file and appends an entry to the audit log.

    Args:
        filepath: Path to the target file.
        case_id: Case identifier string.
        officer_id: Investigating officer ID.
        output_dir: Output directory for audit log storage.

    Returns:
        Dict representing the created audit log entry.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)

    hex_digest = hasher.hexdigest()
    size_bytes = path.stat().st_size
    filename = path.name

    prev_hash = get_last_entry_hash(output_dir)
    current_log = load_audit_log(output_dir)
    sequence = len(current_log.get("entries", [])) + 1

    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    entry = {
        "sequence": sequence,
        "action": "FILE_INGESTED",
        "filename": filename,
        "sha256": hex_digest,
        "size_bytes": size_bytes,
        "officer_id": officer_id,
        "case_id": case_id,
        "timestamp_utc": timestamp_utc,
        "prev_entry_hash": prev_hash,
    }

    append_audit_entry(output_dir, entry)
    return entry


def verify_file(filepath: str, expected_sha256: str) -> bool:
    """Verifies that a file's SHA-256 hash matches the expected hash.

    Args:
        filepath: Path to the file to verify.
        expected_sha256: The expected SHA-256 hex string.

    Returns:
        True if verification succeeds.

    Raises:
        TamperDetectedError: If actual hash does not match expected_sha256.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)

    actual_digest = hasher.hexdigest()
    if actual_digest != expected_sha256:
        raise TamperDetectedError(path.name, expected_sha256, actual_digest)

    return True


def get_audit_log(output_dir: str = "outputs") -> List[Dict[str, Any]]:
    """Retrieves all audit log entries from audit_log.json.

    Args:
        output_dir: Path to directory containing audit_log.json.

    Returns:
        List of audit log entry dictionaries.
    """
    log_data = load_audit_log(output_dir)
    return log_data.get("entries", [])
