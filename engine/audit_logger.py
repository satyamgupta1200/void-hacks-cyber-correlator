"""Audit logger module for handling forensic audit logs."""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any


def load_audit_log(output_dir: str = "outputs") -> Dict[str, Any]:
    """Loads the audit log JSON from output_dir or initializes a new one.

    Args:
        output_dir: Directory where audit_log.json is located.

    Returns:
        Dict containing log_version and entries list.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    log_file = out_path / "audit_log.json"

    if not log_file.exists():
        initial_data = {"log_version": "1.0", "entries": []}
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(initial_data, f, indent=2)
        return initial_data

    try:
        with open(log_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict) or "entries" not in data:
                return {"log_version": "1.0", "entries": []}
            return data
    except Exception:
        return {"log_version": "1.0", "entries": []}


def append_audit_entry(output_dir: str, entry: Dict[str, Any]) -> None:
    """Appends an entry dictionary to the audit log JSON.

    Args:
        output_dir: Directory where audit_log.json is located.
        entry: Audit entry dictionary to append.
    """
    log_data = load_audit_log(output_dir)
    log_data["entries"].append(entry)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    log_file = out_path / "audit_log.json"

    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(log_data, f, indent=2)


def get_last_entry_hash(output_dir: str = "outputs") -> Optional[str]:
    """Gets the sha256 hash of the most recent audit log entry.

    Args:
        output_dir: Directory where audit_log.json is located.

    Returns:
        The sha256 hex string of the last entry, or None if empty.
    """
    log_data = load_audit_log(output_dir)
    entries = log_data.get("entries", [])
    if not entries:
        return None
    return entries[-1].get("sha256")
