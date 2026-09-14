"""Bank statement CSV parser module."""

import csv
import logging
from pathlib import Path
from typing import Dict, List, Any
from dateutil import parser as date_parser

from parsers.base_parser import BaseParser, Entity, ParseResult

logger = logging.getLogger(__name__)


class BankParser(BaseParser):
    """Parser for Bank Statement CSV files."""

    def parse(self, filepath: str) -> ParseResult:
        """Parses a bank statement CSV file into entities and transaction events.

        Args:
            filepath: Path to the bank statement CSV file.

        Returns:
            ParseResult containing extracted entities, events, record count, and warnings.
        """
        path = Path(filepath)
        filename = path.name
        warnings: List[str] = []
        events: List[Dict[str, Any]] = []
        entity_map: Dict[str, Entity] = {}

        if not path.exists():
            raise FileNotFoundError(f"Bank statement file not found: {filepath}")

        record_count = 0
        expected_cols = {
            "txn_id", "txn_timestamp", "debit_account", "credit_account",
            "upi_handle_sender", "upi_handle_receiver", "amount_inr",
            "txn_type", "bank_ref", "narration", "balance_after"
        }

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames:
                headers = {col.strip() for col in reader.fieldnames}
                missing = expected_cols - headers
                if missing:
                    warnings.append(f"Missing expected columns in Bank CSV: {sorted(list(missing))}")

            for row in reader:
                record_count += 1
                txn_id = row.get("txn_id", "").strip()
                txn_ts_raw = row.get("txn_timestamp", "").strip()
                debit_acc = row.get("debit_account", "").strip()
                credit_acc = row.get("credit_account", "").strip()
                upi_sender_raw = row.get("upi_handle_sender", "").strip()
                upi_recv_raw = row.get("upi_handle_receiver", "").strip()
                amount_raw = row.get("amount_inr", "0").strip()
                txn_type = row.get("txn_type", "TRANSFER").strip()
                bank_ref = row.get("bank_ref", "").strip()
                narration = row.get("narration", "").strip()

                upi_sender_norm = self.normalize_upi(upi_sender_raw)
                upi_recv_norm = self.normalize_upi(upi_recv_raw)

                try:
                    amount_inr = float(amount_raw) if amount_raw else 0.0
                except ValueError:
                    amount_inr = 0.0

                ts_str = None
                if txn_ts_raw:
                    try:
                        dt = date_parser.parse(txn_ts_raw)
                        ts_str = dt.isoformat()
                    except Exception:
                        ts_str = txn_ts_raw

                event = {
                    "event_type": "BANK_TXN",
                    "txn_id": txn_id,
                    "from_upi": upi_sender_norm,
                    "to_upi": upi_recv_norm,
                    "debit_account": debit_acc,
                    "credit_account": credit_acc,
                    "amount_inr": amount_inr,
                    "timestamp": ts_str,
                    "txn_type": txn_type,
                    "bank_ref": bank_ref,
                    "narration": narration,
                }
                events.append(event)

                # Entity tracking - UPI Sender
                if upi_sender_norm:
                    key = f"UPI_HANDLE:{upi_sender_norm}"
                    if key not in entity_map:
                        entity_map[key] = Entity(
                            entity_type="UPI_HANDLE",
                            raw_value=upi_sender_raw,
                            normalized_value=upi_sender_norm,
                            source_file=filename,
                            source_sha256=self.source_sha256,
                            first_seen_ts=ts_str,
                            last_seen_ts=ts_str,
                        )
                    else:
                        ent = entity_map[key]
                        if ts_str:
                            if not ent.first_seen_ts or ts_str < ent.first_seen_ts:
                                ent.first_seen_ts = ts_str
                            if not ent.last_seen_ts or ts_str > ent.last_seen_ts:
                                ent.last_seen_ts = ts_str

                # Entity tracking - UPI Receiver
                if upi_recv_norm:
                    key = f"UPI_HANDLE:{upi_recv_norm}"
                    if key not in entity_map:
                        entity_map[key] = Entity(
                            entity_type="UPI_HANDLE",
                            raw_value=upi_recv_raw,
                            normalized_value=upi_recv_norm,
                            source_file=filename,
                            source_sha256=self.source_sha256,
                            first_seen_ts=ts_str,
                            last_seen_ts=ts_str,
                        )
                    else:
                        ent = entity_map[key]
                        if ts_str:
                            if not ent.first_seen_ts or ts_str < ent.first_seen_ts:
                                ent.first_seen_ts = ts_str
                            if not ent.last_seen_ts or ts_str > ent.last_seen_ts:
                                ent.last_seen_ts = ts_str

                # Entity tracking - Debit Account
                if debit_acc:
                    key = f"ACCOUNT:{debit_acc}"
                    if key not in entity_map:
                        entity_map[key] = Entity(
                            entity_type="ACCOUNT",
                            raw_value=debit_acc,
                            normalized_value=debit_acc,
                            source_file=filename,
                            source_sha256=self.source_sha256,
                            first_seen_ts=ts_str,
                            last_seen_ts=ts_str,
                        )
                    else:
                        ent = entity_map[key]
                        if ts_str:
                            if not ent.first_seen_ts or ts_str < ent.first_seen_ts:
                                ent.first_seen_ts = ts_str
                            if not ent.last_seen_ts or ts_str > ent.last_seen_ts:
                                ent.last_seen_ts = ts_str

                # Entity tracking - Credit Account
                if credit_acc:
                    key = f"ACCOUNT:{credit_acc}"
                    if key not in entity_map:
                        entity_map[key] = Entity(
                            entity_type="ACCOUNT",
                            raw_value=credit_acc,
                            normalized_value=credit_acc,
                            source_file=filename,
                            source_sha256=self.source_sha256,
                            first_seen_ts=ts_str,
                            last_seen_ts=ts_str,
                        )
                    else:
                        ent = entity_map[key]
                        if ts_str:
                            if not ent.first_seen_ts or ts_str < ent.first_seen_ts:
                                ent.first_seen_ts = ts_str
                            if not ent.last_seen_ts or ts_str > ent.last_seen_ts:
                                ent.last_seen_ts = ts_str

        return ParseResult(
            entities=list(entity_map.values()),
            events=events,
            source_file=filename,
            source_sha256=self.source_sha256,
            parser_name="BankParser",
            record_count=record_count,
            warnings=warnings,
        )
