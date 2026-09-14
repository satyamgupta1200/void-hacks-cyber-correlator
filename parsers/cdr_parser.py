"""CDR (Call Detail Records) parser module."""

import csv
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dateutil import parser as date_parser

from parsers.base_parser import BaseParser, Entity, ParseResult

logger = logging.getLogger(__name__)


class CDRParser(BaseParser):
    """Parser for Call Detail Records (CDR) CSV files."""

    def parse(self, filepath: str) -> ParseResult:
        """Parses a CDR CSV file into entities and call events.

        Args:
            filepath: Path to the CDR CSV file.

        Returns:
            ParseResult containing entities, events, record count, and warnings.
        """
        path = Path(filepath)
        filename = path.name
        warnings: List[str] = []
        events: List[Dict[str, Any]] = []
        entity_map: Dict[str, Entity] = {}

        if not path.exists():
            raise FileNotFoundError(f"CDR file not found: {filepath}")

        record_count = 0
        expected_cols = {
            "msisdn", "called_number", "call_start", "call_end",
            "duration_sec", "imei", "imsi", "cell_id", "lac",
            "call_type", "roaming_flag", "serving_operator"
        }

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames:
                headers = {col.strip() for col in reader.fieldnames}
                missing = expected_cols - headers
                if missing:
                    warnings.append(f"Missing expected columns in CDR CSV: {sorted(list(missing))}")

            for row in reader:
                record_count += 1
                msisdn_raw = row.get("msisdn", "").strip()
                called_raw = row.get("called_number", "").strip()
                call_start_raw = row.get("call_start", "").strip()
                call_end_raw = row.get("call_end", "").strip()
                duration_raw = row.get("duration_sec", "0").strip()
                imei_raw = row.get("imei", "").strip()
                imsi_raw = row.get("imsi", "").strip()
                cell_id_raw = row.get("cell_id", "").strip()
                call_type_raw = row.get("call_type", "VOICE").strip()

                msisdn_norm = self.normalize_phone(msisdn_raw)
                called_norm = self.normalize_phone(called_raw)

                # Parse timestamps
                start_ts_str = None
                end_ts_str = None
                if call_start_raw:
                    try:
                        start_dt = date_parser.parse(call_start_raw)
                        start_ts_str = start_dt.isoformat()
                    except Exception:
                        start_ts_str = call_start_raw

                if call_end_raw:
                    try:
                        end_dt = date_parser.parse(call_end_raw)
                        end_ts_str = end_dt.isoformat()
                    except Exception:
                        end_ts_str = call_end_raw

                try:
                    duration_sec = int(duration_raw) if duration_raw else 0
                except ValueError:
                    duration_sec = 0

                # Create event record
                event = {
                    "event_type": "CDR",
                    "from": msisdn_norm or msisdn_raw,
                    "to": called_norm or called_raw,
                    "imei": imei_raw,
                    "imsi": imsi_raw,
                    "start_ts": start_ts_str,
                    "end_ts": end_ts_str,
                    "duration_sec": duration_sec,
                    "call_type": call_type_raw,
                    "cell_id": cell_id_raw,
                }
                events.append(event)

                # Entity tracking - MSISDN
                if msisdn_norm:
                    key = f"PHONE:{msisdn_norm}"
                    if key not in entity_map:
                        entity_map[key] = Entity(
                            entity_type="PHONE",
                            raw_value=msisdn_raw,
                            normalized_value=msisdn_norm,
                            source_file=filename,
                            source_sha256=self.source_sha256,
                            first_seen_ts=start_ts_str,
                            last_seen_ts=start_ts_str,
                            attributes={"imsi": imsi_raw} if imsi_raw else {},
                        )
                    else:
                        ent = entity_map[key]
                        if start_ts_str:
                            if not ent.first_seen_ts or start_ts_str < ent.first_seen_ts:
                                ent.first_seen_ts = start_ts_str
                            if not ent.last_seen_ts or start_ts_str > ent.last_seen_ts:
                                ent.last_seen_ts = start_ts_str

                # Entity tracking - Called Number
                if called_norm:
                    key = f"PHONE:{called_norm}"
                    if key not in entity_map:
                        entity_map[key] = Entity(
                            entity_type="PHONE",
                            raw_value=called_raw,
                            normalized_value=called_norm,
                            source_file=filename,
                            source_sha256=self.source_sha256,
                            first_seen_ts=start_ts_str,
                            last_seen_ts=start_ts_str,
                        )
                    else:
                        ent = entity_map[key]
                        if start_ts_str:
                            if not ent.first_seen_ts or start_ts_str < ent.first_seen_ts:
                                ent.first_seen_ts = start_ts_str
                            if not ent.last_seen_ts or start_ts_str > ent.last_seen_ts:
                                ent.last_seen_ts = start_ts_str

                # Entity tracking - IMEI
                if imei_raw:
                    key = f"IMEI:{imei_raw}"
                    if key not in entity_map:
                        entity_map[key] = Entity(
                            entity_type="IMEI",
                            raw_value=imei_raw,
                            normalized_value=imei_raw,
                            source_file=filename,
                            source_sha256=self.source_sha256,
                            first_seen_ts=start_ts_str,
                            last_seen_ts=start_ts_str,
                        )
                    else:
                        ent = entity_map[key]
                        if start_ts_str:
                            if not ent.first_seen_ts or start_ts_str < ent.first_seen_ts:
                                ent.first_seen_ts = start_ts_str
                            if not ent.last_seen_ts or start_ts_str > ent.last_seen_ts:
                                ent.last_seen_ts = start_ts_str

        return ParseResult(
            entities=list(entity_map.values()),
            events=events,
            source_file=filename,
            source_sha256=self.source_sha256,
            parser_name="CDRParser",
            record_count=record_count,
            warnings=warnings,
        )
