"""APK/Android dump JSON parser module."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any
from dateutil import parser as date_parser

from parsers.base_parser import BaseParser, Entity, ParseResult

logger = logging.getLogger(__name__)

DANGEROUS_PERMISSIONS = {
    "READ_SMS",
    "BIND_ACCESSIBILITY_SERVICE",
    "RECORD_AUDIO",
    "SYSTEM_ALERT_WINDOW",
    "PROCESS_OUTGOING_CALLS",
}

LEGITIMATE_SOURCES = {
    "com.android.vending",
    "Google Play Store",
    "play.google.com",
}


class APKParser(BaseParser):
    """Parser for Android APK/Device dump JSON files."""

    def parse(self, filepath: str) -> ParseResult:
        """Parses an Android dump JSON file into device, app, IP entities, and logs.

        Args:
            filepath: Path to the APK dump JSON file.

        Returns:
            ParseResult containing entities, events, record count, and warnings.
        """
        path = Path(filepath)
        filename = path.name
        warnings: List[str] = []
        events: List[Dict[str, Any]] = []
        entity_map: Dict[str, Entity] = {}

        if not path.exists():
            raise FileNotFoundError(f"APK dump file not found: {filepath}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        device_info = data.get("device_info", {})
        installed_apps = data.get("installed_apps", [])
        sms_log = data.get("sms_log", [])
        call_log = data.get("call_log", [])
        network_log = data.get("network_log", [])

        record_count = len(installed_apps) + len(sms_log) + len(call_log) + len(network_log)

        # Device Entity
        android_id = device_info.get("android_id", "")
        model = device_info.get("model", "")
        imei = device_info.get("imei", "")
        capture_ts = device_info.get("capture_timestamp", "")

        capture_ts_str = None
        if capture_ts:
            try:
                capture_ts_str = date_parser.parse(capture_ts).isoformat()
            except Exception:
                capture_ts_str = capture_ts

        if android_id or model:
            dev_val = android_id or model
            entity_map["DEVICE:" + dev_val] = Entity(
                entity_type="DEVICE",
                raw_value=dev_val,
                normalized_value=dev_val,
                source_file=filename,
                source_sha256=self.source_sha256,
                first_seen_ts=capture_ts_str,
                last_seen_ts=capture_ts_str,
                attributes={
                    "model": model,
                    "os_version": device_info.get("os_version", ""),
                    "android_id": android_id,
                },
            )

        if imei:
            entity_map["IMEI:" + imei] = Entity(
                entity_type="IMEI",
                raw_value=imei,
                normalized_value=imei,
                source_file=filename,
                source_sha256=self.source_sha256,
                first_seen_ts=capture_ts_str,
                last_seen_ts=capture_ts_str,
            )

        # Network log IPs
        for net in network_log:
            ip = net.get("ip_assigned", "").strip()
            conn_ts = net.get("connected_ts", "").strip()
            conn_ts_str = None
            if conn_ts:
                try:
                    conn_ts_str = date_parser.parse(conn_ts).isoformat()
                except Exception:
                    conn_ts_str = conn_ts

            if ip:
                key = f"IP_ADDRESS:{ip}"
                if key not in entity_map:
                    entity_map[key] = Entity(
                        entity_type="IP_ADDRESS",
                        raw_value=ip,
                        normalized_value=ip,
                        source_file=filename,
                        source_sha256=self.source_sha256,
                        first_seen_ts=conn_ts_str,
                        last_seen_ts=conn_ts_str,
                        attributes={"ssid": net.get("ssid", ""), "bssid": net.get("bssid", "")},
                    )

            events.append({
                "event_type": "NETWORK_LOG",
                "ssid": net.get("ssid", ""),
                "bssid": net.get("bssid", ""),
                "ip_assigned": ip,
                "timestamp": conn_ts_str,
            })

        # Installed apps inspection
        for app in installed_apps:
            pkg_name = app.get("package_name", "").strip()
            install_src = app.get("install_source", "").strip()
            perms = app.get("permissions", [])
            install_ts = app.get("install_ts", "").strip()

            is_sideloaded = install_src not in LEGITIMATE_SOURCES
            has_dangerous_perm = any(p in DANGEROUS_PERMISSIONS for p in perms)

            if is_sideloaded or has_dangerous_perm:
                reason_parts = []
                if is_sideloaded:
                    reason_parts.append(f"sideloaded from '{install_src}'")
                if has_dangerous_perm:
                    matched_perms = [p for p in perms if p in DANGEROUS_PERMISSIONS]
                    reason_parts.append(f"dangerous perms: {matched_perms}")
                warnings.append(f"Flagged App '{pkg_name}': {', '.join(reason_parts)}")

            if pkg_name:
                key = f"APP:{pkg_name}"
                entity_map[key] = Entity(
                    entity_type="APP",
                    raw_value=pkg_name,
                    normalized_value=pkg_name,
                    source_file=filename,
                    source_sha256=self.source_sha256,
                    attributes={
                        "app_label": app.get("app_label", ""),
                        "install_source": install_src,
                        "permissions": perms,
                        "is_dangerous": has_dangerous_perm,
                        "is_sideloaded": is_sideloaded,
                    },
                )

        # SMS events
        for sms in sms_log:
            sender = self.normalize_phone(sms.get("from", "")) or sms.get("from", "")
            receiver = self.normalize_phone(sms.get("to", "")) or sms.get("to", "")
            ts = sms.get("ts", "")
            ts_str = None
            if ts:
                try:
                    ts_str = date_parser.parse(ts).isoformat()
                except Exception:
                    ts_str = ts

            events.append({
                "event_type": "SMS_LOG",
                "from": sender,
                "to": receiver,
                "body": sms.get("body", ""),
                "timestamp": ts_str,
            })

        # Call log events
        for call in call_log:
            num = self.normalize_phone(call.get("number", "")) or call.get("number", "")
            ts = call.get("ts", "")
            ts_str = None
            if ts:
                try:
                    ts_str = date_parser.parse(ts).isoformat()
                except Exception:
                    ts_str = ts

            events.append({
                "event_type": "CALL_LOG",
                "number": num,
                "type": call.get("type", ""),
                "duration": call.get("duration", 0),
                "timestamp": ts_str,
            })

        return ParseResult(
            entities=list(entity_map.values()),
            events=events,
            source_file=filename,
            source_sha256=self.source_sha256,
            parser_name="APKParser",
            record_count=record_count,
            warnings=warnings,
        )
