"""Email .eml file parser module using standard library email module."""

import email
from email import policy
import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dateutil import parser as date_parser

from parsers.base_parser import BaseParser, Entity, ParseResult

logger = logging.getLogger(__name__)

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_REGEX = re.compile(r"https?://[^\s<>\"]+")


class EmailParser(BaseParser):
    """Parser for RFC-2822 .eml phishing email files."""

    def parse(self, filepath: str) -> ParseResult:
        """Parses an email .eml file into IP entities, email metadata events, and warnings.

        Args:
            filepath: Path to the .eml file.

        Returns:
            ParseResult containing entities, events, record count, and warnings.
        """
        path = Path(filepath)
        filename = path.name
        warnings: List[str] = []
        events: List[Dict[str, Any]] = []
        entity_map: Dict[str, Entity] = {}

        if not path.exists():
            raise FileNotFoundError(f"Email file not found: {filepath}")

        with open(path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)

        from_header = str(msg.get("From", ""))
        to_header = str(msg.get("To", ""))
        subject = str(msg.get("Subject", ""))
        date_header = str(msg.get("Date", ""))
        reply_to = str(msg.get("Reply-To", ""))
        x_orig_ip = str(msg.get("X-Originating-IP", "")).strip("[] ")

        received_headers = msg.get_all("Received", [])
        received_chain = [str(r) for r in received_headers]

        auth_results = str(msg.get("Authentication-Results", ""))

        # Parse SPF/DKIM/DMARC statuses
        spf_status = "unknown"
        dkim_status = "unknown"
        dmarc_status = "unknown"

        if "spf=pass" in auth_results.lower():
            spf_status = "pass"
        elif "spf=fail" in auth_results.lower():
            spf_status = "fail"
        elif "spf=neutral" in auth_results.lower():
            spf_status = "neutral"

        if "dkim=pass" in auth_results.lower():
            dkim_status = "pass"
        elif "dkim=fail" in auth_results.lower():
            dkim_status = "fail"

        if "dmarc=pass" in auth_results.lower():
            dmarc_status = "pass"
        elif "dmarc=fail" in auth_results.lower():
            dmarc_status = "fail"

        if spf_status == "fail":
            warnings.append("SPF authentication failed for email")
        if dkim_status == "fail":
            warnings.append("DKIM authentication failed for email")
        if dmarc_status == "fail":
            warnings.append("DMARC authentication failed for email")

        # Parse date
        ts_str = None
        if date_header:
            try:
                ts_str = date_parser.parse(date_header).isoformat()
            except Exception:
                ts_str = date_header

        # Extract body text & HTML for URLs
        body_content = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disp = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disp:
                    fname = part.get_filename() or "unnamed"
                    attachments.append({"filename": fname, "mime_type": content_type})
                elif content_type in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_content += payload.decode("utf-8", errors="replace") + "\n"
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_content = payload.decode("utf-8", errors="replace")
                else:
                    body_content = str(msg.get_payload())
            except Exception:
                body_content = str(msg.get_payload())

        extracted_urls = list(set(URL_REGEX.findall(body_content)))

        # IP extraction from X-Originating-IP and Received headers
        extracted_ips = set()
        if x_orig_ip and IP_REGEX.match(x_orig_ip):
            extracted_ips.add(x_orig_ip)

        for r_header in received_chain:
            ips = IP_REGEX.findall(r_header)
            for ip in ips:
                if not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("192.168."):
                    extracted_ips.add(ip)

        # Create IP entities
        for ip in extracted_ips:
            key = f"IP_ADDRESS:{ip}"
            entity_map[key] = Entity(
                entity_type="IP_ADDRESS",
                raw_value=ip,
                normalized_value=ip,
                source_file=filename,
                source_sha256=self.source_sha256,
                first_seen_ts=ts_str,
                last_seen_ts=ts_str,
                attributes={"is_originating_ip": (ip == x_orig_ip)},
            )

        event = {
            "event_type": "PHISHING_EMAIL",
            "from": from_header,
            "to": to_header,
            "subject": subject,
            "date": ts_str,
            "reply_to": reply_to,
            "originating_ip": x_orig_ip,
            "received_chain": received_chain,
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "urls": extracted_urls,
            "attachments": attachments,
        }
        events.append(event)

        return ParseResult(
            entities=list(entity_map.values()),
            events=events,
            source_file=filename,
            source_sha256=self.source_sha256,
            parser_name="EmailParser",
            record_count=1,
            warnings=warnings,
        )
