"""Base parser interface and core data structures (Entity, ParseResult)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import uuid


@dataclass
class Entity:
    """Represents a discrete forensic entity (PHONE, IMEI, UPI_HANDLE, IP_ADDRESS, ACCOUNT, DEVICE)."""
    entity_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: str = ""  # PHONE | IMEI | UPI_HANDLE | IP_ADDRESS | ACCOUNT | DEVICE
    raw_value: str = ""
    normalized_value: str = ""
    source_file: str = ""
    source_sha256: str = ""
    first_seen_ts: Optional[str] = None
    last_seen_ts: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    linked_entity_ids: List[str] = field(default_factory=list)


@dataclass
class ParseResult:
    """Encapsulates the parsed entities, raw events, and parser execution metadata."""
    entities: List[Entity]
    events: List[Dict[str, Any]]  # Raw transaction/call/sms events
    source_file: str
    source_sha256: str
    parser_name: str
    record_count: int
    warnings: List[str] = field(default_factory=list)


class BaseParser(ABC):
    """Abstract base class for all forensic artifact parsers."""

    def __init__(self, source_sha256: str):
        """Initializes the parser with the source file SHA-256 digest.

        Args:
            source_sha256: Hex string of the source file's SHA-256 hash.
        """
        self.source_sha256 = source_sha256

    @abstractmethod
    def parse(self, filepath: str) -> ParseResult:
        """Parses the target file into a ParseResult object.

        Args:
            filepath: Path to the target artifact file.

        Returns:
            ParseResult instance containing extracted entities and events.
        """
        pass

    def normalize_phone(self, raw: str) -> str:
        """Strips non-digits, ensures 10-digit Indian mobile with +91 prefix.

        Args:
            raw: Raw input phone string.

        Returns:
            Normalized phone string (e.g. "+919845012345").
        """
        if not raw:
            return ""
        digits = ''.join(filter(str.isdigit, str(raw)))
        if len(digits) == 10:
            return f"+91{digits}"
        elif len(digits) == 12 and digits.startswith("91"):
            return f"+{digits}"
        return digits

    def normalize_upi(self, raw: str) -> str:
        """Lowercases and strips whitespace from UPI handle.

        Args:
            raw: Raw UPI handle string.

        Returns:
            Normalized UPI handle.
        """
        if not raw:
            return ""
        return str(raw).lower().strip()
