"""Sysmon XML log parser.

Parses Sysmon event logs (Event IDs 1, 3, 7, 8, 11, 13, 22, etc.)
and extracts security-relevant fields.
"""

import xml.etree.ElementTree as ET
import uuid
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field
from .ioc_extractor import IOCExtractor, IOC


@dataclass
class AlertData:
    """Normalized alert data structure used across all parsers."""
    alert_id: str = ""
    raw_content: str = ""
    alert_type: str = "generic"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_host: Optional[str] = None
    dest_host: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None
    file_hash: Optional[str] = None
    url: Optional[str] = None
    domain: Optional[str] = None
    email_from: Optional[str] = None
    email_subject: Optional[str] = None
    extracted_iocs: list = field(default_factory=list)
    raw_fields: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.alert_id:
            self.alert_id = str(uuid.uuid4())

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "source_host": self.source_host,
            "dest_host": self.dest_host,
            "user": self.user,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "parent_process": self.parent_process,
            "file_hash": self.file_hash,
            "url": self.url,
            "domain": self.domain,
            "email_from": self.email_from,
            "email_subject": self.email_subject,
            "extracted_iocs": [ioc.to_dict() if hasattr(ioc, "to_dict") else ioc for ioc in self.extracted_iocs],
            "raw_fields": self.raw_fields,
        }


class SysmonParser:
    """Parses Sysmon XML event logs into AlertData."""

    # Sysmon event ID descriptions
    EVENT_TYPES = {
        "1": "Process Creation",
        "2": "File Creation Time Changed",
        "3": "Network Connection",
        "5": "Process Terminated",
        "7": "Image Loaded",
        "8": "CreateRemoteThread",
        "9": "RawAccessRead",
        "10": "Process Access",
        "11": "File Created",
        "12": "Registry Object Added/Deleted",
        "13": "Registry Value Set",
        "15": "File Stream Created",
        "17": "Pipe Created",
        "22": "DNS Query",
        "23": "File Delete",
        "25": "Process Tampering",
    }

    @classmethod
    def parse(cls, content: str) -> AlertData:
        """Parse Sysmon XML content into an AlertData object.

        Args:
            content: Raw XML string from Sysmon event log.

        Returns:
            Normalized AlertData object.
        """
        alert = AlertData(
            raw_content=content,
            alert_type="sysmon",
        )

        try:
            root = ET.fromstring(content.strip())
        except ET.ParseError:
            # Try wrapping in a root element
            try:
                root = ET.fromstring(f"<Events>{content.strip()}</Events>")
                if len(root) > 0:
                    root = root[0]
                else:
                    alert.extracted_iocs = IOCExtractor.extract(content)
                    return alert
            except ET.ParseError:
                alert.extracted_iocs = IOCExtractor.extract(content)
                return alert

        # Handle different XML structures
        raw_fields = {}
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

        # Try to find EventData elements (standard Sysmon format)
        event_data = root.findall(".//EventData/Data") or root.findall(f".//{{{ns['ns']}}}EventData/{{{ns['ns']}}}Data")

        if not event_data:
            # Try without namespace
            event_data = root.findall(".//Data")

        if not event_data:
            # Try direct children
            for child in root.iter():
                if child.text and child.text.strip():
                    tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    name = child.get("Name", tag)
                    raw_fields[name] = child.text.strip()

        for data_elem in event_data:
            name = data_elem.get("Name", "")
            value = data_elem.text or ""
            if name:
                raw_fields[name] = value

        alert.raw_fields = raw_fields

        # Extract system info
        system = root.find(".//System") or root.find(f".//{{{ns['ns']}}}System")
        if system is not None:
            event_id_elem = system.find("EventID") or system.find(f"{{{ns['ns']}}}EventID")
            if event_id_elem is not None and event_id_elem.text:
                raw_fields["EventID"] = event_id_elem.text
                raw_fields["EventType"] = cls.EVENT_TYPES.get(event_id_elem.text, "Unknown")

            time_elem = system.find(".//TimeCreated") or system.find(f".//{{{ns['ns']}}}TimeCreated")
            if time_elem is not None:
                sys_time = time_elem.get("SystemTime", "")
                if sys_time:
                    try:
                        alert.timestamp = datetime.fromisoformat(sys_time.replace("Z", "+00:00"))
                    except ValueError:
                        pass

            computer_elem = system.find("Computer") or system.find(f"{{{ns['ns']}}}Computer")
            if computer_elem is not None and computer_elem.text:
                alert.source_host = computer_elem.text

        # Map Sysmon fields to AlertData
        alert.user = raw_fields.get("User", raw_fields.get("TargetUser"))
        alert.process_name = raw_fields.get("Image", raw_fields.get("TargetImage"))
        alert.command_line = raw_fields.get("CommandLine", raw_fields.get("OriginalFileName"))
        alert.parent_process = raw_fields.get("ParentImage", raw_fields.get("ParentCommandLine"))
        alert.source_ip = raw_fields.get("SourceIp", raw_fields.get("SourceIP"))
        alert.dest_ip = raw_fields.get("DestinationIp", raw_fields.get("DestinationIP"))
        alert.dest_host = raw_fields.get("DestinationHostname")
        alert.domain = raw_fields.get("QueryName", raw_fields.get("DestinationHostname"))

        # Extract hashes
        hashes = raw_fields.get("Hashes", "")
        if hashes:
            for hash_entry in hashes.split(","):
                if "=" in hash_entry:
                    hash_type, hash_value = hash_entry.split("=", 1)
                    raw_fields[f"Hash_{hash_type.strip()}"] = hash_value.strip()
                    if hash_type.strip().upper() in ("SHA256", "SHA1", "MD5"):
                        alert.file_hash = hash_value.strip()

        # Timestamp from field
        utc_time = raw_fields.get("UtcTime", "")
        if utc_time:
            try:
                alert.timestamp = datetime.strptime(utc_time, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                try:
                    alert.timestamp = datetime.strptime(utc_time, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass

        # Extract IOCs from all text content
        all_text = content + " " + " ".join(raw_fields.values())
        alert.extracted_iocs = IOCExtractor.extract(all_text)

        return alert

    @classmethod
    def can_parse(cls, content: str) -> bool:
        """Check if content looks like a Sysmon event."""
        indicators = ["<Sysmon", "EventData", "Microsoft-Windows-Sysmon", "Image>", "CommandLine>"]
        return any(ind in content for ind in indicators)
