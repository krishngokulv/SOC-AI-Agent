"""Windows Event Log parser.

Parses Windows Security, System, and Application event logs.
"""

import xml.etree.ElementTree as ET
import uuid
from datetime import datetime
from typing import Optional
from .sysmon import AlertData
from .ioc_extractor import IOCExtractor


class WindowsEventParser:
    """Parses Windows Event Log XML into AlertData."""

    # Notable security event IDs
    SECURITY_EVENTS = {
        "4624": "Successful Logon",
        "4625": "Failed Logon",
        "4634": "Logoff",
        "4648": "Explicit Credential Logon",
        "4672": "Special Privileges Assigned",
        "4688": "Process Creation",
        "4689": "Process Exit",
        "4697": "Service Installed",
        "4698": "Scheduled Task Created",
        "4720": "User Account Created",
        "4722": "User Account Enabled",
        "4724": "Password Reset Attempt",
        "4728": "Member Added to Security Group",
        "4732": "Member Added to Local Group",
        "4740": "Account Locked Out",
        "4756": "Member Added to Universal Group",
        "4768": "Kerberos TGT Requested",
        "4769": "Kerberos Service Ticket Requested",
        "4771": "Kerberos Pre-Auth Failed",
        "4776": "NTLM Auth Attempted",
        "5140": "Network Share Accessed",
        "5145": "Network Share Object Checked",
        "7045": "Service Installed",
    }

    @classmethod
    def parse(cls, content: str) -> AlertData:
        """Parse Windows Event Log XML content.

        Args:
            content: Raw XML string from Windows Event Log.

        Returns:
            Normalized AlertData object.
        """
        alert = AlertData(
            raw_content=content,
            alert_type="windows_event",
        )

        raw_fields = {}

        try:
            root = ET.fromstring(content.strip())
        except ET.ParseError:
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

        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

        # System section
        system = root.find(".//System") or root.find(f".//{{{ns['ns']}}}System")
        if system is not None:
            for elem in system:
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if elem.text:
                    raw_fields[tag] = elem.text
                for attr_name, attr_val in elem.attrib.items():
                    raw_fields[f"{tag}_{attr_name}"] = attr_val

        event_id = raw_fields.get("EventID", "")
        raw_fields["EventDescription"] = cls.SECURITY_EVENTS.get(event_id, "Unknown Event")

        # TimeCreated
        time_created = raw_fields.get("TimeCreated_SystemTime", "")
        if time_created:
            try:
                alert.timestamp = datetime.fromisoformat(time_created.replace("Z", "+00:00"))
            except ValueError:
                pass

        alert.source_host = raw_fields.get("Computer", "")

        # EventData section
        event_data = (
            root.findall(".//EventData/Data")
            or root.findall(f".//{{{ns['ns']}}}EventData/{{{ns['ns']}}}Data")
            or root.findall(".//Data")
        )

        for data_elem in event_data:
            name = data_elem.get("Name", "")
            value = data_elem.text or ""
            if name:
                raw_fields[name] = value

        alert.raw_fields = raw_fields

        # Map common fields
        alert.user = raw_fields.get("TargetUserName", raw_fields.get("SubjectUserName"))
        alert.source_ip = raw_fields.get("IpAddress", raw_fields.get("SourceAddress"))
        alert.dest_ip = raw_fields.get("DestAddress")
        alert.process_name = raw_fields.get("NewProcessName", raw_fields.get("ProcessName"))
        alert.command_line = raw_fields.get("CommandLine", raw_fields.get("ProcessCommandLine"))
        alert.parent_process = raw_fields.get("ParentProcessName")

        # Extract IOCs
        all_text = content + " " + " ".join(str(v) for v in raw_fields.values())
        alert.extracted_iocs = IOCExtractor.extract(all_text)

        return alert

    @classmethod
    def can_parse(cls, content: str) -> bool:
        """Check if content looks like a Windows Event Log."""
        indicators = ["<Event ", "EventData", "Microsoft-Windows-Security", "EventID"]
        return any(ind in content for ind in indicators) and "Sysmon" not in content
