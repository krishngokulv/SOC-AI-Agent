"""Generic firewall log parser.

Parses common firewall log formats including iptables, pf, Windows Firewall,
and generic syslog-style firewall entries.
"""

import re
import uuid
from datetime import datetime
from typing import Optional
from .sysmon import AlertData
from .ioc_extractor import IOCExtractor


class FirewallParser:
    """Parses firewall logs into AlertData."""

    # Common firewall log patterns
    PATTERNS = {
        "iptables": re.compile(
            r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
            r"(?P<host>\S+)\s+kernel:.*?"
            r"(?:IN=(?P<in_iface>\S*))?\s*"
            r"(?:OUT=(?P<out_iface>\S*))?\s*"
            r"(?:SRC=(?P<src>\S+))?\s*"
            r"(?:DST=(?P<dst>\S+))?\s*"
            r".*?"
            r"(?:PROTO=(?P<proto>\S+))?\s*"
            r"(?:SPT=(?P<spt>\d+))?\s*"
            r"(?:DPT=(?P<dpt>\d+))?",
            re.DOTALL,
        ),
        "pf": re.compile(
            r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
            r"(?P<host>\S+)\s+\S+:.*?"
            r"(?P<action>pass|block)\s+(?:in|out)\s+on\s+(?P<iface>\S+):\s*"
            r"(?P<src>[\d.]+)(?:\.(?P<spt>\d+))?\s*>\s*"
            r"(?P<dst>[\d.]+)(?:\.(?P<dpt>\d+))?",
        ),
        "generic_csv": re.compile(
            r"(?P<timestamp>[\d\-/]+\s+[\d:]+)\s*,\s*"
            r"(?P<action>\w+)\s*,\s*"
            r"(?P<proto>\w+)\s*,\s*"
            r"(?P<src>[\d.]+)\s*,\s*"
            r"(?P<dst>[\d.]+)\s*,\s*"
            r"(?P<spt>\d+)\s*,\s*"
            r"(?P<dpt>\d+)",
        ),
    }

    # Additional field extraction
    IP_PORT_PATTERN = re.compile(r"(\d+\.\d+\.\d+\.\d+)[:\s]+(\d+)")
    ACTION_PATTERN = re.compile(r"\b(ACCEPT|DENY|DROP|BLOCK|REJECT|ALLOW|PASS|PERMIT)\b", re.IGNORECASE)
    PROTO_PATTERN = re.compile(r"\b(TCP|UDP|ICMP|GRE|ESP|AH)\b", re.IGNORECASE)

    @classmethod
    def parse(cls, content: str) -> AlertData:
        """Parse firewall log content.

        Args:
            content: Raw firewall log text.

        Returns:
            Normalized AlertData object.
        """
        alert = AlertData(
            raw_content=content,
            alert_type="firewall",
        )

        raw_fields = {}
        lines = content.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            parsed = False
            for fmt_name, pattern in cls.PATTERNS.items():
                match = pattern.search(line)
                if match:
                    groups = match.groupdict()
                    raw_fields.update({k: v for k, v in groups.items() if v})
                    raw_fields["format_detected"] = fmt_name
                    parsed = True
                    break

            if not parsed:
                # Fallback: extract what we can
                action_match = cls.ACTION_PATTERN.search(line)
                if action_match:
                    raw_fields["action"] = action_match.group(1).upper()

                proto_match = cls.PROTO_PATTERN.search(line)
                if proto_match:
                    raw_fields["proto"] = proto_match.group(1).upper()

                ip_ports = cls.IP_PORT_PATTERN.findall(line)
                if len(ip_ports) >= 2:
                    raw_fields.setdefault("src", ip_ports[0][0])
                    raw_fields.setdefault("spt", ip_ports[0][1])
                    raw_fields.setdefault("dst", ip_ports[1][0])
                    raw_fields.setdefault("dpt", ip_ports[1][1])
                elif len(ip_ports) == 1:
                    raw_fields.setdefault("src", ip_ports[0][0])
                    raw_fields.setdefault("spt", ip_ports[0][1])

        # Parse timestamp
        ts_str = raw_fields.get("timestamp", "")
        if ts_str:
            for fmt in [
                "%b %d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S",
            ]:
                try:
                    parsed_ts = datetime.strptime(ts_str, fmt)
                    if parsed_ts.year == 1900:
                        parsed_ts = parsed_ts.replace(year=datetime.utcnow().year)
                    alert.timestamp = parsed_ts
                    break
                except ValueError:
                    continue

        alert.source_ip = raw_fields.get("src")
        alert.dest_ip = raw_fields.get("dst")
        alert.source_host = raw_fields.get("host")
        alert.raw_fields = raw_fields

        # Extract IOCs
        alert.extracted_iocs = IOCExtractor.extract(content)

        return alert

    @classmethod
    def can_parse(cls, content: str) -> bool:
        """Check if content looks like a firewall log."""
        indicators = [
            "SRC=", "DST=", "SPT=", "DPT=", "PROTO=",
            "iptables", "firewall", "ACCEPT", "DROP", "BLOCK",
            "pass in", "block in", "pass out", "block out",
        ]
        content_upper = content.upper()
        return sum(1 for ind in indicators if ind.upper() in content_upper) >= 2
