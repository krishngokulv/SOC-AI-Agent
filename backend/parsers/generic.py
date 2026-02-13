"""Generic/freeform text alert parser.

Handles any alert format not covered by specialized parsers.
Uses pattern matching and IOC extraction to normalize the data.
"""

import re
import uuid
from datetime import datetime
from typing import Optional
from .sysmon import AlertData
from .ioc_extractor import IOCExtractor


class GenericParser:
    """Parses generic/freeform text alerts."""

    # Common syslog-style timestamp patterns
    TIMESTAMP_PATTERNS = [
        (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"), "%Y-%m-%dT%H:%M:%S"),
        (re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"), "%Y-%m-%d %H:%M:%S"),
        (re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
        (re.compile(r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"), "%d/%b/%Y:%H:%M:%S"),
        (re.compile(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"), "%Y/%m/%d %H:%M:%S"),
    ]

    # User/account patterns
    USER_PATTERNS = [
        re.compile(r"(?:user|username|account|login)[=:\s]+['\"]?(\S+)['\"]?", re.IGNORECASE),
        re.compile(r"for (?:user |invalid user )?(\S+) from", re.IGNORECASE),
    ]

    # Process patterns
    PROCESS_PATTERN = re.compile(r"(?:process|executable|image|program)[=:\s]+['\"]?([^\s'\"]+)", re.IGNORECASE)
    CMD_PATTERN = re.compile(r"(?:command|cmd|commandline|command_line)[=:\s]+['\"]?(.+?)(?:['\"]?\s*$|['\"]?\s+\w+=)", re.IGNORECASE | re.MULTILINE)

    # Host patterns
    HOST_PATTERN = re.compile(r"(?:hostname|host|computer|machine)[=:\s]+['\"]?(\S+)['\"]?", re.IGNORECASE)

    @classmethod
    def parse(cls, content: str) -> AlertData:
        """Parse generic text alert content.

        Args:
            content: Raw alert text in any format.

        Returns:
            Normalized AlertData object.
        """
        alert = AlertData(
            raw_content=content,
            alert_type="generic",
        )

        raw_fields = {}

        # Try to extract timestamp
        for pattern, fmt in cls.TIMESTAMP_PATTERNS:
            match = pattern.search(content)
            if match:
                ts_str = match.group(1)
                try:
                    ts_str_clean = ts_str.replace("Z", "+00:00")
                    alert.timestamp = datetime.fromisoformat(ts_str_clean)
                except ValueError:
                    try:
                        parsed = datetime.strptime(ts_str, fmt)
                        if parsed.year == 1900:
                            parsed = parsed.replace(year=datetime.utcnow().year)
                        alert.timestamp = parsed
                    except ValueError:
                        continue
                break

        # Extract user
        for pattern in cls.USER_PATTERNS:
            match = pattern.search(content)
            if match:
                alert.user = match.group(1).strip("'\"")
                raw_fields["user"] = alert.user
                break

        # Extract process
        match = cls.PROCESS_PATTERN.search(content)
        if match:
            alert.process_name = match.group(1).strip("'\"")
            raw_fields["process"] = alert.process_name

        # Extract command line
        match = cls.CMD_PATTERN.search(content)
        if match:
            alert.command_line = match.group(1).strip("'\"")
            raw_fields["command_line"] = alert.command_line

        # Extract hostname
        match = cls.HOST_PATTERN.search(content)
        if match:
            alert.source_host = match.group(1).strip("'\"")
            raw_fields["host"] = alert.source_host

        # Try key=value extraction
        kv_pattern = re.compile(r"(\w+)=['\"]?([^'\"=\n]+)['\"]?")
        for key, value in kv_pattern.findall(content):
            key_lower = key.lower()
            value = value.strip()
            raw_fields[key] = value

            if key_lower in ("src", "srcip", "source_ip", "srcaddr") and not alert.source_ip:
                alert.source_ip = value
            elif key_lower in ("dst", "dstip", "dest_ip", "dstaddr", "destination") and not alert.dest_ip:
                alert.dest_ip = value
            elif key_lower in ("hostname", "host", "computer") and not alert.source_host:
                alert.source_host = value

        # Try JSON-like extraction
        json_pattern = re.compile(r'"(\w+)"\s*:\s*"([^"]*)"')
        for key, value in json_pattern.findall(content):
            if key not in raw_fields:
                raw_fields[key] = value

        alert.raw_fields = raw_fields

        # Extract IOCs
        alert.extracted_iocs = IOCExtractor.extract(content)

        # Set IP fields from extracted IOCs if not already set
        ip_iocs = [ioc for ioc in alert.extracted_iocs if ioc.ioc_type.value in ("ipv4", "ipv6")]
        if ip_iocs and not alert.source_ip:
            alert.source_ip = ip_iocs[0].value
        if len(ip_iocs) > 1 and not alert.dest_ip:
            alert.dest_ip = ip_iocs[1].value

        # Set domain from extracted IOCs
        domain_iocs = [ioc for ioc in alert.extracted_iocs if ioc.ioc_type.value == "domain"]
        if domain_iocs and not alert.domain:
            alert.domain = domain_iocs[0].value

        return alert

    @classmethod
    def can_parse(cls, content: str) -> bool:
        """Generic parser can parse anything."""
        return True
