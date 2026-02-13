"""Basic PCAP metadata parser.

Extracts network connection metadata from PCAP files using scapy.
Falls back to text-based parsing if scapy is not available.
"""

import uuid
import re
from datetime import datetime
from typing import Optional
from .sysmon import AlertData
from .ioc_extractor import IOCExtractor


class PcapParser:
    """Parses PCAP files or tcpdump-style text output."""

    # tcpdump-style line pattern
    TCPDUMP_PATTERN = re.compile(
        r"(?P<timestamp>[\d:.]+)\s+"
        r"(?:IP\s+)?"
        r"(?P<src>[\d.]+)(?:\.(?P<spt>\d+))?\s*>\s*"
        r"(?P<dst>[\d.]+)(?:\.(?P<dpt>\d+))?:?\s*"
        r"(?P<rest>.*)"
    )

    # Zeek/Bro conn.log pattern
    ZEEK_PATTERN = re.compile(
        r"(?P<timestamp>[\d.]+)\s+"
        r"(?P<uid>\S+)\s+"
        r"(?P<src>[\d.]+)\s+"
        r"(?P<spt>\d+)\s+"
        r"(?P<dst>[\d.]+)\s+"
        r"(?P<dpt>\d+)\s+"
        r"(?P<proto>\S+)"
    )

    @classmethod
    def parse(cls, content: str) -> AlertData:
        """Parse PCAP text output or binary PCAP file.

        For binary PCAP files, attempts to use scapy for parsing.
        For text output (tcpdump, tshark), uses regex parsing.

        Args:
            content: Raw PCAP text output or file content.

        Returns:
            Normalized AlertData object.
        """
        alert = AlertData(
            raw_content=content,
            alert_type="pcap",
        )

        raw_fields = {
            "connections": [],
            "protocols": set(),
            "source_ips": set(),
            "dest_ips": set(),
            "dest_ports": set(),
            "total_packets": 0,
        }

        # Try binary PCAP parsing with scapy
        if cls._is_binary(content):
            raw_fields = cls._parse_binary_pcap(content, raw_fields)
        else:
            # Text-based parsing
            lines = content.strip().split("\n")
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                raw_fields["total_packets"] += 1

                # Try tcpdump format
                match = cls.TCPDUMP_PATTERN.search(line)
                if match:
                    groups = match.groupdict()
                    conn = {
                        "src": groups.get("src"),
                        "spt": groups.get("spt"),
                        "dst": groups.get("dst"),
                        "dpt": groups.get("dpt"),
                        "info": groups.get("rest", ""),
                    }
                    raw_fields["connections"].append(conn)
                    if conn["src"]:
                        raw_fields["source_ips"].add(conn["src"])
                    if conn["dst"]:
                        raw_fields["dest_ips"].add(conn["dst"])
                    if conn["dpt"]:
                        raw_fields["dest_ports"].add(conn["dpt"])
                    continue

                # Try Zeek format
                match = cls.ZEEK_PATTERN.search(line)
                if match:
                    groups = match.groupdict()
                    conn = {
                        "src": groups.get("src"),
                        "spt": groups.get("spt"),
                        "dst": groups.get("dst"),
                        "dpt": groups.get("dpt"),
                        "proto": groups.get("proto"),
                    }
                    raw_fields["connections"].append(conn)
                    if conn["src"]:
                        raw_fields["source_ips"].add(conn["src"])
                    if conn["dst"]:
                        raw_fields["dest_ips"].add(conn["dst"])
                    if conn["dpt"]:
                        raw_fields["dest_ports"].add(conn["dpt"])
                    if conn.get("proto"):
                        raw_fields["protocols"].add(conn["proto"])

        # Convert sets to lists for serialization
        raw_fields["protocols"] = list(raw_fields["protocols"])
        raw_fields["source_ips"] = list(raw_fields["source_ips"])
        raw_fields["dest_ips"] = list(raw_fields["dest_ips"])
        raw_fields["dest_ports"] = list(raw_fields["dest_ports"])

        # Set primary IPs
        if raw_fields["source_ips"]:
            alert.source_ip = raw_fields["source_ips"][0]
        if raw_fields["dest_ips"]:
            alert.dest_ip = raw_fields["dest_ips"][0]

        alert.raw_fields = raw_fields

        # Extract IOCs from text content
        alert.extracted_iocs = IOCExtractor.extract(content)

        return alert

    @classmethod
    def _is_binary(cls, content: str) -> bool:
        """Check if content appears to be binary PCAP data."""
        try:
            if content[:4] in ("\xd4\xc3\xb2\xa1", "\xa1\xb2\xc3\xd4"):
                return True
        except (IndexError, TypeError):
            pass
        return False

    @classmethod
    def _parse_binary_pcap(cls, content: str, raw_fields: dict) -> dict:
        """Attempt to parse binary PCAP using scapy."""
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS
            import tempfile
            import os

            # Write to temp file for scapy
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
                f.write(content.encode("latin-1") if isinstance(content, str) else content)
                tmp_path = f.name

            try:
                packets = rdpcap(tmp_path)
                raw_fields["total_packets"] = len(packets)

                for pkt in packets[:1000]:  # Limit to first 1000 packets
                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        raw_fields["source_ips"].add(src)
                        raw_fields["dest_ips"].add(dst)

                        conn = {"src": src, "dst": dst}

                        if TCP in pkt:
                            conn["spt"] = str(pkt[TCP].sport)
                            conn["dpt"] = str(pkt[TCP].dport)
                            raw_fields["dest_ports"].add(str(pkt[TCP].dport))
                            raw_fields["protocols"].add("TCP")
                        elif UDP in pkt:
                            conn["spt"] = str(pkt[UDP].sport)
                            conn["dpt"] = str(pkt[UDP].dport)
                            raw_fields["dest_ports"].add(str(pkt[UDP].dport))
                            raw_fields["protocols"].add("UDP")

                            if DNS in pkt and pkt[DNS].qd:
                                try:
                                    conn["dns_query"] = pkt[DNS].qd.qname.decode()
                                except (AttributeError, UnicodeDecodeError):
                                    pass

                        raw_fields["connections"].append(conn)

            finally:
                os.unlink(tmp_path)

        except ImportError:
            raw_fields["parse_error"] = "scapy not available for binary PCAP parsing"
        except Exception as e:
            raw_fields["parse_error"] = f"PCAP parse error: {str(e)}"

        return raw_fields

    @classmethod
    def can_parse(cls, content: str) -> bool:
        """Check if content looks like PCAP output."""
        if cls._is_binary(content):
            return True
        indicators = ["IP ", " > ", "Flags [", ".http:", ".dns:", "tcpdump", "tshark"]
        return any(ind in content for ind in indicators)
