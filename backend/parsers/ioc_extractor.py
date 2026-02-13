"""Regex-based IOC extraction from arbitrary text.

Extracts IPs, domains, URLs, hashes, emails, CVEs, and file paths
with defanging support.
"""

import re
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class IOCType(str, Enum):
    """Types of Indicators of Compromise."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    FILE_PATH_WINDOWS = "file_path_windows"
    FILE_PATH_LINUX = "file_path_linux"


@dataclass
class IOC:
    """Represents a single extracted IOC."""
    ioc_type: IOCType
    value: str
    original_value: str
    context: str = ""

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "type": self.ioc_type.value,
            "value": self.value,
            "original_value": self.original_value,
            "context": self.context,
        }


# Private/reserved IPv4 ranges to exclude
PRIVATE_IPV4_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
]

# Common TLDs for domain validation
VALID_TLDS = {
    "com", "net", "org", "io", "info", "biz", "co", "us", "uk", "de", "fr",
    "ru", "cn", "jp", "br", "in", "au", "ca", "it", "es", "nl", "se", "no",
    "fi", "dk", "pl", "cz", "at", "ch", "be", "pt", "ie", "nz", "za", "mx",
    "ar", "cl", "kr", "tw", "hk", "sg", "my", "th", "ph", "vn", "id", "pk",
    "bd", "lk", "np", "edu", "gov", "mil", "int", "xyz", "top", "site",
    "online", "club", "wang", "shop", "app", "dev", "tech", "cloud", "pro",
    "cc", "tv", "me", "mobi", "asia", "name", "tel", "travel", "museum",
    "aero", "coop", "jobs", "cat", "post", "xxx", "onion", "bit", "tk",
    "ml", "ga", "cf", "gq", "pw", "ws", "la", "ly", "to", "ac", "sh",
}


def _defang(text: str) -> str:
    """Re-fang defanged indicators."""
    result = text
    result = result.replace("hxxp://", "http://")
    result = result.replace("hxxps://", "https://")
    result = result.replace("hXXp://", "http://")
    result = result.replace("hXXps://", "https://")
    result = result.replace("[.]", ".")
    result = result.replace("[dot]", ".")
    result = result.replace("[at]", "@")
    result = result.replace("[@]", "@")
    result = result.replace("[://]", "://")
    return result


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IPv4 address is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for network in PRIVATE_IPV4_RANGES:
            if addr in network:
                return True
        return False
    except ValueError:
        return True


def _get_context(text: str, match_start: int, match_end: int, window: int = 50) -> str:
    """Extract surrounding context for an IOC match."""
    ctx_start = max(0, match_start - window)
    ctx_end = min(len(text), match_end + window)
    context = text[ctx_start:ctx_end].strip()
    context = re.sub(r"\s+", " ", context)
    return context


class IOCExtractor:
    """Extracts Indicators of Compromise from arbitrary text."""

    # Regex patterns
    IPV4_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[?\.\]?)){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    IPV6_PATTERN = re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
        r"|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    )

    URL_PATTERN = re.compile(
        r"(?:h[xX]{2}ps?://|https?://|ftp://)"
        r"[^\s<>\"'\)\]}{,;]{3,}",
        re.IGNORECASE,
    )

    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\[?\.\]?){1,}"
        r"[a-zA-Z]{2,63}\b"
    )

    MD5_PATTERN = re.compile(r"\b[0-9a-fA-F]{32}\b")
    SHA1_PATTERN = re.compile(r"\b[0-9a-fA-F]{40}\b")
    SHA256_PATTERN = re.compile(r"\b[0-9a-fA-F]{64}\b")

    EMAIL_PATTERN = re.compile(
        r"\b[a-zA-Z0-9._%+\-]+(?:\[?@\]?|\[@\])[a-zA-Z0-9.\-]+\[?\.\]?[a-zA-Z]{2,}\b"
    )

    CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    WINDOWS_PATH_PATTERN = re.compile(
        r"[A-Za-z]:\\(?:[^\\\s<>\"*?|:]{1,255}\\)*[^\\\s<>\"*?|:]{1,255}"
    )

    LINUX_PATH_PATTERN = re.compile(
        r"(?:^|[\s\"'=])(/(?:usr|etc|var|tmp|opt|home|root|bin|sbin|lib|proc|sys|dev|mnt|media|srv)"
        r"(?:/[^\s<>\"'*?|;&#]{1,255})+)"
    )

    @classmethod
    def extract(cls, text: str, include_private_ips: bool = False) -> List[IOC]:
        """Extract all IOCs from the given text.

        Args:
            text: Raw text to extract IOCs from.
            include_private_ips: If True, include private/reserved IP addresses.

        Returns:
            List of extracted IOC objects.
        """
        if not text:
            return []

        defanged_text = _defang(text)
        iocs: List[IOC] = []
        seen_values: set = set()

        # Extract SHA256 first (longest hash)
        for match in cls.SHA256_PATTERN.finditer(defanged_text):
            value = match.group(0).lower()
            if value not in seen_values:
                seen_values.add(value)
                iocs.append(IOC(
                    ioc_type=IOCType.SHA256,
                    value=value,
                    original_value=match.group(0),
                    context=_get_context(text, match.start(), match.end()),
                ))

        # Extract SHA1 (exclude substrings of SHA256)
        sha256_values = {ioc.value for ioc in iocs if ioc.ioc_type == IOCType.SHA256}
        for match in cls.SHA1_PATTERN.finditer(defanged_text):
            value = match.group(0).lower()
            if value not in seen_values and not any(value in s for s in sha256_values):
                seen_values.add(value)
                iocs.append(IOC(
                    ioc_type=IOCType.SHA1,
                    value=value,
                    original_value=match.group(0),
                    context=_get_context(text, match.start(), match.end()),
                ))

        # Extract MD5 (exclude substrings of SHA1/SHA256)
        longer_hashes = {ioc.value for ioc in iocs if ioc.ioc_type in (IOCType.SHA1, IOCType.SHA256)}
        for match in cls.MD5_PATTERN.finditer(defanged_text):
            value = match.group(0).lower()
            if value not in seen_values and not any(value in s for s in longer_hashes):
                seen_values.add(value)
                iocs.append(IOC(
                    ioc_type=IOCType.MD5,
                    value=value,
                    original_value=match.group(0),
                    context=_get_context(text, match.start(), match.end()),
                ))

        # Extract URLs
        for match in cls.URL_PATTERN.finditer(defanged_text):
            value = match.group(0).rstrip(".,;:)>]}")
            if value not in seen_values:
                seen_values.add(value)
                iocs.append(IOC(
                    ioc_type=IOCType.URL,
                    value=value,
                    original_value=match.group(0),
                    context=_get_context(text, match.start(), match.end()),
                ))

        # Extract CVEs
        for match in cls.CVE_PATTERN.finditer(defanged_text):
            value = match.group(0).upper()
            if value not in seen_values:
                seen_values.add(value)
                iocs.append(IOC(
                    ioc_type=IOCType.CVE,
                    value=value,
                    original_value=match.group(0),
                    context=_get_context(text, match.start(), match.end()),
                ))

        # Extract emails
        for match in cls.EMAIL_PATTERN.finditer(defanged_text):
            value = _defang(match.group(0)).lower()
            if value not in seen_values and "." in value.split("@")[-1]:
                seen_values.add(value)
                iocs.append(IOC(
                    ioc_type=IOCType.EMAIL,
                    value=value,
                    original_value=match.group(0),
                    context=_get_context(text, match.start(), match.end()),
                ))

        # Extract IPv4
        for match in cls.IPV4_PATTERN.finditer(defanged_text):
            value = _defang(match.group(0))
            if value not in seen_values:
                if include_private_ips or not _is_private_ip(value):
                    seen_values.add(value)
                    iocs.append(IOC(
                        ioc_type=IOCType.IPV4,
                        value=value,
                        original_value=match.group(0),
                        context=_get_context(text, match.start(), match.end()),
                    ))

        # Extract IPv6
        for match in cls.IPV6_PATTERN.finditer(defanged_text):
            value = match.group(0)
            try:
                normalized = str(ipaddress.ip_address(value))
                if normalized not in seen_values and not ipaddress.ip_address(value).is_private:
                    seen_values.add(normalized)
                    iocs.append(IOC(
                        ioc_type=IOCType.IPV6,
                        value=normalized,
                        original_value=match.group(0),
                        context=_get_context(text, match.start(), match.end()),
                    ))
            except ValueError:
                continue

        # Extract domains (filter out IPs and known non-domains)
        url_domains = set()
        for ioc in iocs:
            if ioc.ioc_type == IOCType.URL:
                domain_match = re.search(r"://([^/:\s]+)", ioc.value)
                if domain_match:
                    url_domains.add(domain_match.group(1).lower())

        for match in cls.DOMAIN_PATTERN.finditer(defanged_text):
            value = _defang(match.group(0)).lower().rstrip(".")
            tld = value.split(".")[-1]
            if (
                value not in seen_values
                and tld in VALID_TLDS
                and len(value.split(".")) >= 2
                and not cls.IPV4_PATTERN.match(value)
                and len(value) > 4
            ):
                seen_values.add(value)
                iocs.append(IOC(
                    ioc_type=IOCType.DOMAIN,
                    value=value,
                    original_value=match.group(0),
                    context=_get_context(text, match.start(), match.end()),
                ))

        # Extract Windows file paths
        for match in cls.WINDOWS_PATH_PATTERN.finditer(text):
            value = match.group(0)
            if value not in seen_values and len(value) > 5:
                seen_values.add(value)
                iocs.append(IOC(
                    ioc_type=IOCType.FILE_PATH_WINDOWS,
                    value=value,
                    original_value=value,
                    context=_get_context(text, match.start(), match.end()),
                ))

        # Extract Linux file paths
        for match in cls.LINUX_PATH_PATTERN.finditer(text):
            value = match.group(1) if match.group(1) else match.group(0)
            value = value.strip()
            if value not in seen_values and len(value) > 3:
                seen_values.add(value)
                iocs.append(IOC(
                    ioc_type=IOCType.FILE_PATH_LINUX,
                    value=value,
                    original_value=value,
                    context=_get_context(text, match.start(), match.end()),
                ))

        return iocs

    @classmethod
    def extract_ips(cls, text: str) -> List[IOC]:
        """Extract only IP addresses from text."""
        return [ioc for ioc in cls.extract(text) if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6)]

    @classmethod
    def extract_hashes(cls, text: str) -> List[IOC]:
        """Extract only file hashes from text."""
        return [ioc for ioc in cls.extract(text) if ioc.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)]

    @classmethod
    def extract_domains(cls, text: str) -> List[IOC]:
        """Extract only domains from text."""
        return [ioc for ioc in cls.extract(text) if ioc.ioc_type == IOCType.DOMAIN]
