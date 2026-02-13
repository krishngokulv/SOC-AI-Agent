"""VirusTotal API v3 client for IOC enrichment."""

from typing import List
from .base import BaseEnrichment, EnrichmentResult
from config import config


class VirusTotalEnrichment(BaseEnrichment):
    """Enriches IOCs using VirusTotal API v3.

    Supports IP addresses, domains, URLs, and file hashes.
    Free tier: 4 requests/minute, 500 requests/day.
    """

    SOURCE_NAME = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"
    RATE_LIMIT_DELAY = 15.5  # ~4 requests per minute on free tier

    def supported_types(self) -> List[str]:
        return ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]

    async def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Query VirusTotal for IOC intelligence.

        Args:
            ioc_value: The IOC to look up.
            ioc_type: Type of IOC.

        Returns:
            EnrichmentResult with detection ratios and community scores.
        """
        result = EnrichmentResult(
            source=self.SOURCE_NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
        )

        if not config.has_key("VIRUSTOTAL_API_KEY"):
            result.error = "API key not configured"
            return result

        headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

        try:
            if ioc_type in ("ipv4", "ipv6"):
                url = f"{self.BASE_URL}/ip_addresses/{ioc_value}"
                data = await self._request_with_retry("GET", url, headers=headers)
                result = self._parse_ip_response(data, result)

            elif ioc_type == "domain":
                url = f"{self.BASE_URL}/domains/{ioc_value}"
                data = await self._request_with_retry("GET", url, headers=headers)
                result = self._parse_domain_response(data, result)

            elif ioc_type == "url":
                import base64
                url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip("=")
                url = f"{self.BASE_URL}/urls/{url_id}"
                data = await self._request_with_retry("GET", url, headers=headers)
                result = self._parse_url_response(data, result)

            elif ioc_type in ("md5", "sha1", "sha256"):
                url = f"{self.BASE_URL}/files/{ioc_value}"
                data = await self._request_with_retry("GET", url, headers=headers)
                result = self._parse_file_response(data, result)

        except Exception as e:
            result.error = f"VirusTotal API error: {str(e)}"

        return result

    def _parse_ip_response(self, data: dict, result: EnrichmentResult) -> EnrichmentResult:
        """Parse VirusTotal IP address response."""
        if "error" in data:
            result.error = data.get("error", "Unknown error")
            return result

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1

        result.risk_score = min(100, ((malicious + suspicious) / max(total, 1)) * 100)
        result.malicious = malicious >= 3
        result.tags = attrs.get("tags", [])
        result.geo_data = {
            "country": attrs.get("country", ""),
            "continent": attrs.get("continent", ""),
            "as_owner": attrs.get("as_owner", ""),
            "asn": attrs.get("asn", ""),
        }
        result.summary = (
            f"VT: {malicious}/{total} engines flagged as malicious. "
            f"AS: {attrs.get('as_owner', 'N/A')}, Country: {attrs.get('country', 'N/A')}"
        )
        result.raw_response = {
            "last_analysis_stats": stats,
            "reputation": attrs.get("reputation", 0),
            "as_owner": attrs.get("as_owner", ""),
            "country": attrs.get("country", ""),
        }

        return result

    def _parse_domain_response(self, data: dict, result: EnrichmentResult) -> EnrichmentResult:
        """Parse VirusTotal domain response."""
        if "error" in data:
            result.error = data.get("error", "Unknown error")
            return result

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1

        result.risk_score = min(100, ((malicious + suspicious) / max(total, 1)) * 100)
        result.malicious = malicious >= 3
        result.tags = attrs.get("tags", [])
        result.summary = (
            f"VT: {malicious}/{total} engines flagged as malicious. "
            f"Registrar: {attrs.get('registrar', 'N/A')}"
        )
        result.raw_response = {
            "last_analysis_stats": stats,
            "reputation": attrs.get("reputation", 0),
            "registrar": attrs.get("registrar", ""),
            "creation_date": attrs.get("creation_date", ""),
            "categories": attrs.get("categories", {}),
        }

        return result

    def _parse_url_response(self, data: dict, result: EnrichmentResult) -> EnrichmentResult:
        """Parse VirusTotal URL response."""
        if "error" in data:
            result.error = data.get("error", "Unknown error")
            return result

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1

        result.risk_score = min(100, ((malicious + suspicious) / max(total, 1)) * 100)
        result.malicious = malicious >= 3
        result.tags = attrs.get("tags", [])
        result.summary = f"VT: {malicious}/{total} engines flagged URL as malicious."
        result.raw_response = {
            "last_analysis_stats": stats,
            "reputation": attrs.get("reputation", 0),
            "last_final_url": attrs.get("last_final_url", ""),
            "title": attrs.get("title", ""),
        }

        return result

    def _parse_file_response(self, data: dict, result: EnrichmentResult) -> EnrichmentResult:
        """Parse VirusTotal file hash response."""
        if "error" in data:
            result.error = data.get("error", "Unknown error")
            return result

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1

        result.risk_score = min(100, ((malicious + suspicious) / max(total, 1)) * 100)
        result.malicious = malicious >= 3
        result.tags = attrs.get("tags", [])
        result.summary = (
            f"VT: {malicious}/{total} detections. "
            f"Type: {attrs.get('type_description', 'N/A')}, "
            f"Names: {', '.join(attrs.get('names', [])[:3])}"
        )
        result.raw_response = {
            "last_analysis_stats": stats,
            "type_description": attrs.get("type_description", ""),
            "names": attrs.get("names", [])[:5],
            "size": attrs.get("size", 0),
            "sha256": attrs.get("sha256", ""),
            "popular_threat_classification": attrs.get("popular_threat_classification", {}),
        }

        return result
