"""AlienVault OTX API client for threat intelligence."""

from typing import List
from .base import BaseEnrichment, EnrichmentResult
from config import config


class OTXEnrichment(BaseEnrichment):
    """Enriches IOCs using AlienVault OTX (Open Threat Exchange).

    Provides pulse data, malware families, and related indicators.
    Free API with generous rate limits.
    """

    SOURCE_NAME = "otx"
    BASE_URL = "https://otx.alienvault.com/api/v1"
    RATE_LIMIT_DELAY = 0.5

    def supported_types(self) -> List[str]:
        return ["ipv4", "ipv6", "domain", "md5", "sha1", "sha256", "url"]

    async def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Query OTX for IOC threat intelligence.

        Args:
            ioc_value: The IOC to look up.
            ioc_type: Type of IOC.

        Returns:
            EnrichmentResult with pulse and malware family data.
        """
        result = EnrichmentResult(
            source=self.SOURCE_NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
        )

        if not config.has_key("OTX_API_KEY"):
            result.error = "API key not configured"
            return result

        headers = {"X-OTX-API-KEY": config.OTX_API_KEY}

        try:
            if ioc_type in ("ipv4", "ipv6"):
                section = "IPv4" if ioc_type == "ipv4" else "IPv6"
                url = f"{self.BASE_URL}/indicators/{section}/{ioc_value}/general"
                data = await self._request_with_retry("GET", url, headers=headers)
                result = self._parse_general_response(data, result)

                # Get malware data
                url_malware = f"{self.BASE_URL}/indicators/{section}/{ioc_value}/malware"
                malware_data = await self._request_with_retry("GET", url_malware, headers=headers)
                self._add_malware_data(malware_data, result)

            elif ioc_type == "domain":
                url = f"{self.BASE_URL}/indicators/domain/{ioc_value}/general"
                data = await self._request_with_retry("GET", url, headers=headers)
                result = self._parse_general_response(data, result)

                url_malware = f"{self.BASE_URL}/indicators/domain/{ioc_value}/malware"
                malware_data = await self._request_with_retry("GET", url_malware, headers=headers)
                self._add_malware_data(malware_data, result)

            elif ioc_type in ("md5", "sha1", "sha256"):
                url = f"{self.BASE_URL}/indicators/file/{ioc_value}/general"
                data = await self._request_with_retry("GET", url, headers=headers)
                result = self._parse_general_response(data, result)

                url_analysis = f"{self.BASE_URL}/indicators/file/{ioc_value}/analysis"
                analysis_data = await self._request_with_retry("GET", url_analysis, headers=headers)
                self._add_analysis_data(analysis_data, result)

            elif ioc_type == "url":
                import base64
                url_encoded = base64.urlsafe_b64encode(ioc_value.encode()).decode()
                url = f"{self.BASE_URL}/indicators/url/{url_encoded}/general"
                data = await self._request_with_retry("GET", url, headers=headers)
                result = self._parse_general_response(data, result)

        except Exception as e:
            result.error = f"OTX API error: {str(e)}"

        return result

    def _parse_general_response(self, data: dict, result: EnrichmentResult) -> EnrichmentResult:
        """Parse OTX general indicator response."""
        if "error" in data:
            result.error = str(data.get("error", "Unknown error"))
            return result

        pulses = data.get("pulse_info", {})
        pulse_count = pulses.get("count", 0)
        pulse_list = pulses.get("pulses", [])

        # Extract tags from pulses
        tags = set()
        malware_families = set()
        for pulse in pulse_list[:20]:
            tags.update(pulse.get("tags", []))
            for indicator in pulse.get("indicators", [])[:5]:
                if indicator.get("type") == "malware_family":
                    malware_families.add(indicator.get("indicator", ""))

        result.tags = list(tags)[:20]
        result.risk_score = min(100, pulse_count * 10)
        result.malicious = pulse_count >= 3

        geo = data.get("geo", {}) or {}
        result.geo_data = {
            "country": geo.get("country_code", ""),
            "city": geo.get("city", ""),
            "latitude": geo.get("latitude", ""),
            "longitude": geo.get("longitude", ""),
        }

        result.summary = (
            f"OTX: {pulse_count} pulses reference this IOC. "
            f"Tags: {', '.join(list(tags)[:5]) if tags else 'none'}"
        )

        result.raw_response = {
            "pulse_count": pulse_count,
            "pulses": [
                {
                    "name": p.get("name", ""),
                    "description": (p.get("description", "")[:200] if p.get("description") else ""),
                    "created": p.get("created", ""),
                    "tags": p.get("tags", []),
                    "adversary": p.get("adversary", ""),
                }
                for p in pulse_list[:10]
            ],
            "malware_families": list(malware_families),
            "sections": data.get("sections", []),
        }

        return result

    def _add_malware_data(self, data: dict, result: EnrichmentResult) -> None:
        """Add malware-specific data to the result."""
        if "error" in data or not data:
            return

        malware_list = data.get("data", [])
        if malware_list:
            families = set()
            for m in malware_list[:10]:
                hash_val = m.get("hash", "")
                if hash_val:
                    families.add(hash_val[:16])

            result.raw_response["associated_malware"] = [
                {"hash": m.get("hash", ""), "detections": m.get("detections", {})}
                for m in malware_list[:5]
            ]
            result.risk_score = min(100, result.risk_score + len(malware_list) * 5)

    def _add_analysis_data(self, data: dict, result: EnrichmentResult) -> None:
        """Add file analysis data to the result."""
        if "error" in data or not data:
            return

        analysis = data.get("analysis", {})
        if analysis:
            info = analysis.get("info", {}).get("results", {})
            result.raw_response["file_analysis"] = {
                "file_type": info.get("file_type", ""),
                "file_class": info.get("file_class", ""),
                "ssdeep": info.get("ssdeep", ""),
            }
