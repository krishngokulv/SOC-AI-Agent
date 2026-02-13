"""URLhaus API client for URL/domain threat data.

No API key required.
"""

from typing import List
from .base import BaseEnrichment, EnrichmentResult


class URLhausEnrichment(BaseEnrichment):
    """Enriches URLs and domains using URLhaus (abuse.ch).

    No API key required. Provides malware distribution data.
    """

    SOURCE_NAME = "urlhaus"
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"
    RATE_LIMIT_DELAY = 0.5

    def supported_types(self) -> List[str]:
        return ["url", "domain", "md5", "sha256"]

    async def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Query URLhaus for URL/domain/hash threat data.

        Args:
            ioc_value: The IOC to look up.
            ioc_type: Type of IOC.

        Returns:
            EnrichmentResult with malware distribution data.
        """
        result = EnrichmentResult(
            source=self.SOURCE_NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
        )

        try:
            if ioc_type == "url":
                data = await self._request_with_retry(
                    "POST",
                    f"{self.BASE_URL}/url/",
                    json_data={"url": ioc_value},
                )
                result = self._parse_url_response(data, result)

            elif ioc_type == "domain":
                data = await self._request_with_retry(
                    "POST",
                    f"{self.BASE_URL}/host/",
                    json_data={"host": ioc_value},
                )
                result = self._parse_host_response(data, result)

            elif ioc_type in ("md5", "sha256"):
                payload_key = "md5_hash" if ioc_type == "md5" else "sha256_hash"
                data = await self._request_with_retry(
                    "POST",
                    f"{self.BASE_URL}/payload/",
                    json_data={payload_key: ioc_value},
                )
                result = self._parse_payload_response(data, result)

        except Exception as e:
            result.error = f"URLhaus API error: {str(e)}"

        return result

    def _parse_url_response(self, data: dict, result: EnrichmentResult) -> EnrichmentResult:
        """Parse URLhaus URL lookup response."""
        query_status = data.get("query_status", "")

        if query_status == "no_results":
            result.summary = "URLhaus: URL not found in database"
            return result

        if query_status != "ok":
            result.error = f"URLhaus query status: {query_status}"
            return result

        url_status = data.get("url_status", "")
        threat = data.get("threat", "")
        tags = data.get("tags", []) or []
        date_added = data.get("date_added", "")

        result.malicious = url_status == "online" or threat != ""
        result.risk_score = 80.0 if result.malicious else 20.0
        result.tags = [t for t in tags if t]

        payloads = data.get("payloads", []) or []
        payload_info = []
        for p in payloads[:5]:
            payload_info.append({
                "filename": p.get("filename", ""),
                "file_type": p.get("file_type", ""),
                "signature": p.get("signature", ""),
                "virustotal_percent": p.get("virustotal", {}).get("percent", 0) if p.get("virustotal") else 0,
            })

        result.summary = (
            f"URLhaus: Status={url_status}, Threat={threat or 'N/A'}, "
            f"Tags={', '.join(result.tags) if result.tags else 'none'}"
        )

        result.raw_response = {
            "url_status": url_status,
            "threat": threat,
            "date_added": date_added,
            "tags": result.tags,
            "payloads": payload_info,
            "reporter": data.get("reporter", ""),
            "blacklists": data.get("blacklists", {}),
        }

        return result

    def _parse_host_response(self, data: dict, result: EnrichmentResult) -> EnrichmentResult:
        """Parse URLhaus host/domain lookup response."""
        query_status = data.get("query_status", "")

        if query_status == "no_results":
            result.summary = "URLhaus: Host not found in database"
            return result

        if query_status not in ("ok", "is_host"):
            result.error = f"URLhaus query status: {query_status}"
            return result

        url_count = data.get("url_count", 0)
        urls_online = data.get("urls_online", 0)
        blacklists = data.get("blacklists", {})

        result.malicious = urls_online > 0 or url_count > 5
        result.risk_score = min(100, url_count * 5 + urls_online * 20)
        result.tags = []

        # Check blacklist status
        for bl_name, bl_status in (blacklists or {}).items():
            if bl_status and bl_status != "not listed":
                result.tags.append(f"{bl_name}:{bl_status}")

        result.summary = (
            f"URLhaus: {url_count} URLs tracked, {urls_online} currently online"
        )

        urls = data.get("urls", []) or []
        result.raw_response = {
            "url_count": url_count,
            "urls_online": urls_online,
            "blacklists": blacklists,
            "sample_urls": [
                {
                    "url": u.get("url", ""),
                    "url_status": u.get("url_status", ""),
                    "threat": u.get("threat", ""),
                    "date_added": u.get("date_added", ""),
                    "tags": u.get("tags", []),
                }
                for u in urls[:10]
            ],
        }

        return result

    def _parse_payload_response(self, data: dict, result: EnrichmentResult) -> EnrichmentResult:
        """Parse URLhaus payload/hash lookup response."""
        query_status = data.get("query_status", "")

        if query_status == "no_results":
            result.summary = "URLhaus: Hash not found in database"
            return result

        if query_status not in ("ok", "hash_not_found"):
            result.error = f"URLhaus query status: {query_status}"
            return result

        file_type = data.get("file_type", "")
        signature = data.get("signature", "")
        url_count = data.get("url_count", 0)

        result.malicious = signature != "" or url_count > 0
        result.risk_score = 90.0 if result.malicious else 10.0
        result.tags = [signature] if signature else []

        result.summary = (
            f"URLhaus: Signature={signature or 'N/A'}, "
            f"Type={file_type or 'N/A'}, "
            f"Distribution URLs={url_count}"
        )

        result.raw_response = {
            "file_type": file_type,
            "file_size": data.get("file_size", 0),
            "signature": signature,
            "url_count": url_count,
            "firstseen": data.get("firstseen", ""),
            "lastseen": data.get("lastseen", ""),
            "virustotal": data.get("virustotal", {}),
        }

        return result
