"""AbuseIPDB API client for IP reputation checking."""

from typing import List
from .base import BaseEnrichment, EnrichmentResult
from config import config


class AbuseIPDBEnrichment(BaseEnrichment):
    """Enriches IP addresses using AbuseIPDB.

    Free tier: 1000 checks/day.
    """

    SOURCE_NAME = "abuseipdb"
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    RATE_LIMIT_DELAY = 1.0

    def supported_types(self) -> List[str]:
        return ["ipv4", "ipv6"]

    async def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Query AbuseIPDB for IP reputation.

        Args:
            ioc_value: IP address to check.
            ioc_type: Should be ipv4 or ipv6.

        Returns:
            EnrichmentResult with abuse confidence score and reports.
        """
        result = EnrichmentResult(
            source=self.SOURCE_NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
        )

        if not config.has_key("ABUSEIPDB_API_KEY"):
            result.error = "API key not configured"
            return result

        headers = {
            "Key": config.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }

        params = {
            "ipAddress": ioc_value,
            "maxAgeInDays": "90",
            "verbose": "",
        }

        try:
            data = await self._request_with_retry(
                "GET",
                f"{self.BASE_URL}/check",
                headers=headers,
                params=params,
            )

            if "error" in data:
                result.error = str(data.get("error", "Unknown error"))
                if isinstance(data["error"], dict):
                    result.error = data["error"].get("detail", str(data["error"]))
                return result

            report = data.get("data", {})

            abuse_score = report.get("abuseConfidenceScore", 0)
            total_reports = report.get("totalReports", 0)

            result.risk_score = float(abuse_score)
            result.malicious = abuse_score >= 50
            result.geo_data = {
                "country": report.get("countryCode", ""),
                "country_name": report.get("countryName", ""),
                "isp": report.get("isp", ""),
                "domain": report.get("domain", ""),
                "usage_type": report.get("usageType", ""),
            }
            result.tags = report.get("hostnames", [])

            result.summary = (
                f"AbuseIPDB: Abuse confidence {abuse_score}%, "
                f"{total_reports} reports. "
                f"ISP: {report.get('isp', 'N/A')}, "
                f"Usage: {report.get('usageType', 'N/A')}, "
                f"Country: {report.get('countryCode', 'N/A')}"
            )

            result.raw_response = {
                "abuse_confidence_score": abuse_score,
                "total_reports": total_reports,
                "isp": report.get("isp", ""),
                "usage_type": report.get("usageType", ""),
                "country_code": report.get("countryCode", ""),
                "domain": report.get("domain", ""),
                "is_tor": report.get("isTor", False),
                "is_whitelisted": report.get("isWhitelisted", False),
                "last_reported_at": report.get("lastReportedAt", ""),
                "num_distinct_users": report.get("numDistinctUsers", 0),
            }

        except Exception as e:
            result.error = f"AbuseIPDB API error: {str(e)}"

        return result
