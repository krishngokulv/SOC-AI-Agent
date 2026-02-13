"""Shodan API client for IP intelligence."""

from typing import List
from .base import BaseEnrichment, EnrichmentResult
from config import config


class ShodanEnrichment(BaseEnrichment):
    """Enriches IP addresses using Shodan.

    Provides open ports, services, vulnerabilities, and organization data.
    """

    SOURCE_NAME = "shodan"
    BASE_URL = "https://api.shodan.io"
    RATE_LIMIT_DELAY = 1.0

    def supported_types(self) -> List[str]:
        return ["ipv4"]

    async def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Query Shodan for IP intelligence.

        Args:
            ioc_value: IP address to look up.
            ioc_type: Should be ipv4.

        Returns:
            EnrichmentResult with port, service, and vulnerability data.
        """
        result = EnrichmentResult(
            source=self.SOURCE_NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
        )

        if not config.has_key("SHODAN_API_KEY"):
            result.error = "API key not configured"
            return result

        params = {"key": config.SHODAN_API_KEY}

        try:
            data = await self._request_with_retry(
                "GET",
                f"{self.BASE_URL}/shodan/host/{ioc_value}",
                params=params,
            )

            if "error" in data:
                error_msg = data.get("error", "Unknown error")
                if error_msg == "No information available for that IP.":
                    result.summary = "Shodan: No information available for this IP"
                    return result
                result.error = str(error_msg)
                return result

            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            org = data.get("org", "N/A")
            os_name = data.get("os", "N/A")
            country = data.get("country_code", "N/A")

            # Extract services
            services = []
            for service in data.get("data", []):
                services.append({
                    "port": service.get("port"),
                    "transport": service.get("transport", "tcp"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "banner": (service.get("data", "")[:200] if service.get("data") else ""),
                })

            # Risk scoring based on findings
            risk = 0
            if vulns:
                risk += min(50, len(vulns) * 10)
            if len(ports) > 10:
                risk += 15
            high_risk_ports = {21, 23, 445, 1433, 3306, 3389, 5900, 6379, 27017}
            exposed_risky = set(ports) & high_risk_ports
            if exposed_risky:
                risk += len(exposed_risky) * 10

            result.risk_score = min(100, risk)
            result.malicious = len(vulns) >= 3 or risk >= 60
            result.tags = vulns[:10]
            result.geo_data = {
                "country": country,
                "city": data.get("city", ""),
                "org": org,
                "isp": data.get("isp", ""),
            }

            result.summary = (
                f"Shodan: {len(ports)} open ports, {len(vulns)} vulns. "
                f"Org: {org}, OS: {os_name}, Country: {country}"
            )

            result.raw_response = {
                "ports": ports,
                "vulns": vulns[:20],
                "org": org,
                "os": os_name,
                "services": services[:10],
                "country_code": country,
                "city": data.get("city", ""),
                "hostnames": data.get("hostnames", []),
                "last_update": data.get("last_update", ""),
            }

        except Exception as e:
            result.error = f"Shodan API error: {str(e)}"

        return result
