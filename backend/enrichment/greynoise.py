"""GreyNoise Community API client for IP classification."""

from typing import List
from .base import BaseEnrichment, EnrichmentResult
from config import config


class GreyNoiseEnrichment(BaseEnrichment):
    """Enriches IP addresses using GreyNoise Community API.

    Classifies IPs as benign, malicious, or unknown based on
    internet-wide scan and attack data.
    """

    SOURCE_NAME = "greynoise"
    BASE_URL = "https://api.greynoise.io/v3/community"
    RATE_LIMIT_DELAY = 1.0

    def supported_types(self) -> List[str]:
        return ["ipv4"]

    async def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Query GreyNoise for IP classification.

        Args:
            ioc_value: IP address to classify.
            ioc_type: Should be ipv4.

        Returns:
            EnrichmentResult with classification and noise status.
        """
        result = EnrichmentResult(
            source=self.SOURCE_NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
        )

        if not config.has_key("GREYNOISE_API_KEY"):
            result.error = "API key not configured"
            return result

        headers = {
            "key": config.GREYNOISE_API_KEY,
            "Accept": "application/json",
        }

        try:
            data = await self._request_with_retry(
                "GET",
                f"{self.BASE_URL}/{ioc_value}",
                headers=headers,
            )

            if "error" in data or data.get("message") == "IP not observed":
                result.summary = "GreyNoise: IP not observed scanning the internet"
                result.raw_response = {"observed": False}
                return result

            classification = data.get("classification", "unknown")
            noise = data.get("noise", False)
            riot = data.get("riot", False)
            name = data.get("name", "")
            link = data.get("link", "")
            last_seen = data.get("last_seen", "")
            message = data.get("message", "")

            # Score based on classification
            if classification == "malicious":
                result.risk_score = 75.0
                result.malicious = True
            elif classification == "benign":
                result.risk_score = 5.0
                result.malicious = False
            else:
                result.risk_score = 30.0 if noise else 15.0
                result.malicious = False

            # RIOT = Rule It Out — known benign services
            if riot:
                result.risk_score = max(0, result.risk_score - 20)
                result.tags.append("riot_benign")

            result.tags.append(f"classification:{classification}")
            if noise:
                result.tags.append("internet_scanner")

            result.summary = (
                f"GreyNoise: Classification={classification}, "
                f"Noise={noise}, RIOT={riot}"
                f"{f', Name={name}' if name else ''}"
            )

            result.raw_response = {
                "classification": classification,
                "noise": noise,
                "riot": riot,
                "name": name,
                "link": link,
                "last_seen": last_seen,
                "message": message,
            }

        except Exception as e:
            result.error = f"GreyNoise API error: {str(e)}"

        return result
