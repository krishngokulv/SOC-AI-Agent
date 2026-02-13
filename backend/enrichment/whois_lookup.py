"""WHOIS lookup module for domain registration data."""

import asyncio
from typing import List
from .base import BaseEnrichment, EnrichmentResult


class WhoisEnrichment(BaseEnrichment):
    """Enriches domains with WHOIS registration data.

    Uses python-whois library. No API key required.
    """

    SOURCE_NAME = "whois"
    RATE_LIMIT_DELAY = 2.0

    def supported_types(self) -> List[str]:
        return ["domain"]

    async def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Perform WHOIS lookup for a domain.

        Args:
            ioc_value: Domain name to look up.
            ioc_type: Should be domain.

        Returns:
            EnrichmentResult with registration data.
        """
        result = EnrichmentResult(
            source=self.SOURCE_NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
        )

        try:
            # Run in thread pool since python-whois is synchronous
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, self._do_whois_lookup, ioc_value)

            if whois_data is None:
                result.error = "WHOIS lookup returned no data"
                return result

            registrar = whois_data.get("registrar", "N/A")
            creation_date = whois_data.get("creation_date")
            expiration_date = whois_data.get("expiration_date")
            name_servers = whois_data.get("name_servers", [])
            registrant_country = whois_data.get("registrant_country", "N/A")
            dnssec = whois_data.get("dnssec", "N/A")

            # Normalize dates
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(name_servers, set):
                name_servers = list(name_servers)

            # Risk indicators from WHOIS
            risk = 0
            tags = []

            # Recently registered domains are suspicious
            if creation_date:
                from datetime import datetime
                try:
                    if hasattr(creation_date, "timestamp"):
                        age_days = (datetime.utcnow() - creation_date).days
                    else:
                        age_days = 365  # Default if we can't parse
                    if age_days < 30:
                        risk += 30
                        tags.append("newly_registered")
                    elif age_days < 90:
                        risk += 15
                        tags.append("recently_registered")
                except (TypeError, ValueError):
                    pass

            # Privacy-protected registrations
            registrar_str = str(registrar).lower()
            if any(word in registrar_str for word in ["privacy", "proxy", "protected", "whoisguard"]):
                risk += 10
                tags.append("privacy_protected")

            result.risk_score = min(100, risk)
            result.malicious = False  # WHOIS alone can't determine malicious intent
            result.tags = tags
            result.geo_data = {"country": str(registrant_country)}

            creation_str = str(creation_date) if creation_date else "N/A"
            expiry_str = str(expiration_date) if expiration_date else "N/A"

            result.summary = (
                f"WHOIS: Registrar={registrar}, "
                f"Created={creation_str}, "
                f"Expires={expiry_str}, "
                f"Country={registrant_country}"
            )

            result.raw_response = {
                "registrar": str(registrar),
                "creation_date": str(creation_date) if creation_date else None,
                "expiration_date": str(expiration_date) if expiration_date else None,
                "name_servers": [str(ns) for ns in (name_servers or [])][:10],
                "registrant_country": str(registrant_country),
                "dnssec": str(dnssec),
                "domain_name": whois_data.get("domain_name", ""),
                "status": whois_data.get("status", ""),
            }

        except Exception as e:
            result.error = f"WHOIS lookup error: {str(e)}"

        return result

    @staticmethod
    def _do_whois_lookup(domain: str) -> dict:
        """Perform synchronous WHOIS lookup."""
        try:
            import whois
            w = whois.whois(domain)
            if w and w.domain_name:
                return dict(w)
            return {}
        except Exception:
            return {}
