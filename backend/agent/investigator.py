"""IOC enrichment and investigation module.

Orchestrates concurrent enrichment of IOCs against all available
threat intelligence sources.
"""

import asyncio
from typing import List, Dict, Optional
from parsers.ioc_extractor import IOC
from enrichment.base import EnrichmentResult
from enrichment.virustotal import VirusTotalEnrichment
from enrichment.abuseipdb import AbuseIPDBEnrichment
from enrichment.shodan_client import ShodanEnrichment
from enrichment.otx import OTXEnrichment
from enrichment.urlhaus import URLhausEnrichment
from enrichment.greynoise import GreyNoiseEnrichment
from enrichment.whois_lookup import WhoisEnrichment
from database.db import DatabaseManager


class Investigator:
    """Enriches IOCs against all available threat intelligence APIs."""

    def __init__(self, db: DatabaseManager):
        self.db = db
        self.sources = [
            VirusTotalEnrichment(),
            AbuseIPDBEnrichment(),
            ShodanEnrichment(),
            OTXEnrichment(),
            URLhausEnrichment(),
            GreyNoiseEnrichment(),
            WhoisEnrichment(),
        ]

    async def close(self) -> None:
        """Close all enrichment source sessions."""
        for source in self.sources:
            await source.close()

    async def enrich_ioc(
        self,
        ioc: IOC,
        progress_callback=None,
    ) -> Dict:
        """Enrich a single IOC against all applicable sources.

        Checks cache first, then queries APIs concurrently.

        Args:
            ioc: The IOC to enrich.
            progress_callback: Optional async callback for progress updates.

        Returns:
            Dict with IOC data and all enrichment results.
        """
        ioc_value = ioc.value
        ioc_type = ioc.ioc_type.value
        results: List[EnrichmentResult] = []

        applicable_sources = [s for s in self.sources if s.can_enrich(ioc_type)]

        async def enrich_with_source(source):
            """Enrich using a single source, checking cache first."""
            # Check cache
            cached = await self.db.get_cached_enrichment(ioc_value, ioc_type, source.SOURCE_NAME)
            if cached:
                result = EnrichmentResult(
                    source=source.SOURCE_NAME,
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    risk_score=cached.get("risk_score", 0),
                    malicious=cached.get("malicious", False),
                    raw_response=cached.get("raw_response", {}),
                    tags=cached.get("tags", []),
                    geo_data=cached.get("geo_data", {}),
                    summary=cached.get("summary", ""),
                    cached=True,
                )
                if progress_callback:
                    await progress_callback(source.SOURCE_NAME, ioc_value, result, True)
                return result

            try:
                result = await source.enrich(ioc_value, ioc_type)

                # Cache the result if successful
                if not result.error:
                    await self.db.save_enrichment_cache(
                        ioc_value, ioc_type, source.SOURCE_NAME, result.to_dict()
                    )

                if progress_callback:
                    await progress_callback(source.SOURCE_NAME, ioc_value, result, False)

                return result

            except Exception as e:
                error_result = EnrichmentResult(
                    source=source.SOURCE_NAME,
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    error=str(e),
                )
                if progress_callback:
                    await progress_callback(source.SOURCE_NAME, ioc_value, error_result, False)
                return error_result

        # Run all enrichments concurrently
        if applicable_sources:
            results = await asyncio.gather(
                *(enrich_with_source(s) for s in applicable_sources),
                return_exceptions=False,
            )

        # Calculate aggregate risk score
        valid_scores = [r.risk_score for r in results if not r.error and r.risk_score > 0]
        malicious_count = sum(1 for r in results if r.malicious)

        if valid_scores:
            avg_score = sum(valid_scores) / len(valid_scores)
            # Boost score if multiple sources flag as malicious
            if malicious_count >= 3:
                aggregate_risk = min(100, avg_score * 1.3)
            elif malicious_count >= 2:
                aggregate_risk = min(100, avg_score * 1.15)
            else:
                aggregate_risk = avg_score
        else:
            aggregate_risk = 0.0

        # Merge geo data from all sources
        merged_geo = {}
        for r in results:
            if r.geo_data:
                for k, v in r.geo_data.items():
                    if v and k not in merged_geo:
                        merged_geo[k] = v

        # Merge tags
        all_tags = set()
        for r in results:
            all_tags.update(r.tags)

        return {
            "value": ioc_value,
            "type": ioc_type,
            "original": ioc.original_value,
            "context": ioc.context,
            "risk_score": round(aggregate_risk, 1),
            "malicious_count": malicious_count,
            "sources_checked": len(applicable_sources),
            "sources_flagged": malicious_count,
            "geo_data": merged_geo,
            "tags": list(all_tags),
            "enrichment_results": [r.to_dict() for r in results],
            "enrichment_data": {r.source: r.to_dict() for r in results},
        }

    async def enrich_all(
        self,
        iocs: List[IOC],
        progress_callback=None,
    ) -> List[Dict]:
        """Enrich all IOCs, processing concurrently with rate limiting.

        Args:
            iocs: List of IOCs to enrich.
            progress_callback: Optional async callback for progress updates.

        Returns:
            List of enrichment result dicts.
        """
        # Deduplicate IOCs by value
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            if ioc.value not in seen:
                seen.add(ioc.value)
                unique_iocs.append(ioc)

        # Process IOCs with controlled concurrency
        semaphore = asyncio.Semaphore(3)  # Max 3 IOCs at a time

        async def bounded_enrich(ioc):
            async with semaphore:
                return await self.enrich_ioc(ioc, progress_callback)

        results = await asyncio.gather(
            *(bounded_enrich(ioc) for ioc in unique_iocs),
            return_exceptions=True,
        )

        # Filter out exceptions
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                valid_results.append({
                    "value": unique_iocs[i].value,
                    "type": unique_iocs[i].ioc_type.value,
                    "risk_score": 0,
                    "error": str(result),
                    "enrichment_results": [],
                    "enrichment_data": {},
                })
            else:
                valid_results.append(result)

        return valid_results
