"""Base enrichment class with retry logic and rate limiting."""

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Any
import aiohttp


@dataclass
class EnrichmentResult:
    """Standardized enrichment result from any source."""
    source: str
    ioc_value: str
    ioc_type: str
    risk_score: float = 0.0  # 0-100
    malicious: bool = False
    raw_response: dict = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    geo_data: dict = field(default_factory=dict)
    summary: str = ""
    error: Optional[str] = None
    cached: bool = False

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "source": self.source,
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "risk_score": self.risk_score,
            "malicious": self.malicious,
            "raw_response": self.raw_response,
            "tags": self.tags,
            "geo_data": self.geo_data,
            "summary": self.summary,
            "error": self.error,
            "cached": self.cached,
        }


class BaseEnrichment(ABC):
    """Abstract base class for all enrichment modules.

    Provides built-in retry logic (3 retries, exponential backoff)
    and rate limiting capabilities.
    """

    SOURCE_NAME: str = "unknown"
    MAX_RETRIES: int = 3
    BASE_DELAY: float = 1.0
    RATE_LIMIT_DELAY: float = 0.5  # Minimum delay between requests

    def __init__(self):
        self._last_request_time: float = 0
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.RATE_LIMIT_DELAY:
            await asyncio.sleep(self.RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.time()

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> dict:
        """Make an HTTP request with retry logic and exponential backoff.

        Args:
            method: HTTP method (GET, POST).
            url: Request URL.
            headers: Request headers.
            params: Query parameters.
            json_data: JSON body data.

        Returns:
            Parsed JSON response.

        Raises:
            Exception: If all retries are exhausted.
        """
        last_error = None
        session = await self._get_session()

        for attempt in range(self.MAX_RETRIES):
            await self._rate_limit()

            try:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_data,
                ) as response:
                    if response.status == 429:
                        # Rate limited — wait longer
                        retry_after = int(response.headers.get("Retry-After", 60))
                        await asyncio.sleep(min(retry_after, 120))
                        continue

                    if response.status >= 500:
                        raise aiohttp.ClientError(f"Server error: {response.status}")

                    if response.status == 404:
                        return {"error": "not_found", "status": 404}

                    if response.status == 403:
                        return {"error": "forbidden", "status": 403}

                    response.raise_for_status()

                    content_type = response.headers.get("Content-Type", "")
                    if "application/json" in content_type:
                        return await response.json()
                    else:
                        text = await response.text()
                        try:
                            import json
                            return json.loads(text)
                        except (json.JSONDecodeError, ValueError):
                            return {"raw_text": text}

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_error = e
                if attempt < self.MAX_RETRIES - 1:
                    delay = self.BASE_DELAY * (2 ** attempt)
                    await asyncio.sleep(delay)

        raise last_error or Exception("All retries exhausted")

    @abstractmethod
    async def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Enrich an IOC with threat intelligence.

        Args:
            ioc_value: The IOC value to look up.
            ioc_type: The type of IOC (ipv4, domain, url, md5, sha256, etc.).

        Returns:
            EnrichmentResult with findings.
        """
        pass

    @abstractmethod
    def supported_types(self) -> List[str]:
        """Return list of IOC types this enrichment source supports."""
        pass

    def can_enrich(self, ioc_type: str) -> bool:
        """Check if this source can enrich the given IOC type."""
        return ioc_type in self.supported_types()
