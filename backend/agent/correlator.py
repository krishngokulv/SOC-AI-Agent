"""Cross-alert correlation and attack chain detection.

Queries historical investigation data to find related alerts and
build attack chain narratives.
"""

from typing import List, Dict, Optional
from database.db import DatabaseManager


class Correlator:
    """Correlates current investigation with historical data."""

    def __init__(self, db: DatabaseManager):
        self.db = db

    async def correlate(
        self,
        alert_id: str,
        ioc_values: List[str],
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        user: Optional[str] = None,
    ) -> Dict:
        """Find related investigations and build correlation data.

        Args:
            alert_id: Current alert ID to exclude from results.
            ioc_values: List of IOC values to search for.
            source_ip: Source IP to search for.
            dest_ip: Destination IP to search for.
            user: Username to search for.

        Returns:
            Dict with correlation findings.
        """
        related_investigations = await self.db.find_related_investigations(ioc_values)

        # Filter out current investigation
        related_investigations = [
            inv for inv in related_investigations
            if inv.get("alert_id") != alert_id
        ]

        # Analyze findings
        shared_iocs = self._find_shared_iocs(related_investigations)
        attack_chain = self._build_attack_chain(related_investigations)
        historical_verdicts = self._analyze_verdicts(related_investigations)

        return {
            "related_count": len(related_investigations),
            "related_investigations": related_investigations[:20],
            "shared_iocs": shared_iocs,
            "attack_chain": attack_chain,
            "historical_verdicts": historical_verdicts,
            "correlation_summary": self._generate_summary(
                related_investigations, shared_iocs, historical_verdicts
            ),
        }

    def _find_shared_iocs(self, related: List[Dict]) -> List[Dict]:
        """Identify IOCs that appear across multiple investigations."""
        ioc_counts: Dict[str, int] = {}
        ioc_investigations: Dict[str, List[str]] = {}

        for inv in related:
            ioc_val = inv.get("matching_ioc", "")
            if ioc_val:
                ioc_counts[ioc_val] = ioc_counts.get(ioc_val, 0) + 1
                if ioc_val not in ioc_investigations:
                    ioc_investigations[ioc_val] = []
                ioc_investigations[ioc_val].append(inv.get("alert_id", ""))

        shared = [
            {
                "value": ioc,
                "times_seen": count,
                "investigations": ioc_investigations.get(ioc, []),
            }
            for ioc, count in sorted(ioc_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        return shared

    def _build_attack_chain(self, related: List[Dict]) -> List[Dict]:
        """Attempt to build an attack chain from related investigations."""
        if not related:
            return []

        # Sort by timestamp
        sorted_inv = sorted(
            [inv for inv in related if inv.get("timestamp")],
            key=lambda x: x["timestamp"],
        )

        chain = []
        for inv in sorted_inv:
            chain.append({
                "alert_id": inv.get("alert_id"),
                "alert_type": inv.get("alert_type"),
                "verdict": inv.get("verdict"),
                "timestamp": inv.get("timestamp"),
                "matching_ioc": inv.get("matching_ioc"),
            })

        return chain

    def _analyze_verdicts(self, related: List[Dict]) -> Dict:
        """Analyze verdict distribution of related investigations."""
        verdicts = {
            "TRUE_POSITIVE": 0,
            "FALSE_POSITIVE": 0,
            "NEEDS_ESCALATION": 0,
            "pending": 0,
        }

        for inv in related:
            verdict = inv.get("verdict")
            if verdict in verdicts:
                verdicts[verdict] += 1
            else:
                verdicts["pending"] += 1

        return verdicts

    def _generate_summary(
        self,
        related: List[Dict],
        shared_iocs: List[Dict],
        historical_verdicts: Dict,
    ) -> str:
        """Generate a human-readable correlation summary."""
        if not related:
            return "No related investigations found. This appears to be a new, isolated alert."

        parts = [f"Found {len(related)} related investigation(s)."]

        if shared_iocs:
            top_iocs = shared_iocs[:3]
            ioc_str = ", ".join(f"{i['value']} (seen {i['times_seen']}x)" for i in top_iocs)
            parts.append(f"Shared IOCs: {ioc_str}.")

        tp_count = historical_verdicts.get("TRUE_POSITIVE", 0)
        if tp_count > 0:
            parts.append(
                f"{tp_count} related investigation(s) were previously confirmed as true positives. "
                "This significantly increases the likelihood of this alert being malicious."
            )

        fp_count = historical_verdicts.get("FALSE_POSITIVE", 0)
        if fp_count > 0 and tp_count == 0:
            parts.append(
                f"{fp_count} related investigation(s) were previously classified as false positives."
            )

        return " ".join(parts)
