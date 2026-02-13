"""MITRE ATT&CK mapping engine wrapper.

Wraps the technique_mapper module for use in the orchestrator pipeline.
"""

from typing import List, Dict
from parsers.sysmon import AlertData
from mitre.technique_mapper import TechniqueMapper


class AttackMapper:
    """Maps alert data to MITRE ATT&CK techniques."""

    @classmethod
    def map(cls, alert: AlertData, enrichment_data: List[Dict] = None) -> Dict:
        """Map alert to MITRE ATT&CK techniques.

        Args:
            alert: Normalized AlertData object.
            enrichment_data: Optional enrichment results that may provide
                additional behavioral context.

        Returns:
            Dict with matched techniques, narrative, and tactic coverage.
        """
        # Map from alert data
        techniques = TechniqueMapper.map_techniques(alert)

        # Additional mapping from enrichment tags if available
        if enrichment_data:
            for ioc_data in enrichment_data:
                tags = ioc_data.get("tags", [])
                for tag in tags:
                    extra = cls._map_from_tag(tag)
                    for tech in extra:
                        if not any(t["technique_id"] == tech["technique_id"] for t in techniques):
                            techniques.append(tech)

        # Generate narrative
        narrative = TechniqueMapper.get_attack_narrative(techniques)

        # Compute tactic coverage
        tactics_covered = set(t["tactic"] for t in techniques)
        all_tactics = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact",
        ]
        tactic_coverage = {
            tactic: tactic in tactics_covered for tactic in all_tactics
        }

        return {
            "techniques": techniques,
            "technique_count": len(techniques),
            "narrative": narrative,
            "tactic_coverage": tactic_coverage,
            "tactics_covered": list(tactics_covered),
        }

    @classmethod
    def _map_from_tag(cls, tag: str) -> List[Dict]:
        """Attempt to map enrichment tags to techniques."""
        tag_lower = tag.lower()
        from mitre.attack_data import ATTACK_TECHNIQUES

        tag_mappings = {
            "malware": ["T1204.002"],
            "ransomware": ["T1486", "T1490"],
            "phishing": ["T1566"],
            "botnet": ["T1071.001"],
            "c2": ["T1071.001"],
            "scanner": ["T1595"],
            "tor": ["T1090"],
            "proxy": ["T1090"],
            "miner": ["T1496"],
            "exploit": ["T1203"],
        }

        results = []
        for keyword, tech_ids in tag_mappings.items():
            if keyword in tag_lower:
                for tid in tech_ids:
                    tech_info = ATTACK_TECHNIQUES.get(tid, {})
                    if tech_info:
                        results.append({
                            "technique_id": tid,
                            "name": tech_info.get("name", "Unknown"),
                            "tactic": tech_info.get("tactic", "Unknown"),
                            "description": tech_info.get("description", ""),
                            "evidence": f"Enrichment tag: {tag}",
                            "rule_name": f"Tag mapping: {keyword}",
                        })

        return results
