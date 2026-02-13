"""Severity verdict and confidence scoring engine.

Uses a weighted scoring system combining enrichment results,
historical correlation, behavioral indicators, and temporal analysis
to produce a final verdict with reasoning.
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from parsers.sysmon import AlertData


class VerdictEngine:
    """Produces investigation verdicts with confidence scoring and reasoning."""

    # Verdict types
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_ESCALATION = "NEEDS_ESCALATION"

    # Scoring weights
    WEIGHT_ENRICHMENT = 0.35
    WEIGHT_BEHAVIORAL = 0.25
    WEIGHT_CORRELATION = 0.20
    WEIGHT_MITRE = 0.15
    WEIGHT_TEMPORAL = 0.05

    # Known malicious process names (for behavioral scoring)
    MALICIOUS_PROCESSES = [
        re.compile(r"mimikatz|mimi\.exe", re.IGNORECASE),
        re.compile(r"lazagne|LaZagne", re.IGNORECASE),
        re.compile(r"procdump.*lsass|lsass.*dump", re.IGNORECASE),
        re.compile(r"cobalt.*strike|beacon\.exe", re.IGNORECASE),
        re.compile(r"psexec|PsExe[cs]", re.IGNORECASE),
        re.compile(r"nc\.exe|ncat|netcat", re.IGNORECASE),
        re.compile(r"chisel|plink\.exe", re.IGNORECASE),
    ]

    # Suspicious command patterns
    SUSPICIOUS_COMMANDS = [
        (re.compile(r"-[Ee]ncoded[Cc]ommand|FromBase64String", re.IGNORECASE), 30),
        (re.compile(r"Invoke-Mimikatz|Invoke-Kerberoast|Invoke-Expression", re.IGNORECASE), 35),
        (re.compile(r"certutil.*-urlcache.*-split|bitsadmin.*transfer", re.IGNORECASE), 25),
        (re.compile(r"vssadmin.*delete|bcdedit.*recoveryenabled", re.IGNORECASE), 40),
        (re.compile(r"net\s+user.*\/add|net\s+localgroup.*admin", re.IGNORECASE), 20),
        (re.compile(r"reg\s+save\s+HKLM\\SAM|reg\s+save\s+HKLM\\SYSTEM", re.IGNORECASE), 35),
        (re.compile(r"lsass\.exe|sekurlsa|logonpasswords", re.IGNORECASE), 35),
        (re.compile(r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread", re.IGNORECASE), 30),
        (re.compile(r"Invoke-WebRequest.*http|DownloadString.*http|DownloadFile.*http", re.IGNORECASE), 20),
        (re.compile(r"schtasks\s+/create.*cmd|schtasks.*powershell", re.IGNORECASE), 20),
        (re.compile(r"whoami|systeminfo|ipconfig|net\s+view", re.IGNORECASE), 10),
    ]

    # Known C2 ports
    C2_PORTS = {4444, 5555, 8080, 8443, 1337, 31337, 9999, 6666, 7777, 3333}

    # Benign process patterns
    BENIGN_PATTERNS = [
        re.compile(r"Windows\\System32\\svchost\.exe\s+-k\s+", re.IGNORECASE),
        re.compile(r"wuauclt|UsoClient|TrustedInstaller|MsMpEng", re.IGNORECASE),
        re.compile(r"Chrome\\Application\\chrome\.exe|firefox\.exe.*contentproc", re.IGNORECASE),
        re.compile(r"Microsoft\\Edge\\Application|Teams\.exe", re.IGNORECASE),
        re.compile(r"WindowsApps\\.*\.exe|Program Files.*update", re.IGNORECASE),
    ]

    @classmethod
    def evaluate(
        cls,
        alert: AlertData,
        enrichment_results: List[Dict],
        correlation_data: Dict,
        mitre_data: Dict,
        triage_severity: str,
    ) -> Dict:
        """Evaluate all investigation data and produce a final verdict.

        Args:
            alert: The original parsed alert.
            enrichment_results: IOC enrichment results from all sources.
            correlation_data: Historical correlation findings.
            mitre_data: MITRE ATT&CK mapping results.
            triage_severity: Initial severity from triage.

        Returns:
            Dict with verdict, confidence, reasoning chain, and scores.
        """
        reasoning = []

        # 1. Enrichment Score (0-100)
        enrichment_score, enrichment_reasons = cls._score_enrichment(enrichment_results)
        reasoning.extend(enrichment_reasons)

        # 2. Behavioral Score (0-100)
        behavioral_score, behavioral_reasons = cls._score_behavioral(alert)
        reasoning.extend(behavioral_reasons)

        # 3. Correlation Score (0-100)
        correlation_score, correlation_reasons = cls._score_correlation(correlation_data)
        reasoning.extend(correlation_reasons)

        # 4. MITRE Score (0-100)
        mitre_score, mitre_reasons = cls._score_mitre(mitre_data)
        reasoning.extend(mitre_reasons)

        # 5. Temporal Score (0-100)
        temporal_score, temporal_reasons = cls._score_temporal(alert)
        reasoning.extend(temporal_reasons)

        # Compute weighted total
        total_score = (
            enrichment_score * cls.WEIGHT_ENRICHMENT +
            behavioral_score * cls.WEIGHT_BEHAVIORAL +
            correlation_score * cls.WEIGHT_CORRELATION +
            mitre_score * cls.WEIGHT_MITRE +
            temporal_score * cls.WEIGHT_TEMPORAL
        )

        # Check for benign overrides
        benign_score, benign_reasons = cls._check_benign(alert)
        if benign_score > 50:
            total_score = max(0, total_score - benign_score)
            reasoning.extend(benign_reasons)

        # Determine verdict
        verdict, confidence = cls._determine_verdict(total_score, enrichment_results, correlation_data)

        # Adjust confidence based on data availability
        sources_with_data = sum(1 for r in enrichment_results if r.get("enrichment_results"))
        if sources_with_data == 0:
            confidence = max(30, confidence - 20)
            reasoning.append("Limited enrichment data available. Confidence reduced.")

        # Generate recommended actions
        actions = cls._recommend_actions(verdict, alert, enrichment_results, mitre_data)

        return {
            "verdict": verdict,
            "confidence": round(confidence, 1),
            "total_score": round(total_score, 1),
            "reasoning": reasoning,
            "reasoning_summary": cls._summarize_reasoning(verdict, confidence, reasoning),
            "score_breakdown": {
                "enrichment": {"score": round(enrichment_score, 1), "weight": cls.WEIGHT_ENRICHMENT},
                "behavioral": {"score": round(behavioral_score, 1), "weight": cls.WEIGHT_BEHAVIORAL},
                "correlation": {"score": round(correlation_score, 1), "weight": cls.WEIGHT_CORRELATION},
                "mitre": {"score": round(mitre_score, 1), "weight": cls.WEIGHT_MITRE},
                "temporal": {"score": round(temporal_score, 1), "weight": cls.WEIGHT_TEMPORAL},
            },
            "recommended_actions": actions,
        }

    @classmethod
    def _score_enrichment(cls, enrichment_results: List[Dict]) -> Tuple[float, List[str]]:
        """Score based on IOC enrichment data."""
        if not enrichment_results:
            return 0.0, ["No IOCs found for enrichment."]

        reasons = []
        max_risk = 0.0
        total_malicious_sources = 0
        total_iocs_flagged = 0

        for ioc in enrichment_results:
            risk = ioc.get("risk_score", 0)
            malicious_count = ioc.get("malicious_count", 0)
            max_risk = max(max_risk, risk)

            if malicious_count >= 3:
                total_iocs_flagged += 1
                reasons.append(
                    f"IOC {ioc['value']} flagged as malicious by {malicious_count} sources "
                    f"(risk score: {risk}). Strong indicator of compromise."
                )
            elif malicious_count >= 1:
                total_iocs_flagged += 1
                reasons.append(
                    f"IOC {ioc['value']} flagged by {malicious_count} source(s) "
                    f"(risk score: {risk})."
                )
            elif risk > 30:
                reasons.append(f"IOC {ioc['value']} has elevated risk score: {risk}.")

            total_malicious_sources += malicious_count

        if total_malicious_sources >= 5:
            score = min(100, max_risk + 20)
        elif total_malicious_sources >= 3:
            score = min(100, max_risk + 10)
        else:
            score = max_risk

        if not reasons:
            reasons.append("No IOCs flagged as malicious by enrichment sources.")

        return score, reasons

    @classmethod
    def _score_behavioral(cls, alert: AlertData) -> Tuple[float, List[str]]:
        """Score based on behavioral indicators in the alert."""
        score = 0.0
        reasons = []

        text = f"{alert.process_name or ''} {alert.command_line or ''} {alert.raw_content or ''}"

        # Check malicious processes
        for pattern in cls.MALICIOUS_PROCESSES:
            if pattern.search(text):
                score += 40
                reasons.append(f"Known malicious tool detected: {pattern.pattern[:50]}")
                break

        # Check suspicious commands
        for pattern, points in cls.SUSPICIOUS_COMMANDS:
            if pattern.search(text):
                score += points
                reasons.append(f"Suspicious command pattern: {pattern.pattern[:60]}")

        # Check parent-child process relationships
        parent = alert.parent_process or ""
        child = alert.process_name or ""
        suspicious_pairs = [
            ("winword.exe", "cmd.exe"), ("winword.exe", "powershell.exe"),
            ("excel.exe", "cmd.exe"), ("excel.exe", "powershell.exe"),
            ("outlook.exe", "cmd.exe"), ("outlook.exe", "powershell.exe"),
            ("explorer.exe", "cmd.exe"), ("svchost.exe", "cmd.exe"),
            ("w3wp.exe", "cmd.exe"), ("w3wp.exe", "powershell.exe"),
        ]
        for parent_pattern, child_pattern in suspicious_pairs:
            if parent_pattern.lower() in parent.lower() and child_pattern.lower() in child.lower():
                score += 20
                reasons.append(f"Suspicious parent-child process: {parent_pattern} -> {child_pattern}")
                break

        # Check for C2 ports in raw data
        if alert.raw_fields:
            for key, value in alert.raw_fields.items():
                if "port" in key.lower():
                    try:
                        port = int(value)
                        if port in cls.C2_PORTS:
                            score += 15
                            reasons.append(f"Known C2 port detected: {port}")
                    except (ValueError, TypeError):
                        pass

        score = min(100, score)
        if not reasons:
            reasons.append("No significant behavioral indicators detected.")

        return score, reasons

    @classmethod
    def _score_correlation(cls, correlation_data: Dict) -> Tuple[float, List[str]]:
        """Score based on historical correlation data."""
        reasons = []
        score = 0.0

        related_count = correlation_data.get("related_count", 0)
        verdicts = correlation_data.get("historical_verdicts", {})

        tp_count = verdicts.get("TRUE_POSITIVE", 0)
        fp_count = verdicts.get("FALSE_POSITIVE", 0)

        if tp_count > 0:
            score += min(50, tp_count * 20)
            reasons.append(
                f"IOCs appeared in {tp_count} previously confirmed true positive(s). "
                "Strong correlation with known malicious activity."
            )

        if related_count > 3:
            score += 15
            reasons.append(f"IOCs correlated across {related_count} previous investigations.")
        elif related_count > 0:
            score += 5
            reasons.append(f"IOCs found in {related_count} previous investigation(s).")

        if fp_count > 0 and tp_count == 0:
            score = max(0, score - 10)
            reasons.append(
                f"IOCs appeared in {fp_count} false positive(s). "
                "May reduce malicious confidence."
            )

        score = min(100, score)
        if not reasons:
            reasons.append("No historical correlation data available.")

        return score, reasons

    @classmethod
    def _score_mitre(cls, mitre_data: Dict) -> Tuple[float, List[str]]:
        """Score based on MITRE ATT&CK technique mapping."""
        reasons = []
        techniques = mitre_data.get("techniques", [])
        tactics_covered = mitre_data.get("tactics_covered", [])

        if not techniques:
            return 0.0, ["No MITRE ATT&CK techniques identified."]

        # Base score from technique count
        score = min(50, len(techniques) * 8)

        # Bonus for covering multiple tactics (indicates sophisticated attack)
        if len(tactics_covered) >= 4:
            score += 25
            reasons.append(
                f"Attack chain spans {len(tactics_covered)} MITRE ATT&CK tactics, "
                "indicating a sophisticated multi-stage attack."
            )
        elif len(tactics_covered) >= 2:
            score += 10

        # High-impact tactics
        high_impact = {"Impact", "Credential Access", "Exfiltration", "Lateral Movement"}
        impact_overlap = high_impact.intersection(set(tactics_covered))
        if impact_overlap:
            score += len(impact_overlap) * 10
            reasons.append(f"High-impact tactics detected: {', '.join(impact_overlap)}")

        reasons.append(
            f"Matched {len(techniques)} MITRE ATT&CK technique(s) across "
            f"{len(tactics_covered)} tactic(s)."
        )

        return min(100, score), reasons

    @classmethod
    def _score_temporal(cls, alert: AlertData) -> Tuple[float, List[str]]:
        """Score based on temporal factors (time of day, etc.)."""
        reasons = []
        score = 0.0

        if alert.timestamp:
            hour = alert.timestamp.hour
            # Off-hours: 10 PM to 6 AM
            if hour >= 22 or hour < 6:
                score += 20
                reasons.append(f"Alert occurred during off-hours ({hour:02d}:00). Slightly elevated risk.")
            # Weekend check
            if alert.timestamp.weekday() >= 5:
                score += 10
                reasons.append("Alert occurred on a weekend.")

        if not reasons:
            reasons.append("No temporal risk factors identified.")

        return min(100, score), reasons

    @classmethod
    def _check_benign(cls, alert: AlertData) -> Tuple[float, List[str]]:
        """Check for benign indicators that should lower the score."""
        score = 0.0
        reasons = []
        text = f"{alert.process_name or ''} {alert.command_line or ''} {alert.raw_content or ''}"

        for pattern in cls.BENIGN_PATTERNS:
            if pattern.search(text):
                score += 30
                reasons.append(f"Benign indicator detected: {pattern.pattern[:50]}. Score reduced.")

        return score, reasons

    @classmethod
    def _determine_verdict(
        cls,
        total_score: float,
        enrichment_results: List[Dict],
        correlation_data: Dict,
    ) -> Tuple[str, float]:
        """Determine final verdict and confidence from total score."""
        tp_history = correlation_data.get("historical_verdicts", {}).get("TRUE_POSITIVE", 0)

        if total_score >= 60 or (total_score >= 45 and tp_history > 0):
            verdict = cls.TRUE_POSITIVE
            confidence = min(99, 50 + total_score * 0.5)
        elif total_score <= 20:
            verdict = cls.FALSE_POSITIVE
            confidence = min(99, 50 + (100 - total_score) * 0.4)
        else:
            verdict = cls.NEEDS_ESCALATION
            confidence = min(99, 30 + abs(50 - total_score))

        return verdict, confidence

    @classmethod
    def _recommend_actions(
        cls,
        verdict: str,
        alert: AlertData,
        enrichment_results: List[Dict],
        mitre_data: Dict,
    ) -> List[str]:
        """Generate recommended response actions based on findings."""
        actions = []

        if verdict == cls.TRUE_POSITIVE:
            actions.append("Immediately isolate the affected host from the network.")

            if alert.source_ip:
                actions.append(f"Block source IP {alert.source_ip} at the firewall.")
            if alert.user:
                actions.append(f"Reset credentials for user '{alert.user}'.")
                actions.append(f"Review all recent activity for user '{alert.user}'.")

            # Malicious IOCs
            for ioc in enrichment_results:
                if ioc.get("malicious_count", 0) >= 2:
                    if ioc.get("type") in ("ipv4", "ipv6"):
                        actions.append(f"Block IP {ioc['value']} at perimeter firewall.")
                    elif ioc.get("type") == "domain":
                        actions.append(f"Block domain {ioc['value']} in DNS sinkhole.")
                    elif ioc.get("type") in ("md5", "sha256"):
                        actions.append(f"Search environment for file hash {ioc['value'][:16]}...")

            tactics = mitre_data.get("tactics_covered", [])
            if "Credential Access" in tactics:
                actions.append("Initiate organization-wide password reset for affected accounts.")
            if "Lateral Movement" in tactics:
                actions.append("Scan adjacent hosts for indicators of compromise.")
            if "Exfiltration" in tactics:
                actions.append("Review data loss prevention logs for data theft evidence.")
            if "Impact" in tactics:
                actions.append("Verify backup integrity and prepare recovery procedures.")

            actions.append("Collect forensic evidence and preserve volatile data.")
            actions.append("File incident report and notify security leadership.")

        elif verdict == cls.NEEDS_ESCALATION:
            actions.append("Escalate to senior analyst for manual review.")
            actions.append("Gather additional context from the host and user.")
            if alert.source_ip:
                actions.append(f"Monitor traffic to/from {alert.source_ip} for additional indicators.")
            actions.append("Do not take destructive action until further analysis is complete.")

        else:  # FALSE_POSITIVE
            actions.append("No immediate action required.")
            actions.append("Consider adding to allowlist/exception list if recurring.")
            actions.append("Document the false positive for tuning detection rules.")

        return actions

    @classmethod
    def _summarize_reasoning(cls, verdict: str, confidence: float, reasons: List[str]) -> str:
        """Generate a concise reasoning summary."""
        verdict_text = {
            cls.TRUE_POSITIVE: "confirmed malicious activity",
            cls.FALSE_POSITIVE: "benign activity (false positive)",
            cls.NEEDS_ESCALATION: "suspicious activity requiring human review",
        }.get(verdict, "unknown")

        key_reasons = [r for r in reasons if any(
            word in r.lower() for word in [
                "malicious", "flagged", "confirmed", "suspicious", "known",
                "attack chain", "benign", "true positive", "impact",
            ]
        )][:3]

        summary = f"Verdict: {verdict} ({confidence}% confidence) — {verdict_text}. "
        if key_reasons:
            summary += "Key factors: " + " ".join(key_reasons)

        return summary
