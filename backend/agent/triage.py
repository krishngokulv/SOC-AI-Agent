"""Alert classification and initial triage module.

Classifies alerts by type and assigns initial severity estimates
based on content analysis.
"""

import re
from typing import Tuple
from parsers.sysmon import AlertData


class TriageEngine:
    """Classifies alerts and assigns initial severity levels."""

    SEVERITY_LEVELS = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    # High severity indicators
    CRITICAL_INDICATORS = [
        re.compile(r"mimikatz|sekurlsa|logonpasswords|credential\s*dump", re.IGNORECASE),
        re.compile(r"ransomware|vssadmin.*delete.*shadows|bcdedit.*recoveryenabled.*no", re.IGNORECASE),
        re.compile(r"data\s*encrypted.*impact|mass.*file.*encrypt", re.IGNORECASE),
    ]

    HIGH_INDICATORS = [
        re.compile(r"cobalt\s*strike|meterpreter|empire|covenant", re.IGNORECASE),
        re.compile(r"-[Ee]ncoded[Cc]ommand|FromBase64String", re.IGNORECASE),
        re.compile(r"reverse\s*shell|bind\s*shell|web\s*shell", re.IGNORECASE),
        re.compile(r"psexec|lateral\s*movement|pass.the.hash", re.IGNORECASE),
        re.compile(r"exfiltrat|data\s*theft|c2.*beacon|command.*control", re.IGNORECASE),
        re.compile(r"process\s*inject|VirtualAllocEx|CreateRemoteThread", re.IGNORECASE),
        re.compile(r"lsass\.exe.*access|LSASS.*memory", re.IGNORECASE),
    ]

    MEDIUM_INDICATORS = [
        re.compile(r"brute\s*force|multiple.*failed.*login|4625", re.IGNORECASE),
        re.compile(r"phishing|suspicious.*email|malicious.*link", re.IGNORECASE),
        re.compile(r"dns\s*tunnel|unusual.*dns|dns.*exfil", re.IGNORECASE),
        re.compile(r"suspicious.*process|unusual.*activity|anomal", re.IGNORECASE),
        re.compile(r"scheduled\s*task|schtasks|registry.*run\s*key", re.IGNORECASE),
        re.compile(r"after.hours|off.hours|unusual.*time", re.IGNORECASE),
        re.compile(r"port\s*scan|network\s*scan|reconnaissance", re.IGNORECASE),
    ]

    LOW_INDICATORS = [
        re.compile(r"failed.*login|invalid.*password", re.IGNORECASE),
        re.compile(r"blocked.*firewall|denied.*connection", re.IGNORECASE),
        re.compile(r"warning|notice|informational", re.IGNORECASE),
    ]

    # Benign indicators that lower severity
    BENIGN_INDICATORS = [
        re.compile(r"windows\s*update|wuauclt|UsoClient|TrustedInstaller", re.IGNORECASE),
        re.compile(r"Microsoft\s*Defender|MsMpEng|MpSigStub", re.IGNORECASE),
        re.compile(r"svchost\.exe.*-k.*netsvcs|Windows\\System32\\svchost", re.IGNORECASE),
        re.compile(r"chrome.*update|firefox.*update|software.*update", re.IGNORECASE),
        re.compile(r"SYSTEM.*logon.*type.*5|service\s*logon", re.IGNORECASE),
    ]

    @classmethod
    def classify(cls, alert: AlertData) -> Tuple[str, str, str]:
        """Classify an alert and determine initial severity.

        Args:
            alert: Normalized AlertData object.

        Returns:
            Tuple of (severity, classification, description).
        """
        text = cls._get_searchable_text(alert)

        # Check benign indicators first
        benign_score = sum(1 for pattern in cls.BENIGN_INDICATORS if pattern.search(text))

        # Check severity indicators
        critical_hits = sum(1 for pattern in cls.CRITICAL_INDICATORS if pattern.search(text))
        high_hits = sum(1 for pattern in cls.HIGH_INDICATORS if pattern.search(text))
        medium_hits = sum(1 for pattern in cls.MEDIUM_INDICATORS if pattern.search(text))
        low_hits = sum(1 for pattern in cls.LOW_INDICATORS if pattern.search(text))

        # Determine severity
        if critical_hits > 0 and benign_score == 0:
            severity = "CRITICAL"
        elif high_hits > 0 and benign_score == 0:
            severity = "HIGH"
        elif medium_hits > 0:
            severity = "MEDIUM" if benign_score == 0 else "LOW"
        elif low_hits > 0 or benign_score > 0:
            severity = "LOW"
        else:
            severity = "MEDIUM"  # Unknown alerts get medium by default

        # Classify alert type more specifically
        classification = cls._classify_type(alert, text)

        # Generate description
        description = cls._generate_description(alert, severity, classification, text)

        return severity, classification, description

    @classmethod
    def _get_searchable_text(cls, alert: AlertData) -> str:
        """Build searchable text from all alert fields."""
        parts = [
            alert.raw_content or "",
            alert.process_name or "",
            alert.command_line or "",
            alert.parent_process or "",
            alert.email_subject or "",
        ]
        if alert.raw_fields:
            parts.extend(str(v) for v in alert.raw_fields.values())
        return " ".join(parts)

    @classmethod
    def _classify_type(cls, alert: AlertData, text: str) -> str:
        """Determine specific attack classification."""
        classifications = {
            "credential_theft": [r"mimikatz|credential.*dump|lsass|sekurlsa|logonpasswords"],
            "ransomware": [r"ransomware|vssadmin.*delete|encrypt.*files|ransom\s*note"],
            "brute_force": [r"brute.*force|multiple.*failed.*login|password.*spray"],
            "phishing": [r"phishing|suspicious.*email|malicious.*(link|attachment)"],
            "c2_communication": [r"c2|beacon|command.*control|callback.*http"],
            "lateral_movement": [r"lateral.*movement|psexec|pass.*hash|remote.*exec"],
            "data_exfiltration": [r"exfiltrat|data.*theft|large.*outbound|bulk.*transfer"],
            "dns_tunneling": [r"dns.*tunnel|unusual.*dns|dns.*exfil"],
            "privilege_escalation": [r"privilege.*escalat|uac.*bypass|admin.*access"],
            "malware_execution": [r"malware|trojan|backdoor|encoded.*command"],
            "insider_threat": [r"insider|after.*hours|unusual.*time|off.*hours"],
            "reconnaissance": [r"recon|scan|discovery|enumerat"],
        }

        for classification, patterns in classifications.items():
            for pattern_str in patterns:
                if re.search(pattern_str, text, re.IGNORECASE):
                    return classification

        return f"{alert.alert_type}_alert"

    @classmethod
    def _generate_description(cls, alert: AlertData, severity: str, classification: str, text: str) -> str:
        """Generate a human-readable triage description."""
        parts = [f"Alert classified as {classification.replace('_', ' ').title()}."]
        parts.append(f"Initial severity assessment: {severity}.")

        if alert.source_ip:
            parts.append(f"Source IP: {alert.source_ip}.")
        if alert.user:
            parts.append(f"User: {alert.user}.")
        if alert.process_name:
            parts.append(f"Process: {alert.process_name}.")
        if alert.command_line:
            cmd_preview = alert.command_line[:100]
            parts.append(f"Command: {cmd_preview}...")
        if alert.extracted_iocs:
            parts.append(f"Extracted {len(alert.extracted_iocs)} IOCs for enrichment.")

        return " ".join(parts)
