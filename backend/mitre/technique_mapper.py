"""Maps behavioral indicators to MITRE ATT&CK techniques.

Uses pattern matching on process names, command lines, network patterns,
and file operations to identify likely ATT&CK techniques.
"""

import re
from typing import List, Dict, Optional
from .attack_data import ATTACK_TECHNIQUES


class TechniqueMapper:
    """Maps observed behaviors and indicators to MITRE ATT&CK techniques."""

    # Mapping rules: list of (pattern_description, check_function, technique_ids)
    # Each rule is a tuple of: (name, regex/keyword patterns, technique IDs, applies_to_fields)

    BEHAVIORAL_RULES = [
        # Execution - PowerShell
        {
            "name": "PowerShell execution",
            "patterns": [
                re.compile(r"powershell\.exe|pwsh\.exe|powershell_ise\.exe", re.IGNORECASE),
            ],
            "fields": ["process_name", "command_line", "raw_content"],
            "techniques": ["T1059.001"],
        },
        {
            "name": "Encoded PowerShell command",
            "patterns": [
                re.compile(r"-[Ee]ncoded[Cc]ommand\s+|(?:-[Ee]nc\s+|-[Ee][Cc]\s+)[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
                re.compile(r"FromBase64String|Convert.*Base64|Invoke-Expression|IEX\s*\(", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1059.001", "T1027.010"],
        },
        # Execution - cmd.exe
        {
            "name": "Windows Command Shell",
            "patterns": [
                re.compile(r"cmd\.exe\s+/[ckCK]", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1059.003"],
        },
        # Execution - WMI
        {
            "name": "WMI execution",
            "patterns": [
                re.compile(r"wmic\s+|wmiprvse\.exe|winmgmt|WmiPrvSE", re.IGNORECASE),
                re.compile(r"Win32_Process.*Create|ManagementObject.*InvokeMethod", re.IGNORECASE),
            ],
            "fields": ["process_name", "command_line", "raw_content"],
            "techniques": ["T1047"],
        },
        # Execution - Scheduled Tasks
        {
            "name": "Scheduled Task creation",
            "patterns": [
                re.compile(r"schtasks\s+/create|at\s+\d{2}:\d{2}|Register-ScheduledTask", re.IGNORECASE),
                re.compile(r"TaskScheduler|ScheduledTask", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1053.005", "T1053"],
        },
        # Execution - Service execution
        {
            "name": "Service execution",
            "patterns": [
                re.compile(r"sc\s+(create|start|config)|psexec|PsExec\.exe", re.IGNORECASE),
                re.compile(r"services\.exe.*child|service\s+installed|New-Service", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content", "process_name"],
            "techniques": ["T1569.002", "T1543.003"],
        },
        # Credential Access - LSASS
        {
            "name": "LSASS memory access (credential dumping)",
            "patterns": [
                re.compile(r"lsass\.exe|mimikatz|sekurlsa|logonpasswords", re.IGNORECASE),
                re.compile(r"procdump.*lsass|MiniDumpWriteDump|comsvcs\.dll.*MiniDump", re.IGNORECASE),
                re.compile(r"OpenProcess.*lsass|PROCESS_VM_READ.*lsass", re.IGNORECASE),
            ],
            "fields": ["process_name", "command_line", "raw_content"],
            "techniques": ["T1003.001", "T1003"],
        },
        # Credential Access - SAM
        {
            "name": "SAM database access",
            "patterns": [
                re.compile(r"reg\s+save\s+HKLM\\SAM|reg\s+save\s+HKLM\\SYSTEM", re.IGNORECASE),
                re.compile(r"\\Windows\\System32\\config\\SAM", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1003.002"],
        },
        # Credential Access - NTDS
        {
            "name": "NTDS.dit access",
            "patterns": [
                re.compile(r"ntds\.dit|ntdsutil|vssadmin.*ntds|secretsdump", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1003.003"],
        },
        # Credential Access - Brute Force
        {
            "name": "Brute force / password guessing",
            "patterns": [
                re.compile(r"(?:Failed|failure|invalid)\s+(?:password|login|logon|authentication)", re.IGNORECASE),
                re.compile(r"brute\s*force|password\s*spray|credential\s*stuff", re.IGNORECASE),
                re.compile(r"multiple failed login|repeated login attempt|Event\s*ID.*4625", re.IGNORECASE),
            ],
            "fields": ["raw_content"],
            "techniques": ["T1110", "T1110.001"],
        },
        # Credential Access - Kerberoasting
        {
            "name": "Kerberoasting",
            "patterns": [
                re.compile(r"kerberoast|Invoke-Kerberoast|GetUserSPNs|TGS-REP", re.IGNORECASE),
                re.compile(r"Event\s*ID.*4769.*0x17|RC4-HMAC.*TGS", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1558.003"],
        },
        # Process Injection
        {
            "name": "Process injection",
            "patterns": [
                re.compile(r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection", re.IGNORECASE),
                re.compile(r"QueueUserAPC|SetThreadContext|RtlCreateUserThread", re.IGNORECASE),
                re.compile(r"inject|hollowing|process.*inject", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1055", "T1055.001"],
        },
        # Persistence - Registry Run Keys
        {
            "name": "Registry run key modification",
            "patterns": [
                re.compile(r"\\CurrentVersion\\Run[^a-zA-Z]|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", re.IGNORECASE),
                re.compile(r"reg\s+add.*\\Run\\|Set-ItemProperty.*\\Run\\", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1547.001"],
        },
        # Persistence - Account Creation
        {
            "name": "Account creation",
            "patterns": [
                re.compile(r"net\s+user\s+\S+\s+/add|New-LocalUser|useradd", re.IGNORECASE),
                re.compile(r"Event\s*ID.*4720|user\s+account\s+created", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1136"],
        },
        # Defense Evasion - Log Clearing
        {
            "name": "Event log clearing",
            "patterns": [
                re.compile(r"wevtutil\s+cl|Clear-EventLog|Event\s*ID.*1102", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1070.001"],
        },
        # Defense Evasion - Disabling Defenses
        {
            "name": "Security tool disabling",
            "patterns": [
                re.compile(r"Set-MpPreference.*-DisableRealtimeMonitoring|tamper\s*protect|DisableAntiSpyware", re.IGNORECASE),
                re.compile(r"sc\s+stop\s+(windefend|MsMpSvc|WdNisSvc)|net\s+stop\s+.*security", re.IGNORECASE),
                re.compile(r"Uninstall.*antivirus|kill.*defender|disable.*firewall", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1562.001"],
        },
        # Defense Evasion - Rundll32/Regsvr32
        {
            "name": "System binary proxy execution",
            "patterns": [
                re.compile(r"rundll32\.exe\s+.*(?:javascript|http|shell32|url\.dll)", re.IGNORECASE),
                re.compile(r"regsvr32\s+/s\s+/u\s+/i|regsvr32.*scrobj\.dll", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1218.011", "T1218.010"],
        },
        # Masquerading
        {
            "name": "Process masquerading",
            "patterns": [
                re.compile(r"svchost\.exe.*(?!\\Windows\\System32\\)|\\Temp\\.*svchost|csrss.*\\Users\\", re.IGNORECASE),
            ],
            "fields": ["process_name", "command_line", "raw_content"],
            "techniques": ["T1036.005", "T1036"],
        },
        # Lateral Movement - RDP
        {
            "name": "RDP lateral movement",
            "patterns": [
                re.compile(r"mstsc\.exe|Remote\s*Desktop|RDP|TermService|port\s*3389", re.IGNORECASE),
                re.compile(r"Event\s*ID.*4624.*Type\s*10|logon\s*type.*10", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1021.001"],
        },
        # Lateral Movement - SMB/PsExec
        {
            "name": "SMB/PsExec lateral movement",
            "patterns": [
                re.compile(r"psexec|PsExec\.exe|ADMIN\$|IPC\$|\\\\[\d.]+\\[Cc]\$", re.IGNORECASE),
                re.compile(r"net\s+use\s+\\\\|SMB.*445", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content", "process_name"],
            "techniques": ["T1021.002", "T1570"],
        },
        # Lateral Movement - WinRM
        {
            "name": "WinRM lateral movement",
            "patterns": [
                re.compile(r"winrm|Enter-PSSession|Invoke-Command.*-ComputerName|WS-Management", re.IGNORECASE),
                re.compile(r"port\s*5985|port\s*5986|WinRM", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1021.006"],
        },
        # Discovery commands
        {
            "name": "System discovery",
            "patterns": [
                re.compile(r"systeminfo|hostname|whoami\s+/all|ver\b|uname\s+-a", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1082"],
        },
        {
            "name": "Network discovery",
            "patterns": [
                re.compile(r"ipconfig|ifconfig|netstat|route\s+print|arp\s+-a|net\s+view", re.IGNORECASE),
                re.compile(r"nslookup|nltest|net\s+config", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1016", "T1049"],
        },
        {
            "name": "Account/group discovery",
            "patterns": [
                re.compile(r"net\s+user|net\s+group|net\s+localgroup|Get-ADUser|Get-ADGroup", re.IGNORECASE),
                re.compile(r"whoami\s+/groups|net\s+accounts|dsquery", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1087", "T1069"],
        },
        # C2 - DNS tunneling
        {
            "name": "DNS tunneling",
            "patterns": [
                re.compile(r"dns\s*tunnel|iodine|dnscat|dns2tcp|TXT\s+record.*long", re.IGNORECASE),
                re.compile(r"unusual\s*dns|high\s*volume.*dns|dns.*exfil|subdomain.*length", re.IGNORECASE),
                re.compile(r"QueryName.*[a-zA-Z0-9]{30,}\.", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1071.004", "T1572"],
        },
        # C2 - HTTP/HTTPS beaconing
        {
            "name": "HTTP C2 beaconing",
            "patterns": [
                re.compile(r"beacon|c2\s*server|command\s*and\s*control|callback", re.IGNORECASE),
                re.compile(r"regular\s*interval.*http|periodic.*connection|heartbeat.*http", re.IGNORECASE),
                re.compile(r"cobalt\s*strike|covenant|empire|meterpreter|reverse.*shell", re.IGNORECASE),
            ],
            "fields": ["raw_content"],
            "techniques": ["T1071.001", "T1573"],
        },
        # C2 - Tool Transfer
        {
            "name": "Ingress tool transfer",
            "patterns": [
                re.compile(r"certutil.*-urlcache|bitsadmin.*transfer|Invoke-WebRequest|wget\s+http|curl\s+http", re.IGNORECASE),
                re.compile(r"DownloadFile|DownloadString|Net\.WebClient|Start-BitsTransfer", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1105"],
        },
        # Exfiltration
        {
            "name": "Data exfiltration over C2",
            "patterns": [
                re.compile(r"exfiltrat|data\s*theft|large.*outbound.*transfer|upload.*sensitive", re.IGNORECASE),
                re.compile(r"outbound.*(?:GB|MB).*transfer|unusual.*upload|bulk.*data.*send", re.IGNORECASE),
            ],
            "fields": ["raw_content"],
            "techniques": ["T1041"],
        },
        {
            "name": "Exfiltration over web service",
            "patterns": [
                re.compile(r"(?:mega|dropbox|drive\.google|pastebin|transfer\.sh|anonfile)", re.IGNORECASE),
                re.compile(r"upload.*cloud|cloud.*storage.*exfil", re.IGNORECASE),
            ],
            "fields": ["raw_content"],
            "techniques": ["T1567"],
        },
        # Impact - Ransomware
        {
            "name": "Ransomware behavior",
            "patterns": [
                re.compile(r"vssadmin.*delete\s*shadows|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no", re.IGNORECASE),
                re.compile(r"ransomware|ransom\s*note|encrypted.*files|\.locked$|\.encrypted$", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1490", "T1486"],
        },
        # Impact - Service Stop
        {
            "name": "Service disruption",
            "patterns": [
                re.compile(r"sc\s+stop|net\s+stop|Stop-Service|taskkill\s+/f\s+/im", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1489"],
        },
        # Phishing indicators
        {
            "name": "Phishing email indicators",
            "patterns": [
                re.compile(r"phishing|spearphishing|social\s*engineer", re.IGNORECASE),
                re.compile(r"malicious\s*(attachment|link|url)|suspicious\s*email", re.IGNORECASE),
                re.compile(r"\.eml$|From:.*Reply-To.*mismatch|display.*name.*spoof", re.IGNORECASE),
            ],
            "fields": ["raw_content", "alert_type"],
            "techniques": ["T1566", "T1204.001"],
        },
        # Valid account abuse
        {
            "name": "Valid account usage",
            "patterns": [
                re.compile(r"after.*hours.*login|unusual.*login.*time|off.*hours.*access", re.IGNORECASE),
                re.compile(r"login.*from.*unusual|geographic.*impossible|impossible.*travel", re.IGNORECASE),
            ],
            "fields": ["raw_content"],
            "techniques": ["T1078"],
        },
        # File deletion
        {
            "name": "File deletion / evidence removal",
            "patterns": [
                re.compile(r"del\s+/[fFqQsS]|Remove-Item.*-Force|rm\s+-rf|shred\s+", re.IGNORECASE),
                re.compile(r"SDelete|cipher\s+/w|secure.*delete|wipe.*evidence", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1070.004"],
        },
        # Web shell
        {
            "name": "Web shell activity",
            "patterns": [
                re.compile(r"web\s*shell|aspx?\s*shell|php\s*shell|cmd\.aspx|upload.*shell", re.IGNORECASE),
                re.compile(r"w3wp\.exe.*cmd\.exe|httpd.*sh\s+-c|IIS.*powershell", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content", "process_name"],
            "techniques": ["T1505.003"],
        },
        # UAC Bypass
        {
            "name": "UAC bypass",
            "patterns": [
                re.compile(r"uac\s*bypass|fodhelper|eventvwr.*mmc|Bypass-UAC|CMSTPLUA", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1548.002"],
        },
        # Data staging/archiving
        {
            "name": "Data staging and archiving",
            "patterns": [
                re.compile(r"7z\s+a\s+|rar\s+a\s+|zip\s+.*-r|Compress-Archive|tar\s+czf", re.IGNORECASE),
                re.compile(r"stage.*data|collect.*archive|compress.*exfil", re.IGNORECASE),
            ],
            "fields": ["command_line", "raw_content"],
            "techniques": ["T1560"],
        },
    ]

    @classmethod
    def map_techniques(cls, alert_data) -> List[Dict]:
        """Map alert data to MITRE ATT&CK techniques.

        Args:
            alert_data: AlertData object or dict with alert fields.

        Returns:
            List of matched technique dicts with evidence.
        """
        matched = []
        seen_techniques = set()

        # Build text fields to check
        if hasattr(alert_data, "to_dict"):
            data = alert_data.to_dict()
        elif isinstance(alert_data, dict):
            data = alert_data
        else:
            data = {"raw_content": str(alert_data)}

        # Add raw content field
        raw = data.get("raw_content", "") or ""
        if "raw_fields" in data:
            raw += " " + " ".join(str(v) for v in data.get("raw_fields", {}).values())

        field_values = {
            "process_name": str(data.get("process_name", "") or ""),
            "command_line": str(data.get("command_line", "") or ""),
            "raw_content": raw,
            "alert_type": str(data.get("alert_type", "") or ""),
        }

        for rule in cls.BEHAVIORAL_RULES:
            rule_matched = False
            evidence_text = ""

            for field_name in rule["fields"]:
                text = field_values.get(field_name, "")
                if not text:
                    continue

                for pattern in rule["patterns"]:
                    match = pattern.search(text)
                    if match:
                        rule_matched = True
                        evidence_text = match.group(0)[:100]
                        break

                if rule_matched:
                    break

            if rule_matched:
                for tech_id in rule["techniques"]:
                    if tech_id not in seen_techniques:
                        seen_techniques.add(tech_id)
                        tech_info = ATTACK_TECHNIQUES.get(tech_id, {})
                        matched.append({
                            "technique_id": tech_id,
                            "name": tech_info.get("name", "Unknown"),
                            "tactic": tech_info.get("tactic", "Unknown"),
                            "description": tech_info.get("description", ""),
                            "evidence": evidence_text,
                            "rule_name": rule["name"],
                        })

        return matched

    @classmethod
    def get_attack_narrative(cls, techniques: List[Dict]) -> str:
        """Generate a human-readable attack narrative from matched techniques.

        Args:
            techniques: List of matched technique dicts.

        Returns:
            Narrative string describing the observed attack chain.
        """
        if not techniques:
            return "No specific MITRE ATT&CK techniques were identified in this alert."

        tactic_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact",
        ]

        by_tactic = {}
        for tech in techniques:
            tactic = tech.get("tactic", "Unknown")
            by_tactic.setdefault(tactic, []).append(tech)

        narrative_parts = []
        for tactic in tactic_order:
            if tactic in by_tactic:
                techs = by_tactic[tactic]
                tech_names = [f"{t['name']} ({t['technique_id']})" for t in techs]
                narrative_parts.append(f"**{tactic}**: {', '.join(tech_names)}")

        return "Attack chain analysis:\n" + "\n".join(f"  {i+1}. {part}" for i, part in enumerate(narrative_parts))
