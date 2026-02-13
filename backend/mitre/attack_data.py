"""Local MITRE ATT&CK technique database.

Embedded JSON of the top 80+ most commonly observed techniques.
"""

from typing import Optional

ATTACK_TECHNIQUES = {
    # Initial Access
    "T1566": {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "description": "Adversaries may send phishing messages to gain access to victim systems."},
    "T1566.001": {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "description": "Adversaries send spearphishing emails with a malicious attachment."},
    "T1566.002": {"id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access", "description": "Adversaries send spearphishing emails with a malicious link."},
    "T1190": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "description": "Adversaries exploit vulnerabilities in internet-facing applications."},
    "T1133": {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access", "description": "Adversaries use external remote services to gain initial access."},
    "T1078": {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access", "description": "Adversaries use valid credentials for initial access."},
    "T1199": {"id": "T1199", "name": "Trusted Relationship", "tactic": "Initial Access", "description": "Adversaries exploit trusted third-party relationships."},

    # Execution
    "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries abuse command and script interpreters to execute commands."},
    "T1059.001": {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution", "description": "Adversaries abuse PowerShell commands and scripts for execution."},
    "T1059.003": {"id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell", "tactic": "Execution", "description": "Adversaries abuse the Windows command shell for execution."},
    "T1059.005": {"id": "T1059.005", "name": "Command and Scripting Interpreter: Visual Basic", "tactic": "Execution", "description": "Adversaries abuse VBScript for execution."},
    "T1059.006": {"id": "T1059.006", "name": "Command and Scripting Interpreter: Python", "tactic": "Execution", "description": "Adversaries abuse Python for execution."},
    "T1059.007": {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution", "description": "Adversaries abuse JavaScript for execution."},
    "T1203": {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution", "description": "Adversaries exploit software vulnerabilities in client applications."},
    "T1204": {"id": "T1204", "name": "User Execution", "tactic": "Execution", "description": "An adversary relies upon specific actions by a user to gain execution."},
    "T1204.001": {"id": "T1204.001", "name": "User Execution: Malicious Link", "tactic": "Execution", "description": "A user clicks a malicious link to gain execution."},
    "T1204.002": {"id": "T1204.002", "name": "User Execution: Malicious File", "tactic": "Execution", "description": "A user opens a malicious file to gain execution."},
    "T1047": {"id": "T1047", "name": "Windows Management Instrumentation", "tactic": "Execution", "description": "Adversaries abuse WMI to execute malicious commands."},
    "T1569.002": {"id": "T1569.002", "name": "System Services: Service Execution", "tactic": "Execution", "description": "Adversaries abuse the Windows Service Control Manager to execute binaries."},

    # Persistence
    "T1547.001": {"id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "tactic": "Persistence", "description": "Adversaries add programs to Registry run keys or startup folders."},
    "T1053": {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence", "description": "Adversaries abuse task scheduling to execute malicious code."},
    "T1053.005": {"id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task", "tactic": "Persistence", "description": "Adversaries abuse the Windows Task Scheduler."},
    "T1543.003": {"id": "T1543.003", "name": "Create or Modify System Process: Windows Service", "tactic": "Persistence", "description": "Adversaries create or modify Windows services for persistence."},
    "T1136": {"id": "T1136", "name": "Create Account", "tactic": "Persistence", "description": "Adversaries create accounts to maintain access."},
    "T1098": {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence", "description": "Adversaries manipulate accounts to maintain access."},
    "T1505.003": {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "description": "Adversaries install web shells on web servers for persistence."},

    # Privilege Escalation
    "T1548.002": {"id": "T1548.002", "name": "Abuse Elevation Control Mechanism: Bypass User Account Control", "tactic": "Privilege Escalation", "description": "Adversaries bypass UAC mechanisms to elevate privileges."},
    "T1055": {"id": "T1055", "name": "Process Injection", "tactic": "Privilege Escalation", "description": "Adversaries inject code into processes to evade defenses and elevate privileges."},
    "T1055.001": {"id": "T1055.001", "name": "Process Injection: Dynamic-link Library Injection", "tactic": "Privilege Escalation", "description": "Adversaries inject DLLs into processes."},
    "T1068": {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "description": "Adversaries exploit software vulnerabilities to elevate privileges."},

    # Defense Evasion
    "T1562.001": {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion", "description": "Adversaries disable security tools to avoid detection."},
    "T1070": {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion", "description": "Adversaries delete or modify artifacts to remove evidence."},
    "T1070.001": {"id": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs", "tactic": "Defense Evasion", "description": "Adversaries clear Windows event logs to remove evidence."},
    "T1070.004": {"id": "T1070.004", "name": "Indicator Removal: File Deletion", "tactic": "Defense Evasion", "description": "Adversaries delete files to remove evidence."},
    "T1027": {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "description": "Adversaries use obfuscation to hide information."},
    "T1027.010": {"id": "T1027.010", "name": "Obfuscated Files or Information: Command Obfuscation", "tactic": "Defense Evasion", "description": "Adversaries obfuscate commands to evade detection."},
    "T1036": {"id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion", "description": "Adversaries manipulate features to make artifacts appear legitimate."},
    "T1036.005": {"id": "T1036.005", "name": "Masquerading: Match Legitimate Name or Location", "tactic": "Defense Evasion", "description": "Adversaries match or change names to appear legitimate."},
    "T1218.011": {"id": "T1218.011", "name": "System Binary Proxy Execution: Rundll32", "tactic": "Defense Evasion", "description": "Adversaries abuse rundll32.exe to proxy execution."},
    "T1218.010": {"id": "T1218.010", "name": "System Binary Proxy Execution: Regsvr32", "tactic": "Defense Evasion", "description": "Adversaries abuse regsvr32.exe to proxy execution."},
    "T1140": {"id": "T1140", "name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion", "description": "Adversaries deobfuscate/decode files or information."},
    "T1112": {"id": "T1112", "name": "Modify Registry", "tactic": "Defense Evasion", "description": "Adversaries modify the Windows Registry."},
    "T1564.001": {"id": "T1564.001", "name": "Hide Artifacts: Hidden Files and Directories", "tactic": "Defense Evasion", "description": "Adversaries set files and directories as hidden."},

    # Credential Access
    "T1003": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access", "description": "Adversaries dump credentials from the OS."},
    "T1003.001": {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access", "description": "Adversaries access LSASS process memory for credential material."},
    "T1003.002": {"id": "T1003.002", "name": "OS Credential Dumping: Security Account Manager", "tactic": "Credential Access", "description": "Adversaries extract credentials from the SAM database."},
    "T1003.003": {"id": "T1003.003", "name": "OS Credential Dumping: NTDS", "tactic": "Credential Access", "description": "Adversaries access the NTDS.dit AD database."},
    "T1110": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "description": "Adversaries use brute force techniques to guess credentials."},
    "T1110.001": {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access", "description": "Adversaries guess passwords through repeated login attempts."},
    "T1110.003": {"id": "T1110.003", "name": "Brute Force: Password Spraying", "tactic": "Credential Access", "description": "Adversaries spray common passwords across many accounts."},
    "T1555": {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "Credential Access", "description": "Adversaries search for credentials in password stores."},
    "T1558.003": {"id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting", "tactic": "Credential Access", "description": "Adversaries abuse Kerberos to obtain credential material."},
    "T1552.001": {"id": "T1552.001", "name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access", "description": "Adversaries search local file systems for credentials."},

    # Discovery
    "T1082": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "description": "Adversaries gather detailed system information."},
    "T1083": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "description": "Adversaries enumerate files and directories."},
    "T1057": {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery", "description": "Adversaries enumerate running processes."},
    "T1016": {"id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery", "description": "Adversaries look for network configuration details."},
    "T1018": {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery", "description": "Adversaries attempt to identify remote systems on a network."},
    "T1087": {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery", "description": "Adversaries enumerate system and domain accounts."},
    "T1069": {"id": "T1069", "name": "Permission Groups Discovery", "tactic": "Discovery", "description": "Adversaries enumerate permission groups."},
    "T1049": {"id": "T1049", "name": "System Network Connections Discovery", "tactic": "Discovery", "description": "Adversaries enumerate current network connections."},

    # Lateral Movement
    "T1021.001": {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement", "description": "Adversaries use RDP for lateral movement."},
    "T1021.002": {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement", "description": "Adversaries use SMB shares for lateral movement."},
    "T1021.003": {"id": "T1021.003", "name": "Remote Services: Distributed Component Object Model", "tactic": "Lateral Movement", "description": "Adversaries use DCOM for lateral movement."},
    "T1021.006": {"id": "T1021.006", "name": "Remote Services: Windows Remote Management", "tactic": "Lateral Movement", "description": "Adversaries use WinRM for lateral movement."},
    "T1570": {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement", "description": "Adversaries transfer tools between systems within a network."},
    "T1080": {"id": "T1080", "name": "Taint Shared Content", "tactic": "Lateral Movement", "description": "Adversaries deliver payloads to systems via shared network resources."},

    # Collection
    "T1560": {"id": "T1560", "name": "Archive Collected Data", "tactic": "Collection", "description": "Adversaries compress and/or encrypt collected data."},
    "T1005": {"id": "T1005", "name": "Data from Local System", "tactic": "Collection", "description": "Adversaries search local system sources for data of interest."},
    "T1114": {"id": "T1114", "name": "Email Collection", "tactic": "Collection", "description": "Adversaries collect email data."},
    "T1113": {"id": "T1113", "name": "Screen Capture", "tactic": "Collection", "description": "Adversaries capture screenshots of the victim system."},
    "T1125": {"id": "T1125", "name": "Video Capture", "tactic": "Collection", "description": "Adversaries capture video from webcams."},
    "T1056.001": {"id": "T1056.001", "name": "Input Capture: Keylogging", "tactic": "Collection", "description": "Adversaries log user keystrokes to intercept credentials."},

    # Command and Control
    "T1071": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Adversaries communicate using application layer protocols."},
    "T1071.001": {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "description": "Adversaries use HTTP/S for C2."},
    "T1071.004": {"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control", "description": "Adversaries use DNS for C2 communications."},
    "T1105": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "description": "Adversaries transfer tools from an external system."},
    "T1573": {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control", "description": "Adversaries use encrypted channels for C2."},
    "T1572": {"id": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control", "description": "Adversaries tunnel network communications over existing protocols."},
    "T1090": {"id": "T1090", "name": "Proxy", "tactic": "Command and Control", "description": "Adversaries use a connection proxy to direct traffic."},
    "T1095": {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "Command and Control", "description": "Adversaries use non-application layer protocols for C2."},
    "T1571": {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control", "description": "Adversaries use non-standard ports for C2."},
    "T1568": {"id": "T1568", "name": "Dynamic Resolution", "tactic": "Command and Control", "description": "Adversaries use dynamic resolution to establish C2."},
    "T1132": {"id": "T1132", "name": "Data Encoding", "tactic": "Command and Control", "description": "Adversaries encode data to make C2 traffic less conspicuous."},
    "T1102": {"id": "T1102", "name": "Web Service", "tactic": "Command and Control", "description": "Adversaries use legitimate web services for C2."},

    # Exfiltration
    "T1041": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "description": "Adversaries steal data by transmitting it over the C2 channel."},
    "T1048": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "description": "Adversaries steal data using a different protocol than C2."},
    "T1567": {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "description": "Adversaries use web services to exfiltrate data."},
    "T1537": {"id": "T1537", "name": "Transfer Data to Cloud Account", "tactic": "Exfiltration", "description": "Adversaries exfiltrate data to cloud accounts."},
    "T1029": {"id": "T1029", "name": "Scheduled Transfer", "tactic": "Exfiltration", "description": "Adversaries schedule data exfiltration at certain times."},

    # Impact
    "T1486": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Adversaries encrypt data to disrupt operations (ransomware)."},
    "T1490": {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact", "description": "Adversaries delete or disable recovery features (e.g., shadow copies)."},
    "T1489": {"id": "T1489", "name": "Service Stop", "tactic": "Impact", "description": "Adversaries stop services to render systems or data unavailable."},
    "T1485": {"id": "T1485", "name": "Data Destruction", "tactic": "Impact", "description": "Adversaries destroy data and files on systems."},
    "T1499": {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact", "description": "Adversaries perform DoS attacks on endpoints."},
    "T1491": {"id": "T1491", "name": "Defacement", "tactic": "Impact", "description": "Adversaries deface systems to deliver messaging."},
    "T1531": {"id": "T1531", "name": "Account Access Removal", "tactic": "Impact", "description": "Adversaries interrupt availability by inhibiting access to accounts."},
}


def get_technique(technique_id: str) -> Optional[dict]:
    """Look up a MITRE ATT&CK technique by ID.

    Args:
        technique_id: The technique ID (e.g., T1059.001).

    Returns:
        Technique dict or None if not found.
    """
    return ATTACK_TECHNIQUES.get(technique_id)


def get_techniques_by_tactic(tactic: str) -> list:
    """Get all techniques for a given tactic.

    Args:
        tactic: The tactic name (e.g., "Execution").

    Returns:
        List of technique dicts.
    """
    return [t for t in ATTACK_TECHNIQUES.values() if t["tactic"] == tactic]


TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]
