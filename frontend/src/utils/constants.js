// API Configuration
export const API_BASE_URL = import.meta.env.VITE_API_URL || '';
export const WS_BASE_URL =
  import.meta.env.VITE_WS_URL ||
  `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`;

// Verdict configuration
export const VERDICTS = {
  TRUE_POSITIVE: {
    label: 'True Positive',
    shortLabel: 'TP',
    color: '#ef4444',
    bgColor: 'bg-neon-red/15',
    textColor: 'text-neon-red',
    borderColor: 'border-neon-red/30',
    badgeClass: 'badge-red',
    description: 'Confirmed malicious activity',
  },
  FALSE_POSITIVE: {
    label: 'False Positive',
    shortLabel: 'FP',
    color: '#00ff88',
    bgColor: 'bg-neon-green/15',
    textColor: 'text-neon-green',
    borderColor: 'border-neon-green/30',
    badgeClass: 'badge-green',
    description: 'Benign activity, no threat',
  },
  NEEDS_ESCALATION: {
    label: 'Needs Escalation',
    shortLabel: 'ESC',
    color: '#eab308',
    bgColor: 'bg-neon-yellow/15',
    textColor: 'text-neon-yellow',
    borderColor: 'border-neon-yellow/30',
    badgeClass: 'badge-yellow',
    description: 'Requires human review',
  },
  SUSPICIOUS: {
    label: 'Suspicious',
    shortLabel: 'SUS',
    color: '#f97316',
    bgColor: 'bg-neon-orange/15',
    textColor: 'text-neon-orange',
    borderColor: 'border-neon-orange/30',
    badgeClass: 'badge-yellow',
    description: 'Potentially malicious',
  },
  BENIGN: {
    label: 'Benign',
    shortLabel: 'BEN',
    color: '#00d4ff',
    bgColor: 'bg-neon-blue/15',
    textColor: 'text-neon-blue',
    borderColor: 'border-neon-blue/30',
    badgeClass: 'badge-blue',
    description: 'No threat detected',
  },
};

// Alert types
export const ALERT_TYPES = [
  { value: 'siem', label: 'SIEM Alert', icon: 'Monitor' },
  { value: 'edr', label: 'EDR Alert', icon: 'Shield' },
  { value: 'phishing', label: 'Phishing Email', icon: 'Mail' },
  { value: 'network', label: 'Network Alert', icon: 'Wifi' },
  { value: 'firewall', label: 'Firewall Log', icon: 'Lock' },
  { value: 'ids', label: 'IDS/IPS Alert', icon: 'AlertTriangle' },
  { value: 'malware', label: 'Malware Alert', icon: 'Bug' },
  { value: 'custom', label: 'Custom / Raw Log', icon: 'FileText' },
];

// IOC Types
export const IOC_TYPES = {
  ip: { label: 'IP Address', icon: 'Globe', color: '#00d4ff' },
  domain: { label: 'Domain', icon: 'Globe', color: '#a855f7' },
  url: { label: 'URL', icon: 'Link', color: '#f97316' },
  hash_md5: { label: 'MD5 Hash', icon: 'Hash', color: '#00ff88' },
  hash_sha1: { label: 'SHA1 Hash', icon: 'Hash', color: '#00ff88' },
  hash_sha256: { label: 'SHA256 Hash', icon: 'Hash', color: '#00ff88' },
  email: { label: 'Email', icon: 'Mail', color: '#eab308' },
  cve: { label: 'CVE', icon: 'AlertTriangle', color: '#ef4444' },
};

// Investigation stages (for live timeline)
export const INVESTIGATION_STAGES = [
  {
    key: 'parsing',
    label: 'Parsing Alert',
    description: 'Extracting structured data from raw alert',
    icon: 'FileSearch',
  },
  {
    key: 'ioc_extraction',
    label: 'IOC Extraction',
    description: 'Identifying indicators of compromise',
    icon: 'Search',
  },
  {
    key: 'enrichment',
    label: 'Threat Enrichment',
    description: 'Querying threat intelligence sources',
    icon: 'Database',
  },
  {
    key: 'mitre_mapping',
    label: 'ATT&CK Mapping',
    description: 'Mapping to MITRE ATT&CK framework',
    icon: 'Map',
  },
  {
    key: 'analysis',
    label: 'AI Analysis',
    description: 'Deep analysis by AI reasoning engine',
    icon: 'Brain',
  },
  {
    key: 'verdict',
    label: 'Verdict',
    description: 'Final determination and confidence score',
    icon: 'CheckCircle',
  },
  {
    key: 'report',
    label: 'Report Generation',
    description: 'Generating investigation report',
    icon: 'FileText',
  },
];

// MITRE ATT&CK Tactics (ordered)
export const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
];

// Risk score thresholds
export const RISK_LEVELS = {
  CRITICAL: { min: 80, label: 'Critical', color: '#ef4444' },
  HIGH: { min: 60, label: 'High', color: '#f97316' },
  MEDIUM: { min: 40, label: 'Medium', color: '#eab308' },
  LOW: { min: 20, label: 'Low', color: '#00d4ff' },
  INFO: { min: 0, label: 'Info', color: '#64748b' },
};

// Chart colors palette
export const CHART_COLORS = [
  '#00ff88',
  '#00d4ff',
  '#a855f7',
  '#f97316',
  '#ef4444',
  '#eab308',
  '#06b6d4',
  '#ec4899',
  '#84cc16',
  '#6366f1',
];

// Format helpers
export const formatTimestamp = (ts) => {
  if (!ts) return 'N/A';
  const d = new Date(ts);
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
};

export const formatDate = (ts) => {
  if (!ts) return 'N/A';
  const d = new Date(ts);
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
};

export const formatConfidence = (value) => {
  if (value == null) return 'N/A';
  return `${Math.round(value * 100)}%`;
};

export const getRiskLevel = (score) => {
  if (score >= 80) return RISK_LEVELS.CRITICAL;
  if (score >= 60) return RISK_LEVELS.HIGH;
  if (score >= 40) return RISK_LEVELS.MEDIUM;
  if (score >= 20) return RISK_LEVELS.LOW;
  return RISK_LEVELS.INFO;
};

export const truncate = (str, len = 40) => {
  if (!str) return '';
  return str.length > len ? str.substring(0, len) + '...' : str;
};
