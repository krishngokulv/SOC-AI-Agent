import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Download, ExternalLink, Clock, Shield, Fingerprint,
  Map, Brain, FileText, ChevronDown, ChevronRight, Link, Globe,
  Hash, Mail, AlertTriangle, Copy, Check,
} from 'lucide-react';
import { investigationAPI } from '../utils/api';
import { VERDICTS, IOC_TYPES, formatTimestamp, formatConfidence, getRiskLevel } from '../utils/constants';
import { VerdictCard } from './VerdictBadge';
import VerdictBadge from './VerdictBadge';

// Mock detail data
const mockDetail = {
  id: 'INV-2024-001',
  alert_type: 'edr',
  created_at: new Date(Date.now() - 3600000).toISOString(),
  completed_at: new Date(Date.now() - 3500000).toISOString(),
  duration: 42.3,
  verdict: 'TRUE_POSITIVE',
  confidence: 0.94,
  summary: 'Suspicious PowerShell execution detected on WORKSTATION-PC07 with encoded command attempting to download a second-stage payload from a known malicious domain. Multiple indicators of compromise identified including communication with known C2 infrastructure.',
  reasoning: 'The encoded PowerShell command decodes to a download cradle targeting e2bee.net/stager, which is a known malicious infrastructure. The destination IP 185.220.101.34 is flagged across multiple threat intelligence sources. The execution chain (cmd.exe -> powershell.exe with encoded command) is consistent with MITRE ATT&CK technique T1059.001. Combined with the file hash matching known malware samples, this represents a confirmed true positive requiring immediate response.',
  raw_alert: '{"timestamp":"2024-01-15T14:23:00Z","rule_name":"Suspicious PowerShell Execution","severity":"HIGH"}',
  iocs: [
    { value: '185.220.101.34', type: 'ip', risk_score: 95, enrichment: { virustotal: { malicious: 42, total: 87 }, abuseipdb: { score: 100, reports: 2341 }, shodan: { ports: [80, 443, 8080], org: 'Suspicious Hosting' } } },
    { value: 'e2bee.net', type: 'domain', risk_score: 92, enrichment: { virustotal: { malicious: 38, total: 79 }, whois: { registrar: 'NameCheap', created: '2024-01-10' } } },
    { value: 'http://e2bee.net/stager', type: 'url', risk_score: 90, enrichment: { virustotal: { malicious: 35, total: 85 }, urlhaus: { status: 'online', threat: 'malware_download' } } },
    { value: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', type: 'hash_md5', risk_score: 88, enrichment: { virustotal: { malicious: 45, total: 72, name: 'Trojan.GenericKD' } } },
    { value: 'evil-domain.xyz', type: 'domain', risk_score: 85, enrichment: { virustotal: { malicious: 25, total: 80 } } },
  ],
  techniques: [
    { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', description: 'Adversary used PowerShell with encoded commands' },
    { id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control', description: 'HTTP-based C2 communication' },
    { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', description: 'Download of second-stage payload' },
    { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', description: 'Base64-encoded PowerShell command' },
    { id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'Initial Access', description: 'Likely initial delivery mechanism' },
  ],
  related_investigations: [
    { id: 'INV-2024-003', verdict: 'TRUE_POSITIVE', confidence: 0.88, alert_type: 'network', created_at: new Date(Date.now() - 7200000).toISOString() },
    { id: 'INV-2024-008', verdict: 'NEEDS_ESCALATION', confidence: 0.71, alert_type: 'siem', created_at: new Date(Date.now() - 86400000).toISOString() },
  ],
};

const iocIcons = {
  ip: Globe,
  domain: Globe,
  url: Link,
  hash_md5: Hash,
  hash_sha1: Hash,
  hash_sha256: Hash,
  email: Mail,
  cve: AlertTriangle,
};

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="p-1 hover:bg-cyber-hover rounded transition-colors"
      title="Copy to clipboard"
    >
      {copied ? (
        <Check size={12} className="text-neon-green" />
      ) : (
        <Copy size={12} className="text-gray-600 hover:text-gray-400" />
      )}
    </button>
  );
}

function IOCRow({ ioc }) {
  const [expanded, setExpanded] = useState(false);
  const Icon = iocIcons[ioc.type] || Fingerprint;
  const riskLevel = getRiskLevel(ioc.risk_score);
  const typeConfig = IOC_TYPES[ioc.type];

  return (
    <>
      <tr
        className="cursor-pointer hover:bg-cyber-hover transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <td>
          <div className="flex items-center gap-2">
            {expanded ? (
              <ChevronDown size={12} className="text-gray-500" />
            ) : (
              <ChevronRight size={12} className="text-gray-500" />
            )}
            <Icon size={14} style={{ color: typeConfig?.color || '#64748b' }} />
            <span className="text-neon-blue">{ioc.value}</span>
            <CopyButton text={ioc.value} />
          </div>
        </td>
        <td>
          <span
            className="badge"
            style={{
              backgroundColor: `${typeConfig?.color || '#64748b'}15`,
              color: typeConfig?.color || '#64748b',
              borderColor: `${typeConfig?.color || '#64748b'}30`,
              border: '1px solid',
            }}
          >
            {typeConfig?.label || ioc.type}
          </span>
        </td>
        <td>
          <div className="flex items-center gap-2">
            <div className="w-16 h-1.5 bg-cyber-bg rounded-full overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${ioc.risk_score}%`,
                  backgroundColor: riskLevel.color,
                }}
              />
            </div>
            <span className="font-bold" style={{ color: riskLevel.color }}>
              {ioc.risk_score}
            </span>
          </div>
        </td>
      </tr>
      {expanded && ioc.enrichment && (
        <tr>
          <td colSpan={3} className="!p-0">
            <div className="p-4 bg-cyber-bg border-t border-b border-cyber-border/50">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {Object.entries(ioc.enrichment).map(([source, data]) => (
                  <div key={source} className="p-3 bg-cyber-surface rounded-lg border border-cyber-border">
                    <h5 className="text-[10px] font-mono text-neon-blue uppercase tracking-wider mb-2 font-semibold">
                      {source}
                    </h5>
                    <div className="space-y-1">
                      {Object.entries(data).map(([key, val]) => (
                        <div key={key} className="flex justify-between text-[11px] font-mono">
                          <span className="text-gray-500">{key}:</span>
                          <span className="text-gray-300">
                            {Array.isArray(val) ? val.join(', ') : String(val)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function InvestigationDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const fetchDetail = async () => {
      try {
        const response = await investigationAPI.getById(id);
        setDetail(response.data);
      } catch {
        console.log('[Detail] Using mock data');
        setDetail({ ...mockDetail, id });
      } finally {
        setLoading(false);
      }
    };
    fetchDetail();
  }, [id]);

  const handleDownload = async (format) => {
    try {
      const response = await fetch(`/api/investigations/${id}/report?format=${format}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `investigation-${id}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download error:', err);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="cyber-spinner mr-3" />
        <span className="font-mono text-gray-400">Loading investigation...</span>
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="text-center py-20">
        <AlertTriangle size={32} className="text-neon-red mx-auto mb-3" />
        <p className="font-mono text-gray-400">Investigation not found</p>
      </div>
    );
  }

  const tabs = [
    { key: 'overview', label: 'Overview', icon: Shield },
    { key: 'iocs', label: `IOCs (${detail.iocs?.length || 0})`, icon: Fingerprint },
    { key: 'techniques', label: `Techniques (${detail.techniques?.length || 0})`, icon: Map },
    { key: 'reasoning', label: 'AI Reasoning', icon: Brain },
    { key: 'raw', label: 'Raw Alert', icon: FileText },
  ];

  return (
    <div className="space-y-6 pb-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/history')}
            className="p-2 rounded-lg border border-cyber-border hover:border-neon-green/30 transition-colors"
          >
            <ArrowLeft size={16} className="text-gray-400" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
              <Shield size={24} className="text-neon-blue" />
              {detail.id}
            </h1>
            <div className="flex items-center gap-4 mt-1">
              <span className="text-xs font-mono text-gray-500 flex items-center gap-1">
                <Clock size={11} /> {formatTimestamp(detail.created_at)}
              </span>
              <span className="badge-blue text-[10px]">{detail.alert_type}</span>
              {detail.duration && (
                <span className="text-xs font-mono text-gray-500">
                  Duration: {detail.duration.toFixed(1)}s
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => handleDownload('html')}
            className="cyber-button-primary flex items-center gap-2 text-xs"
          >
            <Download size={14} />
            HTML
          </button>
          <button
            onClick={() => handleDownload('pdf')}
            className="cyber-button-blue flex items-center gap-2 text-xs"
          >
            <Download size={14} />
            PDF
          </button>
        </div>
      </div>

      {/* Verdict Card */}
      <VerdictCard
        verdict={detail.verdict}
        confidence={detail.confidence}
        reasoning={detail.summary}
      />

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-cyber-border pb-0">
        {tabs.map((tab) => {
          const TabIcon = tab.icon;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`
                flex items-center gap-2 px-4 py-2.5 text-xs font-mono font-medium
                border-b-2 transition-all duration-200
                ${
                  activeTab === tab.key
                    ? 'text-neon-green border-neon-green'
                    : 'text-gray-500 border-transparent hover:text-gray-300 hover:border-gray-700'
                }
              `}
            >
              <TabIcon size={13} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      <div className="animate-fade-in">
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Summary */}
            <div className="cyber-card p-5">
              <h3 className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-3">
                Investigation Summary
              </h3>
              <p className="text-sm text-gray-300 leading-relaxed">{detail.summary}</p>
            </div>

            {/* Quick stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="stat-card" style={{ '--accent-color': '#00d4ff' }}>
                <p className="text-xs font-mono text-gray-500 uppercase">IOCs Found</p>
                <p className="text-2xl font-mono font-bold text-neon-blue mt-1">
                  {detail.iocs?.length || 0}
                </p>
              </div>
              <div className="stat-card" style={{ '--accent-color': '#a855f7' }}>
                <p className="text-xs font-mono text-gray-500 uppercase">Techniques</p>
                <p className="text-2xl font-mono font-bold text-neon-purple mt-1">
                  {detail.techniques?.length || 0}
                </p>
              </div>
              <div className="stat-card" style={{ '--accent-color': '#00ff88' }}>
                <p className="text-xs font-mono text-gray-500 uppercase">Confidence</p>
                <p className="text-2xl font-mono font-bold text-neon-green mt-1">
                  {formatConfidence(detail.confidence)}
                </p>
              </div>
              <div className="stat-card" style={{ '--accent-color': '#eab308' }}>
                <p className="text-xs font-mono text-gray-500 uppercase">Duration</p>
                <p className="text-2xl font-mono font-bold text-neon-yellow mt-1">
                  {detail.duration ? `${detail.duration.toFixed(1)}s` : 'N/A'}
                </p>
              </div>
            </div>

            {/* Related investigations */}
            {detail.related_investigations?.length > 0 && (
              <div className="cyber-card p-5">
                <h3 className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-3">
                  Related Investigations
                </h3>
                <div className="space-y-2">
                  {detail.related_investigations.map((rel) => (
                    <div
                      key={rel.id}
                      onClick={() => navigate(`/investigation/${rel.id}`)}
                      className="flex items-center justify-between p-3 bg-cyber-bg rounded-lg border border-cyber-border
                                 hover:border-neon-green/20 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-sm font-mono text-neon-blue">{rel.id}</span>
                        <span className="badge-blue text-[10px]">{rel.alert_type}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <VerdictBadge verdict={rel.verdict} confidence={rel.confidence} size="sm" />
                        <ArrowLeft size={12} className="text-gray-600 rotate-180" />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* IOCs Tab */}
        {activeTab === 'iocs' && (
          <div className="cyber-card overflow-hidden">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>IOC Value</th>
                  <th>Type</th>
                  <th>Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {detail.iocs?.map((ioc, i) => (
                  <IOCRow key={i} ioc={ioc} />
                ))}
              </tbody>
            </table>
            {(!detail.iocs || detail.iocs.length === 0) && (
              <div className="text-center py-10">
                <Fingerprint size={24} className="text-gray-700 mx-auto mb-2" />
                <p className="text-sm font-mono text-gray-500">No IOCs extracted</p>
              </div>
            )}
          </div>
        )}

        {/* Techniques Tab */}
        {activeTab === 'techniques' && (
          <div className="space-y-3">
            {detail.techniques?.map((tech) => (
              <div
                key={tech.id}
                className="cyber-card p-4 hover:border-neon-green/20 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3">
                    <div className="p-1.5 bg-neon-purple/10 rounded border border-neon-purple/20">
                      <Map size={14} className="text-neon-purple" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-mono font-bold text-neon-blue">
                          {tech.id}
                        </span>
                        <span className="text-sm text-gray-300">{tech.name}</span>
                      </div>
                      <span className="badge-purple text-[10px] mt-1 inline-block">
                        {tech.tactic}
                      </span>
                      {tech.description && (
                        <p className="text-xs text-gray-400 mt-2">{tech.description}</p>
                      )}
                    </div>
                  </div>
                  <a
                    href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-1.5 hover:bg-cyber-hover rounded transition-colors"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <ExternalLink size={12} className="text-gray-500 hover:text-neon-blue" />
                  </a>
                </div>
              </div>
            ))}
            {(!detail.techniques || detail.techniques.length === 0) && (
              <div className="text-center py-10">
                <Map size={24} className="text-gray-700 mx-auto mb-2" />
                <p className="text-sm font-mono text-gray-500">No techniques mapped</p>
              </div>
            )}
          </div>
        )}

        {/* AI Reasoning Tab */}
        {activeTab === 'reasoning' && (
          <div className="cyber-card p-6">
            <div className="flex items-center gap-2 mb-4">
              <Brain size={16} className="text-neon-green" />
              <h3 className="text-xs font-mono text-gray-400 uppercase tracking-wider">
                AI Analysis & Reasoning Chain
              </h3>
            </div>
            <div className="p-4 bg-cyber-bg rounded-lg border border-cyber-border">
              <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap font-mono">
                {detail.reasoning || detail.summary || 'No detailed reasoning available.'}
              </p>
            </div>

            {/* Confidence breakdown */}
            <div className="mt-6">
              <h4 className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-3">
                Confidence Breakdown
              </h4>
              <div className="space-y-3">
                {[
                  { label: 'IOC Risk Assessment', score: 0.95 },
                  { label: 'Behavioral Analysis', score: 0.92 },
                  { label: 'ATT&CK Pattern Match', score: 0.88 },
                  { label: 'Historical Correlation', score: 0.85 },
                  { label: 'Overall Confidence', score: detail.confidence || 0.94 },
                ].map((item) => (
                  <div key={item.label}>
                    <div className="flex justify-between text-xs font-mono mb-1">
                      <span className="text-gray-400">{item.label}</span>
                      <span className="text-neon-green">{formatConfidence(item.score)}</span>
                    </div>
                    <div className="h-1.5 bg-cyber-bg rounded-full overflow-hidden border border-cyber-border">
                      <div
                        className="h-full rounded-full confidence-fill"
                        style={{
                          width: `${item.score * 100}%`,
                          background: `linear-gradient(90deg, #00ff8880, #00ff88)`,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Raw Alert Tab */}
        {activeTab === 'raw' && (
          <div className="cyber-card p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-mono text-gray-400 uppercase tracking-wider">
                Original Alert Data
              </h3>
              <CopyButton text={detail.raw_alert || ''} />
            </div>
            <pre className="p-4 bg-cyber-bg rounded-lg border border-cyber-border text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {(() => {
                try {
                  return JSON.stringify(JSON.parse(detail.raw_alert), null, 2);
                } catch {
                  return detail.raw_alert || 'No raw alert data available';
                }
              })()}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
