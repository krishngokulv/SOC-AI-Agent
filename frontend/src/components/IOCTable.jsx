import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Database, Search, X, Globe, Link, Hash, Mail, AlertTriangle,
  Fingerprint, ChevronDown, ChevronRight, ChevronLeft, Copy,
  Check, Filter, ExternalLink, ArrowUpDown,
} from 'lucide-react';
import { iocAPI } from '../utils/api';
import { IOC_TYPES, getRiskLevel, formatTimestamp, formatDate } from '../utils/constants';

// Mock IOC data
const generateMockIOCs = () => {
  const types = ['ip', 'domain', 'url', 'hash_md5', 'hash_sha256', 'email'];
  const mockValues = {
    ip: ['185.220.101.34', '103.45.67.89', '45.33.32.156', '192.168.1.100', '10.0.0.50', '172.16.0.1', '8.8.8.8', '1.1.1.1', '91.234.56.78', '203.0.113.42', '198.51.100.10', '45.77.123.45'],
    domain: ['evil-domain.xyz', 'malware-c2.net', 'phish-login.com', 'dropper.ru', 'c2-server.io', 'bad-actor.com', 'data-exfil.xyz', 'trojan-host.net'],
    url: ['http://e2bee.net/stager', 'https://phish.example.com/login', 'http://malware.host/payload.exe', 'http://evil-cdn.net/dropper'],
    hash_md5: ['a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', 'd4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9', 'f1e2d3c4b5a6978877665544332211aa'],
    hash_sha256: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'a5c63ff46fa7d44b8cc37af60d15c6b53d8fa8d21c684f9faa7c3dc7f2d5e69f'],
    email: ['attacker@evil.com', 'phisher@fake-bank.com', 'malware.distro@darkweb.org'],
  };

  return Array.from({ length: 45 }, (_, i) => {
    const type = types[Math.floor(Math.random() * types.length)];
    const values = mockValues[type];
    return {
      id: `IOC-${String(i + 1).padStart(4, '0')}`,
      value: values[Math.floor(Math.random() * values.length)],
      type,
      risk_score: Math.floor(Math.random() * 80) + 20,
      times_seen: Math.floor(Math.random() * 50) + 1,
      first_seen: new Date(Date.now() - Math.random() * 90 * 86400000).toISOString(),
      last_seen: new Date(Date.now() - Math.random() * 7 * 86400000).toISOString(),
      tags: ['malware', 'c2', 'phishing', 'dropper'].slice(0, Math.floor(Math.random() * 3) + 1),
      enrichment: {
        virustotal: { malicious: Math.floor(Math.random() * 50), total: 85 },
        abuseipdb: type === 'ip' ? { score: Math.floor(Math.random() * 100), reports: Math.floor(Math.random() * 1000) } : undefined,
      },
    };
  });
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
    <button onClick={handleCopy} className="p-1 hover:bg-cyber-hover rounded transition-colors" title="Copy">
      {copied ? <Check size={11} className="text-neon-green" /> : <Copy size={11} className="text-gray-600" />}
    </button>
  );
}

function IOCDetailPanel({ ioc, onClose }) {
  const riskLevel = getRiskLevel(ioc.risk_score);
  const typeConfig = IOC_TYPES[ioc.type];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="cyber-card p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto border-neon-blue/30 animate-fade-in">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-neon-blue/10 rounded-lg border border-neon-blue/20">
              <Fingerprint size={18} className="text-neon-blue" />
            </div>
            <div>
              <h3 className="text-sm font-mono font-bold text-gray-200">IOC Details</h3>
              <span
                className="badge mt-1 inline-block"
                style={{
                  backgroundColor: `${typeConfig?.color}15`,
                  color: typeConfig?.color,
                  borderColor: `${typeConfig?.color}30`,
                  border: '1px solid',
                }}
              >
                {typeConfig?.label || ioc.type}
              </span>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 hover:bg-cyber-hover rounded transition-colors">
            <X size={16} className="text-gray-500" />
          </button>
        </div>

        {/* Value */}
        <div className="p-4 bg-cyber-bg rounded-lg border border-cyber-border mb-4">
          <div className="flex items-center justify-between">
            <code className="text-sm font-mono text-neon-blue break-all">{ioc.value}</code>
            <CopyButton text={ioc.value} />
          </div>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
          <div className="p-3 bg-cyber-bg rounded-lg border border-cyber-border text-center">
            <p className="text-[10px] font-mono text-gray-500 uppercase">Risk Score</p>
            <p className="text-xl font-mono font-bold mt-1" style={{ color: riskLevel.color }}>
              {ioc.risk_score}
            </p>
          </div>
          <div className="p-3 bg-cyber-bg rounded-lg border border-cyber-border text-center">
            <p className="text-[10px] font-mono text-gray-500 uppercase">Times Seen</p>
            <p className="text-xl font-mono font-bold text-neon-blue mt-1">{ioc.times_seen}</p>
          </div>
          <div className="p-3 bg-cyber-bg rounded-lg border border-cyber-border text-center">
            <p className="text-[10px] font-mono text-gray-500 uppercase">First Seen</p>
            <p className="text-xs font-mono text-gray-300 mt-2">{formatDate(ioc.first_seen)}</p>
          </div>
          <div className="p-3 bg-cyber-bg rounded-lg border border-cyber-border text-center">
            <p className="text-[10px] font-mono text-gray-500 uppercase">Last Seen</p>
            <p className="text-xs font-mono text-gray-300 mt-2">{formatDate(ioc.last_seen)}</p>
          </div>
        </div>

        {/* Risk bar */}
        <div className="mb-6">
          <div className="flex justify-between text-xs font-mono mb-2">
            <span className="text-gray-400">Risk Assessment</span>
            <span style={{ color: riskLevel.color }}>{riskLevel.label}</span>
          </div>
          <div className="h-2 bg-cyber-bg rounded-full overflow-hidden border border-cyber-border">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${ioc.risk_score}%`,
                backgroundColor: riskLevel.color,
                boxShadow: `0 0 8px ${riskLevel.color}50`,
              }}
            />
          </div>
        </div>

        {/* Tags */}
        {ioc.tags?.length > 0 && (
          <div className="mb-6">
            <p className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-2">Tags</p>
            <div className="flex flex-wrap gap-2">
              {ioc.tags.map((tag) => (
                <span key={tag} className="badge-blue">{tag}</span>
              ))}
            </div>
          </div>
        )}

        {/* Enrichment data */}
        {ioc.enrichment && (
          <div>
            <p className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-3">
              Enrichment Data
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {Object.entries(ioc.enrichment).map(([source, data]) => {
                if (!data) return null;
                return (
                  <div key={source} className="p-3 bg-cyber-bg rounded-lg border border-cyber-border">
                    <h5 className="text-[10px] font-mono text-neon-blue uppercase tracking-wider mb-2 font-semibold">
                      {source}
                    </h5>
                    <div className="space-y-1.5">
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
                );
              })}
            </div>
          </div>
        )}

        {/* External links */}
        <div className="mt-6 flex gap-3">
          {ioc.type === 'ip' && (
            <a
              href={`https://www.virustotal.com/gui/ip-address/${ioc.value}`}
              target="_blank"
              rel="noopener noreferrer"
              className="cyber-button-blue flex items-center gap-2 text-xs"
            >
              <ExternalLink size={12} /> VirusTotal
            </a>
          )}
          {ioc.type === 'domain' && (
            <a
              href={`https://www.virustotal.com/gui/domain/${ioc.value}`}
              target="_blank"
              rel="noopener noreferrer"
              className="cyber-button-blue flex items-center gap-2 text-xs"
            >
              <ExternalLink size={12} /> VirusTotal
            </a>
          )}
          {(ioc.type === 'hash_md5' || ioc.type === 'hash_sha256') && (
            <a
              href={`https://www.virustotal.com/gui/file/${ioc.value}`}
              target="_blank"
              rel="noopener noreferrer"
              className="cyber-button-blue flex items-center gap-2 text-xs"
            >
              <ExternalLink size={12} /> VirusTotal
            </a>
          )}
        </div>
      </div>
    </div>
  );
}

export default function IOCTable() {
  const [iocs, setIOCs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [sortField, setSortField] = useState('risk_score');
  const [sortDir, setSortDir] = useState('desc');
  const [selectedIOC, setSelectedIOC] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 20;

  useEffect(() => {
    const fetchIOCs = async () => {
      try {
        const response = await iocAPI.getAll({ limit: 500 });
        const payload = response.data;
        setIOCs(Array.isArray(payload?.data) ? payload.data : Array.isArray(payload) ? payload : []);
      } catch {
        console.log('[IOCs] Using mock data');
        setIOCs(generateMockIOCs());
      } finally {
        setLoading(false);
      }
    };
    fetchIOCs();
  }, []);

  // Filter and sort
  const processedData = useMemo(() => {
    let result = [...iocs];

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (ioc) =>
          ioc.value?.toLowerCase().includes(q) ||
          ioc.type?.toLowerCase().includes(q) ||
          ioc.tags?.some((t) => t.toLowerCase().includes(q))
      );
    }

    if (typeFilter !== 'all') {
      result = result.filter((ioc) => ioc.type === typeFilter);
    }

    result.sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];
      if (sortField === 'first_seen' || sortField === 'last_seen') {
        aVal = new Date(aVal).getTime();
        bVal = new Date(bVal).getTime();
      }
      if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = (bVal || '').toLowerCase();
      }
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [iocs, searchQuery, typeFilter, sortField, sortDir]);

  const totalPages = Math.max(1, Math.ceil(processedData.length / itemsPerPage));
  const paginatedData = processedData.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, typeFilter]);

  const handleSort = useCallback(
    (field) => {
      if (sortField === field) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
      } else {
        setSortField(field);
        setSortDir('desc');
      }
    },
    [sortField]
  );

  const uniqueTypes = useMemo(() => {
    return [...new Set(iocs.map((ioc) => ioc.type))];
  }, [iocs]);

  return (
    <div className="space-y-6 pb-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
          <Database size={24} className="text-neon-blue" />
          IOC Database
        </h1>
        <p className="text-sm text-gray-500 mt-1 font-mono">
          {processedData.length} indicators of compromise
        </p>
      </div>

      {/* Search and Filters */}
      <div className="cyber-card p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex-1 min-w-[300px] relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              placeholder="Search IOCs by value, type, or tag..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full cyber-input pl-9 pr-8"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2"
              >
                <X size={14} className="text-gray-500 hover:text-neon-red" />
              </button>
            )}
          </div>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="cyber-input min-w-[160px]"
          >
            <option value="all">All Types</option>
            {uniqueTypes.map((type) => (
              <option key={type} value={type}>
                {IOC_TYPES[type]?.label || type}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* IOC Table */}
      <div className="cyber-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="cyber-spinner mr-3" />
            <span className="font-mono text-gray-400 text-sm">Loading IOCs...</span>
          </div>
        ) : paginatedData.length === 0 ? (
          <div className="text-center py-20">
            <Fingerprint size={32} className="text-gray-700 mx-auto mb-3" />
            <p className="font-mono text-gray-500 text-sm">No IOCs found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('value')}
                  >
                    <div className="flex items-center gap-1">
                      Value <ArrowUpDown size={10} />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('type')}
                  >
                    <div className="flex items-center gap-1">
                      Type <ArrowUpDown size={10} />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('risk_score')}
                  >
                    <div className="flex items-center gap-1">
                      Risk Score <ArrowUpDown size={10} />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('times_seen')}
                  >
                    <div className="flex items-center gap-1">
                      Times Seen <ArrowUpDown size={10} />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('first_seen')}
                  >
                    <div className="flex items-center gap-1">
                      First Seen <ArrowUpDown size={10} />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('last_seen')}
                  >
                    <div className="flex items-center gap-1">
                      Last Seen <ArrowUpDown size={10} />
                    </div>
                  </th>
                </tr>
              </thead>
              <tbody>
                {paginatedData.map((ioc) => {
                  const Icon = iocIcons[ioc.type] || Fingerprint;
                  const typeConfig = IOC_TYPES[ioc.type];
                  const riskLevel = getRiskLevel(ioc.risk_score);

                  return (
                    <tr
                      key={ioc.id || ioc.value}
                      className="cursor-pointer"
                      onClick={() => setSelectedIOC(ioc)}
                    >
                      <td>
                        <div className="flex items-center gap-2">
                          <Icon size={13} style={{ color: typeConfig?.color || '#64748b' }} />
                          <span className="text-neon-blue truncate max-w-[280px]">
                            {ioc.value}
                          </span>
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
                          <div className="w-12 h-1.5 bg-cyber-bg rounded-full overflow-hidden">
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
                      <td>{ioc.times_seen}x</td>
                      <td className="text-gray-400">{formatDate(ioc.first_seen)}</td>
                      <td className="text-gray-400">{formatDate(ioc.last_seen)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-cyber-border">
            <span className="text-xs font-mono text-gray-500">
              Showing {(currentPage - 1) * itemsPerPage + 1}-
              {Math.min(currentPage * itemsPerPage, processedData.length)} of{' '}
              {processedData.length}
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="p-1.5 rounded border border-cyber-border hover:border-neon-green/30
                           disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft size={14} className="text-gray-400" />
              </button>
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                let page;
                if (totalPages <= 5) page = i + 1;
                else if (currentPage <= 3) page = i + 1;
                else if (currentPage >= totalPages - 2) page = totalPages - 4 + i;
                else page = currentPage - 2 + i;
                return (
                  <button
                    key={page}
                    onClick={() => setCurrentPage(page)}
                    className={`w-8 h-8 rounded text-xs font-mono transition-colors ${
                      currentPage === page
                        ? 'bg-neon-green/20 text-neon-green border border-neon-green/30'
                        : 'text-gray-400 hover:text-gray-200 border border-transparent'
                    }`}
                  >
                    {page}
                  </button>
                );
              })}
              <button
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="p-1.5 rounded border border-cyber-border hover:border-neon-green/30
                           disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight size={14} className="text-gray-400" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* IOC Detail Modal */}
      {selectedIOC && (
        <IOCDetailPanel ioc={selectedIOC} onClose={() => setSelectedIOC(null)} />
      )}
    </div>
  );
}
