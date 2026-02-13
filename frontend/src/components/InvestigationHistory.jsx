import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  History, Search, Filter, ChevronUp, ChevronDown,
  ChevronLeft, ChevronRight, ArrowRight, Clock,
  SortAsc, SortDesc, X,
} from 'lucide-react';
import { investigationAPI } from '../utils/api';
import { VERDICTS, ALERT_TYPES, formatTimestamp, formatConfidence } from '../utils/constants';
import VerdictBadge from './VerdictBadge';

// Mock data for when API is unavailable
const generateMockData = () => {
  const verdictKeys = ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'NEEDS_ESCALATION'];
  const alertTypes = ['siem', 'edr', 'phishing', 'network', 'firewall'];
  return Array.from({ length: 57 }, (_, i) => ({
    id: `INV-2024-${String(i + 1).padStart(3, '0')}`,
    alert_type: alertTypes[Math.floor(Math.random() * alertTypes.length)],
    verdict: verdictKeys[Math.floor(Math.random() * verdictKeys.length)],
    confidence: 0.6 + Math.random() * 0.4,
    ioc_count: Math.floor(Math.random() * 15) + 1,
    technique_count: Math.floor(Math.random() * 8),
    created_at: new Date(Date.now() - Math.random() * 30 * 86400000).toISOString(),
    summary: 'Automated investigation of security alert',
  }));
};

export default function InvestigationHistory() {
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [sortField, setSortField] = useState('created_at');
  const [sortDir, setSortDir] = useState('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 15;

  useEffect(() => {
    const fetchInvestigations = async () => {
      try {
        const response = await investigationAPI.getAll({
          page: 1,
          limit: 200,
        });
        const payload = response.data;
        setInvestigations(Array.isArray(payload?.data) ? payload.data : Array.isArray(payload) ? payload : []);
      } catch {
        console.log('[History] Using mock data');
        setInvestigations(generateMockData());
      } finally {
        setLoading(false);
      }
    };
    fetchInvestigations();
  }, []);

  // Filtered and sorted data
  const processedData = useMemo(() => {
    let result = [...investigations];

    // Search filter
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (inv) =>
          inv.id?.toLowerCase().includes(q) ||
          inv.alert_type?.toLowerCase().includes(q) ||
          inv.summary?.toLowerCase().includes(q)
      );
    }

    // Verdict filter
    if (verdictFilter !== 'all') {
      result = result.filter((inv) => inv.verdict === verdictFilter);
    }

    // Type filter
    if (typeFilter !== 'all') {
      result = result.filter((inv) => inv.alert_type === typeFilter);
    }

    // Sort
    result.sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];

      if (sortField === 'created_at') {
        aVal = new Date(aVal).getTime();
        bVal = new Date(bVal).getTime();
      }
      if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }

      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [investigations, searchQuery, verdictFilter, typeFilter, sortField, sortDir]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(processedData.length / itemsPerPage));
  const paginatedData = processedData.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, verdictFilter, typeFilter]);

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

  const SortIcon = ({ field }) => {
    if (sortField !== field) return <SortAsc size={10} className="text-gray-700" />;
    return sortDir === 'asc' ? (
      <ChevronUp size={12} className="text-neon-green" />
    ) : (
      <ChevronDown size={12} className="text-neon-green" />
    );
  };

  const clearFilters = () => {
    setSearchQuery('');
    setVerdictFilter('all');
    setTypeFilter('all');
    setSortField('created_at');
    setSortDir('desc');
  };

  const hasActiveFilters = searchQuery || verdictFilter !== 'all' || typeFilter !== 'all';

  return (
    <div className="space-y-6 pb-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
            <History size={24} className="text-neon-blue" />
            Investigation History
          </h1>
          <p className="text-sm text-gray-500 mt-1 font-mono">
            {processedData.length} investigation{processedData.length !== 1 ? 's' : ''} found
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="cyber-card p-4">
        <div className="flex flex-wrap items-center gap-4">
          {/* Search */}
          <div className="flex-1 min-w-[250px] relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              placeholder="Search investigations..."
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

          {/* Verdict filter */}
          <select
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
            className="cyber-input min-w-[160px]"
          >
            <option value="all">All Verdicts</option>
            {Object.entries(VERDICTS).map(([key, config]) => (
              <option key={key} value={key}>
                {config.label}
              </option>
            ))}
          </select>

          {/* Type filter */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="cyber-input min-w-[160px]"
          >
            <option value="all">All Types</option>
            {ALERT_TYPES.map((type) => (
              <option key={type.value} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>

          {/* Clear filters */}
          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="text-xs font-mono text-gray-400 hover:text-neon-red transition-colors flex items-center gap-1"
            >
              <X size={12} /> Clear
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="cyber-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="cyber-spinner mr-3" />
            <span className="font-mono text-gray-400 text-sm">Loading investigations...</span>
          </div>
        ) : paginatedData.length === 0 ? (
          <div className="text-center py-20">
            <Search size={32} className="text-gray-700 mx-auto mb-3" />
            <p className="font-mono text-gray-500 text-sm">No investigations found</p>
            <p className="font-mono text-gray-700 text-xs mt-1">
              Try adjusting your filters
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('id')}
                  >
                    <div className="flex items-center gap-1">
                      ID <SortIcon field="id" />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('created_at')}
                  >
                    <div className="flex items-center gap-1">
                      Date <SortIcon field="created_at" />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('alert_type')}
                  >
                    <div className="flex items-center gap-1">
                      Alert Type <SortIcon field="alert_type" />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('verdict')}
                  >
                    <div className="flex items-center gap-1">
                      Verdict <SortIcon field="verdict" />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:text-neon-green transition-colors"
                    onClick={() => handleSort('confidence')}
                  >
                    <div className="flex items-center gap-1">
                      Confidence <SortIcon field="confidence" />
                    </div>
                  </th>
                  <th>IOCs</th>
                  <th>Techniques</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {paginatedData.map((inv) => (
                  <tr
                    key={inv.id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/investigation/${inv.id}`)}
                  >
                    <td className="text-neon-blue font-semibold">{inv.id}</td>
                    <td className="text-gray-400">
                      <div className="flex items-center gap-1.5">
                        <Clock size={11} className="text-gray-600" />
                        {formatTimestamp(inv.created_at)}
                      </div>
                    </td>
                    <td>
                      <span className="badge-blue">{inv.alert_type}</span>
                    </td>
                    <td>
                      <VerdictBadge
                        verdict={inv.verdict}
                        size="sm"
                        showConfidence={false}
                      />
                    </td>
                    <td>
                      <span className="text-neon-green font-bold">
                        {formatConfidence(inv.confidence)}
                      </span>
                    </td>
                    <td>{inv.ioc_count || 0}</td>
                    <td>{inv.technique_count || 0}</td>
                    <td>
                      <ArrowRight size={14} className="text-gray-600" />
                    </td>
                  </tr>
                ))}
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
                if (totalPages <= 5) {
                  page = i + 1;
                } else if (currentPage <= 3) {
                  page = i + 1;
                } else if (currentPage >= totalPages - 2) {
                  page = totalPages - 4 + i;
                } else {
                  page = currentPage - 2 + i;
                }
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
    </div>
  );
}
