import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  LineChart, Line, XAxis, YAxis, CartesianGrid, Area, AreaChart,
  BarChart, Bar,
} from 'recharts';
import {
  Activity, Shield, ShieldAlert, AlertTriangle, Fingerprint,
  TrendingUp, ArrowRight, Clock, Target, Zap,
} from 'lucide-react';
import { dashboardAPI } from '../utils/api';
import { VERDICTS, CHART_COLORS, formatTimestamp, formatConfidence } from '../utils/constants';
import VerdictBadge from './VerdictBadge';

// --- Mock data generators (used when API is unavailable) ---
const mockStats = {
  total_investigations: 1247,
  true_positives: 312,
  false_positives: 687,
  needs_escalation: 248,
  unique_iocs: 3891,
  avg_confidence: 0.87,
};

const mockVerdictData = [
  { name: 'True Positive', value: 312, key: 'TRUE_POSITIVE' },
  { name: 'False Positive', value: 687, key: 'FALSE_POSITIVE' },
  { name: 'Needs Escalation', value: 248, key: 'NEEDS_ESCALATION' },
];

const mockTimelineData = Array.from({ length: 30 }, (_, i) => {
  const date = new Date();
  date.setDate(date.getDate() - (29 - i));
  return {
    date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
    investigations: Math.floor(Math.random() * 40) + 15,
    true_positive: Math.floor(Math.random() * 15) + 3,
    false_positive: Math.floor(Math.random() * 20) + 8,
  };
});

const mockTopIOCs = [
  { value: '185.220.101.34', type: 'ip', risk_score: 95, times_seen: 47 },
  { value: 'evil-domain.xyz', type: 'domain', risk_score: 92, times_seen: 38 },
  { value: 'a1b2c3d4e5f6...', type: 'hash_sha256', risk_score: 88, times_seen: 31 },
  { value: '103.45.67.89', type: 'ip', risk_score: 85, times_seen: 28 },
  { value: 'malware-c2.net', type: 'domain', risk_score: 82, times_seen: 25 },
  { value: '45.33.32.156', type: 'ip', risk_score: 78, times_seen: 22 },
  { value: 'phish-login.com', type: 'domain', risk_score: 75, times_seen: 19 },
  { value: 'd4e5f6a7b8c9...', type: 'hash_md5', risk_score: 71, times_seen: 16 },
  { value: '192.168.1.100', type: 'ip', risk_score: 68, times_seen: 14 },
  { value: 'dropper.ru', type: 'domain', risk_score: 65, times_seen: 12 },
];

const mockTopTechniques = [
  { id: 'T1566', name: 'Phishing', count: 89 },
  { id: 'T1059', name: 'Command & Scripting', count: 76 },
  { id: 'T1078', name: 'Valid Accounts', count: 64 },
  { id: 'T1071', name: 'Application Layer Protocol', count: 58 },
  { id: 'T1053', name: 'Scheduled Task/Job', count: 45 },
  { id: 'T1027', name: 'Obfuscated Files', count: 41 },
  { id: 'T1105', name: 'Ingress Tool Transfer', count: 38 },
  { id: 'T1021', name: 'Remote Services', count: 34 },
  { id: 'T1083', name: 'File & Directory Discovery', count: 29 },
  { id: 'T1070', name: 'Indicator Removal', count: 25 },
];

const mockRecentInvestigations = [
  { id: 'INV-2024-001', alert_type: 'phishing', verdict: 'TRUE_POSITIVE', confidence: 0.94, created_at: new Date(Date.now() - 1800000).toISOString(), ioc_count: 5 },
  { id: 'INV-2024-002', alert_type: 'edr', verdict: 'FALSE_POSITIVE', confidence: 0.91, created_at: new Date(Date.now() - 3600000).toISOString(), ioc_count: 3 },
  { id: 'INV-2024-003', alert_type: 'siem', verdict: 'NEEDS_ESCALATION', confidence: 0.72, created_at: new Date(Date.now() - 7200000).toISOString(), ioc_count: 8 },
  { id: 'INV-2024-004', alert_type: 'network', verdict: 'TRUE_POSITIVE', confidence: 0.88, created_at: new Date(Date.now() - 14400000).toISOString(), ioc_count: 12 },
  { id: 'INV-2024-005', alert_type: 'firewall', verdict: 'FALSE_POSITIVE', confidence: 0.96, created_at: new Date(Date.now() - 28800000).toISOString(), ioc_count: 2 },
  { id: 'INV-2024-006', alert_type: 'edr', verdict: 'TRUE_POSITIVE', confidence: 0.85, created_at: new Date(Date.now() - 43200000).toISOString(), ioc_count: 7 },
];

// --- Stat Card Component ---
function StatCard({ icon: Icon, label, value, change, color, delay = 0 }) {
  return (
    <div
      className="stat-card animate-fade-in-up"
      style={{ '--accent-color': color, animationDelay: `${delay}ms` }}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-1">
            {label}
          </p>
          <p className="text-2xl font-mono font-bold" style={{ color }}>
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
        </div>
        <div
          className="p-2 rounded-lg"
          style={{ backgroundColor: `${color}15`, border: `1px solid ${color}30` }}
        >
          <Icon size={18} style={{ color }} />
        </div>
      </div>
      {change !== undefined && (
        <div className="mt-3 flex items-center gap-1">
          <TrendingUp size={12} className={change >= 0 ? 'text-neon-green' : 'text-neon-red'} />
          <span className={`text-xs font-mono ${change >= 0 ? 'text-neon-green' : 'text-neon-red'}`}>
            {change >= 0 ? '+' : ''}{change}%
          </span>
          <span className="text-xs text-gray-600 font-mono ml-1">vs last week</span>
        </div>
      )}
    </div>
  );
}

// --- Custom Tooltip ---
function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="cyber-card p-3 shadow-neon-green border-neon-green/20">
      <p className="text-xs font-mono text-gray-400 mb-2">{label}</p>
      {payload.map((entry, i) => (
        <div key={i} className="flex items-center gap-2 text-xs font-mono">
          <div
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="text-gray-400">{entry.name}:</span>
          <span className="font-semibold" style={{ color: entry.color }}>
            {entry.value}
          </span>
        </div>
      ))}
    </div>
  );
}

// --- Main Dashboard ---
export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(mockStats);
  const [verdictData, setVerdictData] = useState(mockVerdictData);
  const [timelineData, setTimelineData] = useState(mockTimelineData);
  const [topIOCs, setTopIOCs] = useState(mockTopIOCs);
  const [topTechniques, setTopTechniques] = useState(mockTopTechniques);
  const [recentInvestigations, setRecentInvestigations] = useState(mockRecentInvestigations);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, verdictsRes, timelineRes, iocsRes, techRes, recentRes] =
          await Promise.allSettled([
            dashboardAPI.getStats(),
            dashboardAPI.getVerdictDistribution(),
            dashboardAPI.getTimeline(30),
            dashboardAPI.getTopIOCs(10),
            dashboardAPI.getTopTechniques(10),
            dashboardAPI.getRecentInvestigations(10),
          ]);

        if (statsRes.status === 'fulfilled') setStats(statsRes.value.data);
        if (verdictsRes.status === 'fulfilled') setVerdictData(verdictsRes.value.data);
        if (timelineRes.status === 'fulfilled') setTimelineData(timelineRes.value.data);
        if (iocsRes.status === 'fulfilled') setTopIOCs(iocsRes.value.data);
        if (techRes.status === 'fulfilled') setTopTechniques(techRes.value.data);
        if (recentRes.status === 'fulfilled') setRecentInvestigations(recentRes.value.data);
      } catch (err) {
        console.log('[Dashboard] Using mock data - API unavailable');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const verdictColors = verdictData.map(
    (v) => VERDICTS[v.key]?.color || '#64748b'
  );

  return (
    <div className="space-y-6 pb-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
            <Activity size={24} className="text-neon-green" />
            Threat Operations Dashboard
          </h1>
          <p className="text-sm text-gray-500 mt-1 font-mono">
            Real-time security posture overview
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-neon-green/10 border border-neon-green/20">
            <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
            <span className="text-xs font-mono text-neon-green">LIVE</span>
          </div>
          <button
            onClick={() => navigate('/investigate')}
            className="cyber-button-primary flex items-center gap-2"
          >
            <Zap size={14} />
            New Investigation
          </button>
        </div>
      </div>

      {/* Stat Cards Row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard
          icon={Activity}
          label="Total Investigations"
          value={stats.total_investigations}
          change={12}
          color="#00d4ff"
          delay={0}
        />
        <StatCard
          icon={ShieldAlert}
          label="True Positives"
          value={stats.true_positives}
          change={-5}
          color="#ef4444"
          delay={50}
        />
        <StatCard
          icon={Shield}
          label="False Positives"
          value={stats.false_positives}
          change={8}
          color="#00ff88"
          delay={100}
        />
        <StatCard
          icon={AlertTriangle}
          label="Needs Escalation"
          value={stats.needs_escalation}
          change={3}
          color="#eab308"
          delay={150}
        />
        <StatCard
          icon={Fingerprint}
          label="Unique IOCs"
          value={stats.unique_iocs}
          change={15}
          color="#a855f7"
          delay={200}
        />
        <StatCard
          icon={Target}
          label="Avg Confidence"
          value={formatConfidence(stats.avg_confidence)}
          color="#00ff88"
          delay={250}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Verdict Distribution Donut */}
        <div className="cyber-card p-5">
          <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider mb-4">
            Verdict Distribution
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={verdictData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={4}
                  dataKey="value"
                  stroke="none"
                >
                  {verdictData.map((entry, index) => (
                    <Cell
                      key={entry.key}
                      fill={verdictColors[index]}
                      opacity={0.85}
                    />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          {/* Legend */}
          <div className="flex flex-wrap gap-4 justify-center mt-2">
            {verdictData.map((v, i) => (
              <div key={v.key} className="flex items-center gap-2">
                <div
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: verdictColors[i] }}
                />
                <span className="text-xs font-mono text-gray-400">
                  {v.name} ({v.value})
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Timeline Area Chart */}
        <div className="cyber-card p-5 lg:col-span-2">
          <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider mb-4">
            Investigation Timeline (30 Days)
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData}>
                <defs>
                  <linearGradient id="gradInvestigations" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradTP" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="date"
                  stroke="#334155"
                  tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false}
                />
                <YAxis
                  stroke="#334155"
                  tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Area
                  type="monotone"
                  dataKey="investigations"
                  name="Total"
                  stroke="#00d4ff"
                  fill="url(#gradInvestigations)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="true_positive"
                  name="True Positive"
                  stroke="#ef4444"
                  fill="url(#gradTP)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* IOCs and Techniques Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top 10 IOCs Table */}
        <div className="cyber-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider">
              Top 10 IOCs
            </h3>
            <button
              onClick={() => navigate('/iocs')}
              className="text-xs font-mono text-neon-blue hover:text-neon-green transition-colors flex items-center gap-1"
            >
              View All <ArrowRight size={12} />
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>IOC Value</th>
                  <th>Type</th>
                  <th>Risk</th>
                  <th>Seen</th>
                </tr>
              </thead>
              <tbody>
                {topIOCs.map((ioc, i) => (
                  <tr key={i} className="cursor-pointer" onClick={() => navigate('/iocs')}>
                    <td className="text-neon-blue">{ioc.value}</td>
                    <td>
                      <span className="badge-blue">{ioc.type}</span>
                    </td>
                    <td>
                      <span
                        className="font-bold"
                        style={{
                          color:
                            ioc.risk_score >= 80
                              ? '#ef4444'
                              : ioc.risk_score >= 60
                              ? '#f97316'
                              : ioc.risk_score >= 40
                              ? '#eab308'
                              : '#00ff88',
                        }}
                      >
                        {ioc.risk_score}
                      </span>
                    </td>
                    <td>{ioc.times_seen}x</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top 10 ATT&CK Techniques Bar Chart */}
        <div className="cyber-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider">
              Top ATT&CK Techniques
            </h3>
            <button
              onClick={() => navigate('/attack-map')}
              className="text-xs font-mono text-neon-blue hover:text-neon-green transition-colors flex items-center gap-1"
            >
              Full Map <ArrowRight size={12} />
            </button>
          </div>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topTechniques} layout="vertical" margin={{ left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis
                  type="number"
                  stroke="#334155"
                  tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false}
                />
                <YAxis
                  dataKey="id"
                  type="category"
                  width={55}
                  stroke="#334155"
                  tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar
                  dataKey="count"
                  name="Occurrences"
                  fill="#00ff88"
                  radius={[0, 4, 4, 0]}
                  opacity={0.8}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Investigations */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider">
            Recent Investigations
          </h3>
          <button
            onClick={() => navigate('/history')}
            className="text-xs font-mono text-neon-blue hover:text-neon-green transition-colors flex items-center gap-1"
          >
            View All <ArrowRight size={12} />
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Investigation ID</th>
                <th>Time</th>
                <th>Alert Type</th>
                <th>Verdict</th>
                <th>Confidence</th>
                <th>IOCs</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {recentInvestigations.map((inv) => (
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
                      confidence={inv.confidence}
                      size="sm"
                      showConfidence={false}
                    />
                  </td>
                  <td>
                    <span className="text-neon-green font-bold">
                      {formatConfidence(inv.confidence)}
                    </span>
                  </td>
                  <td>{inv.ioc_count}</td>
                  <td>
                    <ArrowRight size={14} className="text-gray-600" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
