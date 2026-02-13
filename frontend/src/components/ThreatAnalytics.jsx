import React, { useState, useEffect } from 'react';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, RadarChart, Radar, PolarGrid, PolarAngleAxis,
  PolarRadiusAxis,
} from 'recharts';
import {
  BarChart3, TrendingUp, Shield, Globe, Clock,
  Target, Crosshair, AlertTriangle,
} from 'lucide-react';
import { analyticsAPI } from '../utils/api';
import { CHART_COLORS } from '../utils/constants';

// Mock analytics data
const mockTopAttackers = [
  { ip: '185.220.101.34', country: 'DE', attacks: 47, last_seen: '2h ago' },
  { ip: '103.45.67.89', country: 'CN', attacks: 38, last_seen: '4h ago' },
  { ip: '91.234.56.78', country: 'RU', attacks: 31, last_seen: '1h ago' },
  { ip: '45.33.32.156', country: 'US', attacks: 28, last_seen: '6h ago' },
  { ip: '198.51.100.10', country: 'NL', attacks: 25, last_seen: '3h ago' },
  { ip: '203.0.113.42', country: 'KR', attacks: 22, last_seen: '5h ago' },
  { ip: '45.77.123.45', country: 'SG', attacks: 19, last_seen: '8h ago' },
  { ip: '172.217.14.100', country: 'US', attacks: 15, last_seen: '12h ago' },
];

const mockTrends = Array.from({ length: 14 }, (_, i) => {
  const date = new Date();
  date.setDate(date.getDate() - (13 - i));
  return {
    date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
    phishing: Math.floor(Math.random() * 20) + 5,
    malware: Math.floor(Math.random() * 15) + 3,
    bruteforce: Math.floor(Math.random() * 10) + 2,
    c2: Math.floor(Math.random() * 8) + 1,
    exfiltration: Math.floor(Math.random() * 5),
  };
});

const mockSeverityDist = [
  { name: 'Critical', value: 89, color: '#ef4444' },
  { name: 'High', value: 156, color: '#f97316' },
  { name: 'Medium', value: 234, color: '#eab308' },
  { name: 'Low', value: 412, color: '#00d4ff' },
  { name: 'Info', value: 356, color: '#64748b' },
];

const mockAttackCategories = [
  { category: 'Phishing', count: 312 },
  { category: 'Malware', count: 245 },
  { category: 'Brute Force', count: 189 },
  { category: 'C2 Traffic', count: 134 },
  { category: 'Data Exfil', count: 98 },
  { category: 'Lateral Movement', count: 76 },
  { category: 'Privilege Esc', count: 67 },
  { category: 'Reconnaissance', count: 54 },
];

const mockRadarData = [
  { skill: 'Detection Rate', A: 92, fullMark: 100 },
  { skill: 'Response Time', A: 88, fullMark: 100 },
  { skill: 'False Positive Rate', A: 78, fullMark: 100 },
  { skill: 'Coverage', A: 85, fullMark: 100 },
  { skill: 'Accuracy', A: 91, fullMark: 100 },
  { skill: 'Enrichment', A: 87, fullMark: 100 },
];

const mockHourlyActivity = Array.from({ length: 24 }, (_, i) => ({
  hour: `${String(i).padStart(2, '0')}:00`,
  alerts: Math.floor(Math.random() * 30) + (i >= 8 && i <= 18 ? 20 : 5),
  investigations: Math.floor(Math.random() * 15) + (i >= 8 && i <= 18 ? 10 : 2),
}));

// Custom chart tooltip
function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="cyber-card p-3 shadow-lg border-neon-green/20">
      <p className="text-xs font-mono text-gray-400 mb-2">{label}</p>
      {payload.map((entry, i) => (
        <div key={i} className="flex items-center gap-2 text-xs font-mono">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
          <span className="text-gray-400">{entry.name}:</span>
          <span className="font-semibold" style={{ color: entry.color }}>
            {entry.value}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function ThreatAnalytics() {
  const [topAttackers, setTopAttackers] = useState(mockTopAttackers);
  const [trends, setTrends] = useState(mockTrends);
  const [severityDist, setSeverityDist] = useState(mockSeverityDist);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(14);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [attackersRes, trendsRes, severityRes] = await Promise.allSettled([
          analyticsAPI.getTopAttackers(timeRange),
          analyticsAPI.getTrends(timeRange),
          analyticsAPI.getSeverityDistribution(),
        ]);
        if (attackersRes.status === 'fulfilled') setTopAttackers(attackersRes.value.data);
        if (trendsRes.status === 'fulfilled') setTrends(trendsRes.value.data);
        if (severityRes.status === 'fulfilled') setSeverityDist(severityRes.value.data);
      } catch {
        console.log('[Analytics] Using mock data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [timeRange]);

  return (
    <div className="space-y-6 pb-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
            <BarChart3 size={24} className="text-neon-blue" />
            Threat Analytics
          </h1>
          <p className="text-sm text-gray-500 mt-1 font-mono">
            Advanced security metrics and threat intelligence
          </p>
        </div>
        <div className="flex items-center gap-2">
          {[7, 14, 30, 90].map((days) => (
            <button
              key={days}
              onClick={() => setTimeRange(days)}
              className={`px-3 py-1.5 text-xs font-mono rounded-md transition-colors ${
                timeRange === days
                  ? 'bg-neon-green/15 text-neon-green border border-neon-green/30'
                  : 'text-gray-500 hover:text-gray-300 border border-cyber-border'
              }`}
            >
              {days}D
            </button>
          ))}
        </div>
      </div>

      {/* Top stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="stat-card" style={{ '--accent-color': '#ef4444' }}>
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-neon-red" />
            <span className="text-[10px] font-mono text-gray-500 uppercase">Critical Threats</span>
          </div>
          <p className="text-2xl font-mono font-bold text-neon-red">89</p>
          <p className="text-[10px] font-mono text-gray-600 mt-1">+12% from last period</p>
        </div>
        <div className="stat-card" style={{ '--accent-color': '#00ff88' }}>
          <div className="flex items-center gap-2 mb-2">
            <Shield size={14} className="text-neon-green" />
            <span className="text-[10px] font-mono text-gray-500 uppercase">Threats Blocked</span>
          </div>
          <p className="text-2xl font-mono font-bold text-neon-green">1,247</p>
          <p className="text-[10px] font-mono text-gray-600 mt-1">Automated response</p>
        </div>
        <div className="stat-card" style={{ '--accent-color': '#00d4ff' }}>
          <div className="flex items-center gap-2 mb-2">
            <Clock size={14} className="text-neon-blue" />
            <span className="text-[10px] font-mono text-gray-500 uppercase">Avg Response</span>
          </div>
          <p className="text-2xl font-mono font-bold text-neon-blue">23s</p>
          <p className="text-[10px] font-mono text-gray-600 mt-1">Mean time to verdict</p>
        </div>
        <div className="stat-card" style={{ '--accent-color': '#a855f7' }}>
          <div className="flex items-center gap-2 mb-2">
            <Crosshair size={14} className="text-neon-purple" />
            <span className="text-[10px] font-mono text-gray-500 uppercase">Unique Attackers</span>
          </div>
          <p className="text-2xl font-mono font-bold text-neon-purple">156</p>
          <p className="text-[10px] font-mono text-gray-600 mt-1">Distinct source IPs</p>
        </div>
      </div>

      {/* Threat trends + Severity distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Attack trends (stacked area) */}
        <div className="cyber-card p-5 lg:col-span-2">
          <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <TrendingUp size={14} className="text-neon-green" />
            Attack Category Trends
          </h3>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trends}>
                <defs>
                  {['phishing', 'malware', 'bruteforce', 'c2', 'exfiltration'].map((key, i) => (
                    <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={CHART_COLORS[i]} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={CHART_COLORS[i]} stopOpacity={0} />
                    </linearGradient>
                  ))}
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
                <Area type="monotone" dataKey="phishing" name="Phishing" stroke={CHART_COLORS[0]} fill={`url(#grad-phishing)`} strokeWidth={2} />
                <Area type="monotone" dataKey="malware" name="Malware" stroke={CHART_COLORS[1]} fill={`url(#grad-malware)`} strokeWidth={2} />
                <Area type="monotone" dataKey="bruteforce" name="Brute Force" stroke={CHART_COLORS[2]} fill={`url(#grad-bruteforce)`} strokeWidth={2} />
                <Area type="monotone" dataKey="c2" name="C2 Traffic" stroke={CHART_COLORS[3]} fill={`url(#grad-c2)`} strokeWidth={2} />
                <Area type="monotone" dataKey="exfiltration" name="Exfiltration" stroke={CHART_COLORS[4]} fill={`url(#grad-exfiltration)`} strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity distribution donut */}
        <div className="cyber-card p-5">
          <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider mb-4">
            Severity Distribution
          </h3>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityDist}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="none"
                >
                  {severityDist.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} opacity={0.85} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="space-y-2 mt-2">
            {severityDist.map((item) => (
              <div key={item.name} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-xs font-mono text-gray-400">{item.name}</span>
                </div>
                <span className="text-xs font-mono font-semibold" style={{ color: item.color }}>
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Attackers + Attack Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Attackers */}
        <div className="cyber-card p-5">
          <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Globe size={14} className="text-neon-red" />
            Top Threat Sources
          </h3>
          <div className="overflow-x-auto">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Source IP</th>
                  <th>Country</th>
                  <th>Attacks</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {topAttackers.map((attacker, i) => (
                  <tr key={attacker.ip}>
                    <td>
                      <span className={`font-bold ${i < 3 ? 'text-neon-red' : 'text-gray-500'}`}>
                        {i + 1}
                      </span>
                    </td>
                    <td className="text-neon-blue">{attacker.ip}</td>
                    <td>
                      <span className="badge-blue">{attacker.country}</span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-12 h-1.5 bg-cyber-bg rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full bg-neon-red"
                            style={{
                              width: `${(attacker.attacks / topAttackers[0].attacks) * 100}%`,
                            }}
                          />
                        </div>
                        <span className="text-neon-red font-bold">{attacker.attacks}</span>
                      </div>
                    </td>
                    <td className="text-gray-500">{attacker.last_seen}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Attack Categories bar chart */}
        <div className="cyber-card p-5">
          <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Target size={14} className="text-neon-purple" />
            Attack Categories
          </h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={mockAttackCategories} layout="vertical" margin={{ left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis
                  type="number"
                  stroke="#334155"
                  tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false}
                />
                <YAxis
                  dataKey="category"
                  type="category"
                  width={110}
                  stroke="#334155"
                  tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" name="Occurrences" radius={[0, 4, 4, 0]} opacity={0.85}>
                  {mockAttackCategories.map((_, i) => (
                    <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Hourly Activity + Performance Radar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Hourly Activity */}
        <div className="cyber-card p-5 lg:col-span-2">
          <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Clock size={14} className="text-neon-blue" />
            24-Hour Activity Pattern
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={mockHourlyActivity}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="hour"
                  stroke="#334155"
                  tick={{ fill: '#64748b', fontSize: 9, fontFamily: 'JetBrains Mono' }}
                  tickLine={false}
                  interval={2}
                />
                <YAxis
                  stroke="#334155"
                  tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickLine={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="alerts" name="Alerts" fill="#00d4ff" opacity={0.6} radius={[2, 2, 0, 0]} />
                <Bar dataKey="investigations" name="Investigations" fill="#00ff88" opacity={0.8} radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Performance Radar */}
        <div className="cyber-card p-5">
          <h3 className="text-sm font-mono font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Shield size={14} className="text-neon-green" />
            SOC Performance
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={mockRadarData}>
                <PolarGrid stroke="#1e293b" />
                <PolarAngleAxis
                  dataKey="skill"
                  tick={{ fill: '#64748b', fontSize: 9, fontFamily: 'JetBrains Mono' }}
                />
                <PolarRadiusAxis
                  angle={90}
                  domain={[0, 100]}
                  tick={{ fill: '#475569', fontSize: 8 }}
                />
                <Radar
                  name="Performance"
                  dataKey="A"
                  stroke="#00ff88"
                  fill="#00ff88"
                  fillOpacity={0.15}
                  strokeWidth={2}
                />
                <Tooltip content={<CustomTooltip />} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-3 text-center">
            <span className="text-xs font-mono text-gray-500">
              Overall Score:{' '}
              <span className="text-neon-green font-bold">
                {Math.round(mockRadarData.reduce((s, d) => s + d.A, 0) / mockRadarData.length)}%
              </span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
