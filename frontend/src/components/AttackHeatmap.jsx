import React, { useState, useEffect, useMemo } from 'react';
import { Grid3x3, ExternalLink, X, Shield, Target } from 'lucide-react';
import { mitreAPI } from '../utils/api';
import { MITRE_TACTICS } from '../utils/constants';

// Mock heatmap data for demonstration
const generateMockHeatmapData = () => {
  const techniques = {
    'Reconnaissance': [
      { id: 'T1595', name: 'Active Scanning', count: 12 },
      { id: 'T1592', name: 'Gather Victim Host Info', count: 8 },
      { id: 'T1589', name: 'Gather Victim Identity', count: 5 },
      { id: 'T1590', name: 'Gather Victim Network', count: 3 },
    ],
    'Resource Development': [
      { id: 'T1583', name: 'Acquire Infrastructure', count: 6 },
      { id: 'T1587', name: 'Develop Capabilities', count: 4 },
      { id: 'T1585', name: 'Establish Accounts', count: 2 },
    ],
    'Initial Access': [
      { id: 'T1566', name: 'Phishing', count: 89 },
      { id: 'T1190', name: 'Exploit Public-Facing App', count: 34 },
      { id: 'T1078', name: 'Valid Accounts', count: 64 },
      { id: 'T1133', name: 'External Remote Services', count: 18 },
      { id: 'T1199', name: 'Trusted Relationship', count: 7 },
    ],
    'Execution': [
      { id: 'T1059', name: 'Command & Scripting', count: 76 },
      { id: 'T1204', name: 'User Execution', count: 45 },
      { id: 'T1053', name: 'Scheduled Task/Job', count: 38 },
      { id: 'T1047', name: 'WMI', count: 22 },
      { id: 'T1569', name: 'System Services', count: 15 },
    ],
    'Persistence': [
      { id: 'T1547', name: 'Boot/Logon Autostart', count: 31 },
      { id: 'T1053', name: 'Scheduled Task/Job', count: 45 },
      { id: 'T1136', name: 'Create Account', count: 19 },
      { id: 'T1543', name: 'Create/Modify System Process', count: 14 },
      { id: 'T1546', name: 'Event Triggered Execution', count: 11 },
    ],
    'Privilege Escalation': [
      { id: 'T1548', name: 'Abuse Elevation Control', count: 27 },
      { id: 'T1134', name: 'Access Token Manipulation', count: 16 },
      { id: 'T1068', name: 'Exploitation for Priv Esc', count: 12 },
      { id: 'T1078', name: 'Valid Accounts', count: 64 },
    ],
    'Defense Evasion': [
      { id: 'T1027', name: 'Obfuscated Files', count: 41 },
      { id: 'T1070', name: 'Indicator Removal', count: 25 },
      { id: 'T1055', name: 'Process Injection', count: 33 },
      { id: 'T1036', name: 'Masquerading', count: 29 },
      { id: 'T1562', name: 'Impair Defenses', count: 20 },
      { id: 'T1112', name: 'Modify Registry', count: 17 },
    ],
    'Credential Access': [
      { id: 'T1003', name: 'OS Credential Dumping', count: 36 },
      { id: 'T1110', name: 'Brute Force', count: 42 },
      { id: 'T1555', name: 'Credentials from Stores', count: 15 },
      { id: 'T1056', name: 'Input Capture', count: 9 },
    ],
    'Discovery': [
      { id: 'T1083', name: 'File & Directory Discovery', count: 29 },
      { id: 'T1057', name: 'Process Discovery', count: 24 },
      { id: 'T1082', name: 'System Info Discovery', count: 21 },
      { id: 'T1018', name: 'Remote System Discovery', count: 16 },
      { id: 'T1016', name: 'System Network Config', count: 13 },
    ],
    'Lateral Movement': [
      { id: 'T1021', name: 'Remote Services', count: 34 },
      { id: 'T1570', name: 'Lateral Tool Transfer', count: 18 },
      { id: 'T1080', name: 'Taint Shared Content', count: 7 },
    ],
    'Collection': [
      { id: 'T1005', name: 'Data from Local System', count: 22 },
      { id: 'T1039', name: 'Data from Network Shared', count: 11 },
      { id: 'T1114', name: 'Email Collection', count: 19 },
      { id: 'T1074', name: 'Data Staged', count: 14 },
    ],
    'Command and Control': [
      { id: 'T1071', name: 'Application Layer Protocol', count: 58 },
      { id: 'T1105', name: 'Ingress Tool Transfer', count: 38 },
      { id: 'T1573', name: 'Encrypted Channel', count: 27 },
      { id: 'T1572', name: 'Protocol Tunneling', count: 15 },
      { id: 'T1090', name: 'Proxy', count: 20 },
    ],
    'Exfiltration': [
      { id: 'T1041', name: 'Exfil Over C2 Channel', count: 23 },
      { id: 'T1048', name: 'Exfil Over Alt Protocol', count: 12 },
      { id: 'T1567', name: 'Exfil Over Web Service', count: 9 },
    ],
    'Impact': [
      { id: 'T1486', name: 'Data Encrypted for Impact', count: 8 },
      { id: 'T1489', name: 'Service Stop', count: 6 },
      { id: 'T1490', name: 'Inhibit System Recovery', count: 5 },
      { id: 'T1529', name: 'System Shutdown/Reboot', count: 3 },
    ],
  };

  return techniques;
};

function getHeatColor(count, maxCount) {
  if (count === 0) return { bg: 'rgba(30, 41, 59, 0.5)', text: '#475569' };
  const intensity = Math.min(count / maxCount, 1);

  if (intensity > 0.8) return { bg: 'rgba(0, 255, 136, 0.35)', text: '#00ff88' };
  if (intensity > 0.6) return { bg: 'rgba(0, 255, 136, 0.25)', text: '#00ff88' };
  if (intensity > 0.4) return { bg: 'rgba(0, 255, 136, 0.18)', text: '#00ff88cc' };
  if (intensity > 0.2) return { bg: 'rgba(0, 255, 136, 0.10)', text: '#00ff88aa' };
  return { bg: 'rgba(0, 255, 136, 0.05)', text: '#00ff8866' };
}

function TechniqueCell({ technique, maxCount, onClick }) {
  const colors = getHeatColor(technique.count, maxCount);

  return (
    <button
      onClick={() => onClick(technique)}
      className="w-full text-left p-2 rounded border border-cyber-border/50
                 hover:border-neon-green/40 transition-all duration-200
                 hover:scale-[1.02] hover:z-10 relative group"
      style={{ backgroundColor: colors.bg }}
    >
      <div className="text-[10px] font-mono font-semibold" style={{ color: colors.text }}>
        {technique.id}
      </div>
      <div className="text-[9px] font-mono text-gray-500 truncate mt-0.5">
        {technique.name}
      </div>
      <div className="text-[10px] font-mono font-bold mt-1" style={{ color: colors.text }}>
        {technique.count}
      </div>

      {/* Hover tooltip */}
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2
                      bg-cyber-surface border border-cyber-border rounded-lg shadow-lg
                      opacity-0 group-hover:opacity-100 transition-opacity duration-200
                      pointer-events-none z-50 whitespace-nowrap">
        <div className="text-xs font-mono text-neon-green font-semibold">{technique.id}</div>
        <div className="text-xs font-mono text-gray-300">{technique.name}</div>
        <div className="text-[10px] font-mono text-gray-500 mt-1">
          {technique.count} occurrences
        </div>
      </div>
    </button>
  );
}

export default function AttackHeatmap() {
  const [heatmapData, setHeatmapData] = useState({});
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await mitreAPI.getHeatmap();
        setHeatmapData(response.data);
      } catch {
        console.log('[Heatmap] Using mock data');
        setHeatmapData(generateMockHeatmapData());
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const maxCount = useMemo(() => {
    let max = 0;
    Object.values(heatmapData).forEach((techniques) => {
      techniques.forEach((t) => {
        if (t.count > max) max = t.count;
      });
    });
    return max || 1;
  }, [heatmapData]);

  const totalTechniques = useMemo(() => {
    return Object.values(heatmapData).reduce((sum, techs) => sum + techs.length, 0);
  }, [heatmapData]);

  const totalOccurrences = useMemo(() => {
    return Object.values(heatmapData).reduce(
      (sum, techs) => sum + techs.reduce((s, t) => s + t.count, 0),
      0
    );
  }, [heatmapData]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="cyber-spinner mr-3" />
        <span className="font-mono text-gray-400">Loading ATT&CK data...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
            <Grid3x3 size={24} className="text-neon-green" />
            MITRE ATT&CK Heatmap
          </h1>
          <p className="text-sm text-gray-500 mt-1 font-mono">
            Technique frequency across all investigations
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="stat-card !p-3" style={{ '--accent-color': '#00ff88' }}>
            <p className="text-[10px] font-mono text-gray-500">Techniques</p>
            <p className="text-lg font-mono font-bold text-neon-green">{totalTechniques}</p>
          </div>
          <div className="stat-card !p-3" style={{ '--accent-color': '#00d4ff' }}>
            <p className="text-[10px] font-mono text-gray-500">Total Hits</p>
            <p className="text-lg font-mono font-bold text-neon-blue">{totalOccurrences}</p>
          </div>
        </div>
      </div>

      {/* Legend */}
      <div className="cyber-card p-3">
        <div className="flex items-center gap-6">
          <span className="text-xs font-mono text-gray-500">Frequency:</span>
          <div className="flex items-center gap-2">
            {[
              { label: 'Low', bg: 'rgba(0, 255, 136, 0.05)' },
              { label: '', bg: 'rgba(0, 255, 136, 0.10)' },
              { label: '', bg: 'rgba(0, 255, 136, 0.18)' },
              { label: '', bg: 'rgba(0, 255, 136, 0.25)' },
              { label: 'High', bg: 'rgba(0, 255, 136, 0.35)' },
            ].map((item, i) => (
              <div key={i} className="flex items-center gap-1">
                <div
                  className="w-6 h-4 rounded border border-cyber-border"
                  style={{ backgroundColor: item.bg }}
                />
                {item.label && (
                  <span className="text-[10px] font-mono text-gray-500">{item.label}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Heatmap Grid */}
      <div className="overflow-x-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 gap-4 min-w-[800px]">
          {Object.entries(heatmapData).map(([tactic, techniques]) => (
            <div key={tactic} className="cyber-card p-3">
              {/* Tactic header */}
              <div className="flex items-center gap-2 mb-3 pb-2 border-b border-cyber-border">
                <Target size={12} className="text-neon-blue" />
                <h3 className="text-[11px] font-mono font-bold text-neon-blue uppercase tracking-wider">
                  {tactic}
                </h3>
                <span className="text-[10px] font-mono text-gray-600 ml-auto">
                  ({techniques.length})
                </span>
              </div>

              {/* Technique cells */}
              <div className="space-y-1.5">
                {techniques
                  .sort((a, b) => b.count - a.count)
                  .map((tech) => (
                    <TechniqueCell
                      key={`${tactic}-${tech.id}`}
                      technique={tech}
                      maxCount={maxCount}
                      onClick={setSelectedTechnique}
                    />
                  ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="cyber-card p-6 max-w-lg w-full mx-4 border-neon-green/30 shadow-neon-green animate-fade-in">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-neon-green/10 rounded-lg border border-neon-green/20">
                  <Shield size={18} className="text-neon-green" />
                </div>
                <div>
                  <h3 className="text-lg font-mono font-bold text-neon-green">
                    {selectedTechnique.id}
                  </h3>
                  <p className="text-sm text-gray-300">{selectedTechnique.name}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="p-1.5 hover:bg-cyber-hover rounded transition-colors"
              >
                <X size={16} className="text-gray-500" />
              </button>
            </div>

            <div className="space-y-4">
              <div className="p-4 bg-cyber-bg rounded-lg border border-cyber-border">
                <div className="flex justify-between text-xs font-mono mb-2">
                  <span className="text-gray-400">Total Occurrences</span>
                  <span className="text-neon-green font-bold text-lg">
                    {selectedTechnique.count}
                  </span>
                </div>
                <div className="h-2 bg-cyber-surface rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full bg-neon-green"
                    style={{
                      width: `${(selectedTechnique.count / maxCount) * 100}%`,
                      boxShadow: '0 0 10px rgba(0, 255, 136, 0.3)',
                    }}
                  />
                </div>
              </div>

              <a
                href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="cyber-button-blue w-full flex items-center justify-center gap-2"
              >
                <ExternalLink size={14} />
                View on MITRE ATT&CK
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
