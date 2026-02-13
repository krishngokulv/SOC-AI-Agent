import React, { useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import AlertSubmit from './components/AlertSubmit';
import LiveInvestigation from './components/LiveInvestigation';
import InvestigationHistory from './components/InvestigationHistory';
import InvestigationDetail from './components/InvestigationDetail';
import AttackHeatmap from './components/AttackHeatmap';
import IOCTable from './components/IOCTable';
import ThreatAnalytics from './components/ThreatAnalytics';

export default function App() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <div className="flex h-screen bg-cyber-bg overflow-hidden">
      {/* Sidebar Navigation */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />

      {/* Main Content Area */}
      <main
        className={`flex-1 overflow-y-auto transition-all duration-300 ${
          sidebarCollapsed ? 'ml-16' : 'ml-64'
        }`}
      >
        {/* Background grid pattern */}
        <div className="fixed inset-0 grid-bg pointer-events-none opacity-50" />

        {/* Content */}
        <div className="relative z-10 p-6 min-h-screen">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/investigate" element={<AlertSubmit />} />
            <Route
              path="/investigate/:id"
              element={<LiveInvestigation />}
            />
            <Route path="/history" element={<InvestigationHistory />} />
            <Route
              path="/investigation/:id"
              element={<InvestigationDetail />}
            />
            <Route path="/attack-map" element={<AttackHeatmap />} />
            <Route path="/iocs" element={<IOCTable />} />
            <Route path="/analytics" element={<ThreatAnalytics />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}
