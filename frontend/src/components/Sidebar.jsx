import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Plus,
  History,
  Grid3x3,
  Database,
  BarChart3,
  ChevronLeft,
  ChevronRight,
  Shield,
  Terminal,
  Zap,
} from 'lucide-react';

const navItems = [
  {
    path: '/',
    label: 'Dashboard',
    icon: LayoutDashboard,
    description: 'Overview & Stats',
  },
  {
    path: '/investigate',
    label: 'New Investigation',
    icon: Plus,
    description: 'Submit Alert',
    accent: true,
  },
  {
    path: '/history',
    label: 'History',
    icon: History,
    description: 'Past Investigations',
  },
  {
    path: '/attack-map',
    label: 'ATT&CK Heatmap',
    icon: Grid3x3,
    description: 'MITRE Framework',
  },
  {
    path: '/iocs',
    label: 'IOC Database',
    icon: Database,
    description: 'Indicators',
  },
  {
    path: '/analytics',
    label: 'Analytics',
    icon: BarChart3,
    description: 'Threat Trends',
  },
];

export default function Sidebar({ collapsed, onToggle }) {
  const location = useLocation();

  return (
    <aside
      className={`
        fixed left-0 top-0 h-screen z-40
        bg-cyber-surface border-r border-cyber-border
        flex flex-col transition-all duration-300 ease-in-out
        ${collapsed ? 'w-16' : 'w-64'}
      `}
    >
      {/* Logo / Branding */}
      <div className="flex items-center h-16 px-4 border-b border-cyber-border relative">
        <div className="flex items-center gap-3 overflow-hidden">
          {/* Animated shield icon */}
          <div className="relative flex-shrink-0">
            <Shield
              size={24}
              className="text-neon-green animate-pulse-neon"
            />
            <div className="absolute inset-0 rounded-full bg-neon-green/10 animate-ping"
                 style={{ animationDuration: '3s' }} />
          </div>

          {!collapsed && (
            <div className="flex flex-col animate-fade-in">
              <span className="text-sm font-mono font-bold text-neon-green tracking-wider text-glow-green">
                SOC-AI-AGENT
              </span>
              <span className="text-[10px] font-mono text-gray-500 tracking-widest">
                AUTONOMOUS DEFENSE
              </span>
            </div>
          )}
        </div>
      </div>

      {/* System Status Indicator */}
      {!collapsed && (
        <div className="px-4 py-3 border-b border-cyber-border">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
            <span className="text-[10px] font-mono text-gray-400 uppercase tracking-widest">
              System Active
            </span>
            <Zap size={10} className="text-neon-green ml-auto" />
          </div>
        </div>
      )}

      {/* Navigation Links */}
      <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive =
            item.path === '/'
              ? location.pathname === '/'
              : location.pathname.startsWith(item.path);

          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={`
                group flex items-center gap-3 px-3 py-2.5 rounded-lg
                transition-all duration-200 relative
                ${
                  isActive
                    ? 'bg-neon-green/10 text-neon-green border border-neon-green/20'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-cyber-hover border border-transparent'
                }
                ${item.accent && !isActive ? 'border-neon-green/20 hover:border-neon-green/40' : ''}
              `}
              title={collapsed ? item.label : undefined}
            >
              {/* Active indicator bar */}
              {isActive && (
                <div className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-6 bg-neon-green rounded-r" />
              )}

              <Icon
                size={18}
                className={`flex-shrink-0 transition-colors ${
                  isActive ? 'text-neon-green' : 'text-gray-500 group-hover:text-gray-300'
                }`}
              />

              {!collapsed && (
                <div className="flex flex-col min-w-0">
                  <span className={`text-sm font-medium truncate ${
                    isActive ? 'text-neon-green' : ''
                  }`}>
                    {item.label}
                  </span>
                  <span className="text-[10px] text-gray-600 truncate">
                    {item.description}
                  </span>
                </div>
              )}

              {/* New investigation pulse */}
              {item.accent && !collapsed && (
                <div className="ml-auto">
                  <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
                </div>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Terminal section */}
      {!collapsed && (
        <div className="px-4 py-3 border-t border-cyber-border">
          <div className="flex items-center gap-2 text-gray-600">
            <Terminal size={12} />
            <span className="text-[10px] font-mono tracking-wider">
              v1.0.0 // NEURAL ENGINE
            </span>
          </div>
        </div>
      )}

      {/* Collapse Toggle */}
      <button
        onClick={onToggle}
        className="flex items-center justify-center h-10 border-t border-cyber-border
                   text-gray-500 hover:text-neon-green hover:bg-cyber-hover
                   transition-colors duration-200"
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
      </button>
    </aside>
  );
}
