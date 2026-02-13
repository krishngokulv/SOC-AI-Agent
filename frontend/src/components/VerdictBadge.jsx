import React from 'react';
import { VERDICTS, formatConfidence } from '../utils/constants';
import { ShieldAlert, ShieldCheck, AlertTriangle, HelpCircle } from 'lucide-react';

const verdictIcons = {
  TRUE_POSITIVE: ShieldAlert,
  FALSE_POSITIVE: ShieldCheck,
  NEEDS_ESCALATION: AlertTriangle,
  SUSPICIOUS: AlertTriangle,
  BENIGN: ShieldCheck,
};

export default function VerdictBadge({
  verdict,
  confidence,
  size = 'md',
  showConfidence = true,
  showIcon = true,
  animated = false,
}) {
  const config = VERDICTS[verdict];

  if (!config) {
    return (
      <span className="badge bg-gray-800 text-gray-400 border border-gray-700">
        <HelpCircle size={12} className="mr-1" />
        Unknown
      </span>
    );
  }

  const Icon = verdictIcons[verdict] || HelpCircle;

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-[10px]',
    md: 'px-2.5 py-1 text-xs',
    lg: 'px-3.5 py-1.5 text-sm',
    xl: 'px-5 py-2.5 text-base',
  };

  const iconSizes = {
    sm: 10,
    md: 12,
    lg: 14,
    xl: 18,
  };

  return (
    <span
      className={`
        inline-flex items-center gap-1.5 rounded-full font-mono font-semibold
        ${config.bgColor} ${config.textColor} border ${config.borderColor}
        ${sizeClasses[size]}
        ${animated ? 'animate-fade-in' : ''}
        transition-all duration-200 hover:scale-105
      `}
      title={config.description}
    >
      {showIcon && <Icon size={iconSizes[size]} />}
      <span>{config.label}</span>
      {showConfidence && confidence != null && (
        <span className="opacity-70 ml-0.5">
          {formatConfidence(confidence)}
        </span>
      )}
    </span>
  );
}

/**
 * Larger verdict display card for investigation detail / verdict reveal.
 */
export function VerdictCard({ verdict, confidence, reasoning, animated = true }) {
  const config = VERDICTS[verdict];
  if (!config) return null;

  const Icon = verdictIcons[verdict] || HelpCircle;
  const confidencePercent = Math.round((confidence || 0) * 100);

  return (
    <div
      className={`
        cyber-card p-6 border-2 ${config.borderColor}
        ${animated ? 'animate-fade-in-up' : ''}
      `}
      style={{
        boxShadow: `0 0 30px ${config.color}20, 0 0 60px ${config.color}10`,
      }}
    >
      {/* Header */}
      <div className="flex items-center gap-4 mb-4">
        <div
          className={`w-14 h-14 rounded-full flex items-center justify-center ${config.bgColor} border ${config.borderColor}`}
          style={{ boxShadow: `0 0 20px ${config.color}30` }}
        >
          <Icon size={28} style={{ color: config.color }} />
        </div>
        <div>
          <div className={`text-2xl font-mono font-bold ${config.textColor}`}>
            {config.label}
          </div>
          <div className="text-gray-400 text-sm">{config.description}</div>
        </div>
      </div>

      {/* Confidence bar */}
      <div className="mb-4">
        <div className="flex justify-between items-center mb-2">
          <span className="text-xs text-gray-400 font-mono uppercase tracking-wider">
            Confidence Score
          </span>
          <span
            className="text-lg font-mono font-bold"
            style={{ color: config.color }}
          >
            {confidencePercent}%
          </span>
        </div>
        <div className="h-2.5 bg-cyber-bg rounded-full overflow-hidden border border-cyber-border">
          <div
            className="h-full rounded-full confidence-fill"
            style={{
              width: `${confidencePercent}%`,
              background: `linear-gradient(90deg, ${config.color}80, ${config.color})`,
              boxShadow: `0 0 10px ${config.color}50`,
            }}
          />
        </div>
      </div>

      {/* Reasoning */}
      {reasoning && (
        <div className="mt-4 p-4 bg-cyber-bg rounded-lg border border-cyber-border">
          <div className="text-xs text-gray-400 font-mono uppercase tracking-wider mb-2">
            AI Reasoning
          </div>
          <p className="text-gray-300 text-sm leading-relaxed">{reasoning}</p>
        </div>
      )}
    </div>
  );
}
