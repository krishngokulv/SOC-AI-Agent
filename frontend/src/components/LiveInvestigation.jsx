import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  CheckCircle, Loader2, AlertTriangle, XCircle, FileSearch, Search,
  Database, Map, Brain, FileText, Download, ExternalLink, Clock,
  ChevronDown, ChevronRight, Zap,
} from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import { INVESTIGATION_STAGES } from '../utils/constants';
import { VerdictCard } from './VerdictBadge';

const stageIcons = {
  parsing: FileSearch,
  ioc_extraction: Search,
  enrichment: Database,
  mitre_mapping: Map,
  analysis: Brain,
  verdict: Zap,
  report: FileText,
};

function StageNode({ stage, stageData, isActive, isCurrent, index }) {
  const Icon = stageIcons[stage.key] || CheckCircle;
  const status = stageData?.status || 'pending';
  const [expanded, setExpanded] = useState(false);

  const statusConfig = {
    pending: {
      lineColor: 'bg-cyber-border',
      dotBg: 'bg-cyber-surface border-cyber-border',
      iconColor: 'text-gray-600',
      labelColor: 'text-gray-600',
    },
    running: {
      lineColor: 'bg-neon-green/50',
      dotBg: 'bg-neon-green/20 border-neon-green',
      iconColor: 'text-neon-green',
      labelColor: 'text-neon-green',
    },
    complete: {
      lineColor: 'bg-neon-green',
      dotBg: 'bg-neon-green/20 border-neon-green/50',
      iconColor: 'text-neon-green',
      labelColor: 'text-gray-300',
    },
    error: {
      lineColor: 'bg-neon-red',
      dotBg: 'bg-neon-red/20 border-neon-red',
      iconColor: 'text-neon-red',
      labelColor: 'text-neon-red',
    },
  };

  const config = statusConfig[status];
  const hasData = stageData?.data || stageData?.result;

  return (
    <div className={`relative flex gap-4 animate-fade-in-up`} style={{ animationDelay: `${index * 100}ms` }}>
      {/* Vertical line connector */}
      <div className="flex flex-col items-center">
        <div
          className={`
            w-10 h-10 rounded-full flex items-center justify-center border-2
            ${config.dotBg} transition-all duration-500 relative z-10
            ${status === 'running' ? 'animate-glow' : ''}
          `}
          style={
            status === 'running'
              ? { boxShadow: '0 0 15px rgba(0, 255, 136, 0.3)' }
              : status === 'complete'
              ? { boxShadow: '0 0 8px rgba(0, 255, 136, 0.15)' }
              : {}
          }
        >
          {status === 'running' ? (
            <Loader2 size={18} className="text-neon-green animate-spin" />
          ) : status === 'complete' ? (
            <CheckCircle size={18} className="text-neon-green" />
          ) : status === 'error' ? (
            <XCircle size={18} className="text-neon-red" />
          ) : (
            <Icon size={18} className={config.iconColor} />
          )}
        </div>
        {/* Line down */}
        <div
          className={`w-0.5 flex-1 min-h-[20px] ${config.lineColor} transition-all duration-500`}
        />
      </div>

      {/* Stage content */}
      <div className="flex-1 pb-6">
        <div
          className={`
            cyber-card p-4 transition-all duration-300
            ${status === 'running' ? 'border-neon-green/30 shadow-neon-green' : ''}
            ${status === 'error' ? 'border-neon-red/30' : ''}
            ${hasData ? 'cursor-pointer' : ''}
          `}
          onClick={() => hasData && setExpanded(!expanded)}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Icon size={16} className={config.iconColor} />
              <div>
                <h4 className={`text-sm font-semibold ${config.labelColor}`}>
                  {stage.label}
                </h4>
                <p className="text-xs text-gray-500 mt-0.5">
                  {stage.description}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {status === 'running' && (
                <span className="text-[10px] font-mono text-neon-green animate-pulse">
                  PROCESSING
                </span>
              )}
              {stageData?.duration && (
                <span className="text-[10px] font-mono text-gray-500 flex items-center gap-1">
                  <Clock size={10} />
                  {(stageData.duration / 1000).toFixed(1)}s
                </span>
              )}
              {status === 'error' && (
                <span className="text-[10px] font-mono text-neon-red">
                  FAILED
                </span>
              )}
              {hasData && (
                expanded ? (
                  <ChevronDown size={14} className="text-gray-500" />
                ) : (
                  <ChevronRight size={14} className="text-gray-500" />
                )
              )}
            </div>
          </div>

          {/* Expanded data view */}
          {expanded && hasData && (
            <div className="mt-3 pt-3 border-t border-cyber-border">
              <pre className="text-[11px] font-mono text-gray-400 overflow-x-auto whitespace-pre-wrap max-h-60 overflow-y-auto">
                {JSON.stringify(stageData.data || stageData.result, null, 2)}
              </pre>
            </div>
          )}

          {/* Error display */}
          {status === 'error' && stageData?.error && (
            <div className="mt-3 pt-3 border-t border-neon-red/20">
              <p className="text-xs font-mono text-neon-red">
                {stageData.error}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function EnrichmentStream({ results }) {
  const containerRef = useRef(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [results.length]);

  if (results.length === 0) return null;

  return (
    <div className="cyber-card p-4 mt-4 border-neon-blue/20">
      <h4 className="text-xs font-mono text-neon-blue uppercase tracking-wider mb-3 flex items-center gap-2">
        <Database size={12} />
        Enrichment Results Stream ({results.length})
      </h4>
      <div ref={containerRef} className="max-h-48 overflow-y-auto space-y-2">
        {results.map((result, i) => (
          <div
            key={i}
            className="flex items-start gap-3 p-2 bg-cyber-bg rounded border border-cyber-border animate-fade-in"
          >
            <div className="w-2 h-2 rounded-full bg-neon-blue mt-1.5 flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] font-mono text-neon-blue font-semibold">
                  {result.source}
                </span>
                <span className="text-[10px] font-mono text-gray-600">
                  {result.ioc}
                </span>
              </div>
              <p className="text-[11px] font-mono text-gray-400 truncate">
                {typeof result.result === 'string'
                  ? result.result
                  : JSON.stringify(result.result)}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function LiveInvestigation() {
  const { id } = useParams();
  const navigate = useNavigate();

  const {
    connected,
    connecting,
    stages,
    currentStage,
    verdict,
    enrichmentResults,
    isComplete,
    error,
    progress,
  } = useWebSocket(id);

  const [showReport, setShowReport] = useState(false);

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

  return (
    <div className="max-w-3xl mx-auto space-y-6 pb-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
            <Zap size={24} className="text-neon-green" />
            Live Investigation
          </h1>
          <p className="text-sm text-gray-500 mt-1 font-mono">
            ID: {id}
          </p>
        </div>

        {/* Connection status */}
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border ${
            connected
              ? 'bg-neon-green/10 border-neon-green/20'
              : connecting
              ? 'bg-neon-yellow/10 border-neon-yellow/20'
              : 'bg-gray-800 border-gray-700'
          }`}>
            <div className={`w-2 h-2 rounded-full ${
              connected ? 'bg-neon-green animate-pulse' : connecting ? 'bg-neon-yellow animate-pulse' : 'bg-gray-600'
            }`} />
            <span className={`text-xs font-mono ${
              connected ? 'text-neon-green' : connecting ? 'text-neon-yellow' : 'text-gray-500'
            }`}>
              {connected ? 'CONNECTED' : connecting ? 'CONNECTING' : 'DISCONNECTED'}
            </span>
          </div>
        </div>
      </div>

      {/* Progress bar */}
      <div className="cyber-card p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono text-gray-400 uppercase tracking-wider">
            Investigation Progress
          </span>
          <span className="text-sm font-mono text-neon-green font-bold">
            {progress}%
          </span>
        </div>
        <div className="h-1.5 bg-cyber-bg rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500 ease-out"
            style={{
              width: `${progress}%`,
              background: 'linear-gradient(90deg, #00ff88, #00d4ff)',
              boxShadow: '0 0 10px rgba(0, 255, 136, 0.3)',
            }}
          />
        </div>
      </div>

      {/* Error display */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-neon-red/10 border border-neon-red/30 rounded-lg">
          <AlertTriangle size={18} className="text-neon-red flex-shrink-0" />
          <div>
            <p className="text-sm font-mono text-neon-red font-semibold">Investigation Error</p>
            <p className="text-xs font-mono text-gray-400 mt-1">{error}</p>
          </div>
        </div>
      )}

      {/* Stage Timeline */}
      <div className="space-y-0">
        {INVESTIGATION_STAGES.map((stage, index) => (
          <StageNode
            key={stage.key}
            stage={stage}
            stageData={stages[stage.key]}
            isActive={!!stages[stage.key]}
            isCurrent={currentStage === stage.key}
            index={index}
          />
        ))}
      </div>

      {/* Enrichment stream */}
      {enrichmentResults.length > 0 && (
        <EnrichmentStream results={enrichmentResults} />
      )}

      {/* Verdict reveal */}
      {verdict && (
        <div className="animate-fade-in-up" style={{ animationDelay: '300ms' }}>
          <div className="neon-line mb-6" />
          <div className="text-center mb-4">
            <span className="text-xs font-mono text-gray-400 uppercase tracking-[0.3em]">
              Investigation Complete
            </span>
          </div>
          <VerdictCard
            verdict={verdict.verdict}
            confidence={verdict.confidence}
            reasoning={verdict.reasoning}
            animated={true}
          />
        </div>
      )}

      {/* Report download buttons */}
      {isComplete && (
        <div className="flex items-center gap-4 animate-fade-in-up" style={{ animationDelay: '500ms' }}>
          <button
            onClick={() => handleDownload('html')}
            className="flex-1 cyber-button-primary flex items-center justify-center gap-2 py-3"
          >
            <Download size={16} />
            Download HTML Report
          </button>
          <button
            onClick={() => handleDownload('pdf')}
            className="flex-1 cyber-button-blue flex items-center justify-center gap-2 py-3"
          >
            <Download size={16} />
            Download PDF Report
          </button>
          <button
            onClick={() => navigate(`/investigation/${id}`)}
            className="flex-1 cyber-button flex items-center justify-center gap-2 py-3 bg-cyber-surface text-gray-300 border border-cyber-border hover:border-gray-500"
          >
            <ExternalLink size={16} />
            View Details
          </button>
        </div>
      )}

      {/* Not connected / waiting state */}
      {!connected && !connecting && !isComplete && !error && (
        <div className="cyber-card p-8 text-center">
          <div className="cyber-spinner mx-auto mb-4" />
          <p className="text-sm font-mono text-gray-400">
            Waiting for investigation stream...
          </p>
          <p className="text-xs font-mono text-gray-600 mt-2">
            The WebSocket connection will be established once the backend starts processing.
          </p>
        </div>
      )}
    </div>
  );
}
