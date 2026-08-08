import React, { useState } from 'react';
import { LogType, AlertItem } from '../types';
import { SAMPLE_LOGS } from '../data/sampleLogs';
import { Terminal, Upload, Play, RefreshCw, FileText, ShieldAlert, Sparkles, AlertTriangle, CheckCircle } from 'lucide-react';

interface LogParserViewProps {
  onAnalysisComplete: (alert: AlertItem) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
}

export const LogParserView: React.FC<LogParserViewProps> = ({
  onAnalysisComplete,
  isLoading,
  setIsLoading,
}) => {
  const [logType, setLogType] = useState<LogType>('windows');
  const [rawLog, setRawLog] = useState<string>(SAMPLE_LOGS[0].rawLog);
  const [selectedSampleId, setSelectedSampleId] = useState<string>(SAMPLE_LOGS[0].id);
  const [error, setError] = useState<string | null>(null);

  const logTypeOptions: { id: LogType; label: string; desc: string }[] = [
    { id: 'windows', label: 'Windows Event Log', desc: 'EVTX / XML Event 4688, 4624, 4625' },
    { id: 'suricata', label: 'Suricata / Zeek EVE', desc: 'IDS / IPS Network Flow JSON Alert' },
    { id: 'cloudtrail', label: 'AWS CloudTrail', desc: 'Cloud IAM & S3 Telemetry JSON' },
    { id: 'apache_nginx', label: 'Web Access Log', desc: 'Apache / Nginx Access & Exploit Logs' },
    { id: 'auth_log', label: 'Linux Auth Log', desc: '/var/log/auth.log SSH & Sudo Telemetry' },
    { id: 'syslog', label: 'Syslog / Firewall', desc: 'RFC5424 / Palo Alto / Fortinet Logs' },
    { id: 'custom', label: 'Raw Unstructured', desc: 'Generic Security Telemetry' },
  ];

  const handleSelectSample = (sampleId: string) => {
    const sample = SAMPLE_LOGS.find((s) => s.id === sampleId);
    if (sample) {
      setSelectedSampleId(sample.id);
      setLogType(sample.logType);
      setRawLog(sample.rawLog);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setRawLog(content);
        setSelectedSampleId('');
      }
    };
    reader.readAsText(file);
  };

  const handleRunAnalysis = async () => {
    if (!rawLog.trim()) {
      setError('Please provide a security log to analyze.');
      return;
    }

    setError(null);
    setIsLoading(true);

    try {
      const res = await fetch('/api/analyze-log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawLog, logType }),
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to analyze security log.');
      }

      onAnalysisComplete(data.alert);
    } catch (err: any) {
      console.error('Log analysis error:', err);
      setError(err.message || 'An unexpected error occurred during triage.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 p-6 rounded-xl border border-slate-800 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <Terminal className="w-6 h-6 text-cyan-400" />
              <h1 className="text-xl sm:text-2xl font-bold text-white tracking-wide">
                Security Log Triage & Automated Parser
              </h1>
            </div>
            <p className="text-slate-400 text-sm max-w-3xl">
              Paste raw security telemetry, upload log files, or select a pre-loaded threat sample.
              Our engine performs regex IOC extraction, MITRE ATT&CK mapping, and Gemini AI risk assessment.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <label className="cursor-pointer bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-4 py-2 rounded-lg text-sm font-medium flex items-center space-x-2 transition-all">
              <Upload className="w-4 h-4 text-cyan-400" />
              <span>Upload Log (.log/.txt)</span>
              <input type="file" onChange={handleFileUpload} accept=".log,.txt,.json,.xml" className="hidden" />
            </label>
          </div>
        </div>
      </div>

      {/* Preset Threat Scenarios / Samples */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-amber-400" />
            <span>Select Real-World DFIR Threat Scenario</span>
          </h2>
          <span className="text-xs text-slate-500">1-Click Test Scenarios</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
          {SAMPLE_LOGS.map((sample) => {
            const isSelected = selectedSampleId === sample.id;
            return (
              <button
                key={sample.id}
                onClick={() => handleSelectSample(sample.id)}
                className={`text-left p-3 rounded-lg border transition-all flex flex-col justify-between ${
                  isSelected
                    ? 'bg-cyan-950/50 border-cyan-500 shadow-md shadow-cyan-950/50 text-white'
                    : 'bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-300 hover:bg-slate-850'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold uppercase tracking-wider text-cyan-400">{sample.logType}</span>
                    {isSelected && <CheckCircle className="w-3.5 h-3.5 text-cyan-400" />}
                  </div>
                  <h3 className="text-xs font-semibold text-slate-100 line-clamp-1">{sample.name}</h3>
                  <p className="text-[11px] text-slate-400 line-clamp-2 mt-1">{sample.description}</p>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Parser Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        
        {/* Log Type Selector Column */}
        <div className="lg:col-span-1 space-y-4 bg-slate-900 p-4 rounded-xl border border-slate-800">
          <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span>Format & Category</span>
          </h3>

          <div className="space-y-2">
            {logTypeOptions.map((option) => {
              const isCurrent = logType === option.id;
              return (
                <button
                  key={option.id}
                  onClick={() => setLogType(option.id)}
                  className={`w-full text-left p-2.5 rounded-lg border text-xs transition-all ${
                    isCurrent
                      ? 'bg-slate-800 border-cyan-500/70 text-cyan-300 font-medium'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                  }`}
                >
                  <div className="font-semibold text-slate-200">{option.label}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{option.desc}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Code Input & Execution Area */}
        <div className="lg:col-span-3 space-y-4">
          <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden shadow-lg">
            
            {/* Editor Header */}
            <div className="bg-slate-950 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="w-3 h-3 rounded-full bg-rose-500/80" />
                <span className="w-3 h-3 rounded-full bg-amber-500/80" />
                <span className="w-3 h-3 rounded-full bg-emerald-500/80" />
                <span className="font-mono text-xs text-slate-400 ml-2">raw_security_telemetry.log</span>
              </div>
              <span className="text-xs text-slate-500 font-mono">
                {rawLog.length} chars | Format: {logType.toUpperCase()}
              </span>
            </div>

            {/* Editor Body */}
            <textarea
              value={rawLog}
              onChange={(e) => {
                setRawLog(e.target.value);
                setSelectedSampleId('');
              }}
              placeholder="Paste raw security log entries here (Windows XML, Syslog, Suricata EVE JSON, CloudTrail, Web logs)..."
              rows={14}
              className="w-full bg-slate-950 p-4 font-mono text-xs text-emerald-400/90 leading-relaxed focus:outline-none resize-none border-none selection:bg-cyan-900 selection:text-white"
            />

            {/* Error Message if any */}
            {error && (
              <div className="m-4 p-3 bg-rose-950/80 border border-rose-800 text-rose-300 text-xs rounded-lg flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Bottom Controls */}
            <div className="bg-slate-900 px-4 py-3 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="text-xs text-slate-400 flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <span>Extracts IOCs, maps MITRE ATT&CK, & scores threat severity</span>
              </div>

              <button
                onClick={handleRunAnalysis}
                disabled={isLoading}
                className="w-full sm:w-auto bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-sm px-6 py-2.5 rounded-lg shadow-lg shadow-cyan-900/40 flex items-center justify-center space-x-2 transition-all disabled:opacity-50"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    <span>Analyzing Log Telemetry...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 text-white fill-current" />
                    <span>Execute AI Triage Analysis</span>
                  </>
                )}
              </button>
            </div>

          </div>
        </div>

      </div>
    </div>
  );
};
