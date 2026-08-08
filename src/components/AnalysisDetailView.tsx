import React, { useState } from 'react';
import { AlertItem, Severity, TriageStatus } from '../types';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ExternalLink,
  Copy,
  Check,
  Code,
  FileCode,
  Crosshair,
  UserCheck,
  ChevronRight,
  ArrowLeft,
  Sparkles,
  Download,
  Share2,
  Lock,
  Search
} from 'lucide-react';

interface AnalysisDetailViewProps {
  alert: AlertItem;
  onBack: () => void;
  onUpdateStatus: (alertId: string, newStatus: TriageStatus) => void;
  onOpenRuleStudio: (alert: AlertItem) => void;
}

export const AnalysisDetailView: React.FC<AnalysisDetailViewProps> = ({
  alert,
  onBack,
  onUpdateStatus,
  onOpenRuleStudio,
}) => {
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const [selectedIocLookup, setSelectedIocLookup] = useState<string | null>(null);
  const [iocLookupData, setIocLookupData] = useState<any | null>(null);
  const [isLookupLoading, setIsLookupLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'iocs' | 'mitre' | 'timeline' | 'rules'>('overview');

  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-950 border-rose-600 text-rose-300 animate-pulse';
      case 'HIGH':
        return 'bg-amber-950 border-amber-600 text-amber-300';
      case 'MEDIUM':
        return 'bg-yellow-950 border-yellow-600 text-yellow-300';
      case 'LOW':
        return 'bg-blue-950 border-blue-600 text-blue-300';
      default:
        return 'bg-slate-800 border-slate-700 text-slate-300';
    }
  };

  const getStatusBadge = (status: TriageStatus) => {
    switch (status) {
      case 'NEW':
        return 'bg-rose-900/60 text-rose-300 border-rose-700';
      case 'INVESTIGATING':
        return 'bg-amber-900/60 text-amber-300 border-amber-700';
      case 'CONTAINMENT':
        return 'bg-purple-900/60 text-purple-300 border-purple-700';
      case 'ESCALATED':
        return 'bg-red-900/60 text-red-300 border-red-700';
      case 'RESOLVED':
        return 'bg-emerald-900/60 text-emerald-300 border-emerald-700';
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIoc(id);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  const handleLookupIoc = async (value: string) => {
    setSelectedIocLookup(value);
    setIsLookupLoading(true);
    try {
      const res = await fetch(`/api/threat-lookup?value=${encodeURIComponent(value)}`);
      const data = await res.json();
      setIocLookupData(data);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLookupLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Top Action Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 p-4 rounded-xl border border-slate-800">
        <div className="flex items-center space-x-3">
          <button
            onClick={onBack}
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-all"
            title="Back to Triage"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center space-x-2">
              <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full border uppercase tracking-wide ${getSeverityBadge(alert.severity)}`}>
                {alert.severity}
              </span>
              <span className="text-xs font-mono text-slate-400">{alert.id}</span>
              <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${getStatusBadge(alert.status)}`}>
                {alert.status}
              </span>
            </div>
            <h1 className="text-lg font-bold text-white mt-1">{alert.title}</h1>
          </div>
        </div>

        {/* Triage Status Control & Rule Studio Quick Action */}
        <div className="flex items-center space-x-2">
          <select
            value={alert.status}
            onChange={(e) => onUpdateStatus(alert.id, e.target.value as TriageStatus)}
            className="bg-slate-800 text-xs font-semibold text-slate-200 border border-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-500"
          >
            <option value="NEW">Status: NEW</option>
            <option value="INVESTIGATING">Status: INVESTIGATING</option>
            <option value="CONTAINMENT">Status: CONTAINMENT</option>
            <option value="ESCALATED">Status: ESCALATED</option>
            <option value="RESOLVED">Status: RESOLVED</option>
          </select>

          <button
            onClick={() => onOpenRuleStudio(alert)}
            className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center space-x-2 shadow-md shadow-cyan-900/30 transition-all"
          >
            <Code className="w-4 h-4" />
            <span>Generate Sigma / YARA</span>
          </button>
        </div>
      </div>

      {/* Incident Highlight Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        
        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400">Risk Score</div>
            <div className="text-2xl font-black text-rose-400 font-mono mt-1">{alert.riskScore} <span className="text-xs font-normal text-slate-500">/ 100</span></div>
          </div>
          <div className="w-10 h-10 rounded-full bg-rose-950 border border-rose-700 flex items-center justify-center">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
          </div>
        </div>

        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400">Threat Actor Attribution</div>
            <div className="text-sm font-bold text-cyan-300 mt-1 line-clamp-1">{alert.threatActor || 'APT / Unknown'}</div>
          </div>
          <div className="w-10 h-10 rounded-full bg-cyan-950 border border-cyan-700 flex items-center justify-center">
            <UserCheck className="w-5 h-5 text-cyan-400" />
          </div>
        </div>

        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400">Extracted IOCs</div>
            <div className="text-2xl font-bold text-white font-mono mt-1">{alert.iocs.length}</div>
          </div>
          <div className="w-10 h-10 rounded-full bg-purple-950 border border-purple-700 flex items-center justify-center">
            <Crosshair className="w-5 h-5 text-purple-400" />
          </div>
        </div>

        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-slate-400">MITRE Techniques</div>
            <div className="text-2xl font-bold text-amber-400 font-mono mt-1">{alert.mitreMappings.length}</div>
          </div>
          <div className="w-10 h-10 rounded-full bg-amber-950 border border-amber-700 flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
          </div>
        </div>

      </div>

      {/* Navigation Tabs for Analysis View */}
      <div className="border-b border-slate-800 flex space-x-6">
        {[
          { id: 'overview', label: 'Triage Overview & IR Plan' },
          { id: 'iocs', label: `Extracted IOCs (${alert.iocs.length})` },
          { id: 'mitre', label: `MITRE ATT&CK (${alert.mitreMappings.length})` },
          { id: 'timeline', label: `Forensic Timeline (${alert.timelineEvents.length})` },
          { id: 'rules', label: 'Generated Rules & Signatures' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`pb-3 text-sm font-semibold border-b-2 transition-all ${
              activeTab === tab.id
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* TAB 1: OVERVIEW & IR RECOMMENDATIONS */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          <div className="lg:col-span-2 space-y-6">
            
            {/* Executive Summary */}
            <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-3">
              <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span>AI Incident Executive Summary</span>
              </h2>
              <p className="text-sm text-slate-300 leading-relaxed bg-slate-950 p-4 rounded-lg border border-slate-850 font-mono text-xs">
                {alert.summary}
              </p>
            </div>

            {/* Actionable Incident Response Containment Plan */}
            <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-4">
              <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                <Lock className="w-4 h-4 text-emerald-400" />
                <span>Recommended Triage & Containment Actions</span>
              </h2>

              <div className="space-y-2">
                {alert.recommendations.map((rec, idx) => (
                  <div key={idx} className="flex items-start space-x-3 bg-slate-950 p-3 rounded-lg border border-slate-850 text-xs text-slate-300">
                    <span className="flex-shrink-0 w-5 h-5 rounded-full bg-cyan-950 border border-cyan-700 text-cyan-400 font-bold flex items-center justify-center text-[10px]">
                      {idx + 1}
                    </span>
                    <span className="mt-0.5">{rec}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Raw Log Preview */}
            <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Raw Security Log Source</h2>
                <button
                  onClick={() => handleCopy(alert.rawLog, 'raw-log')}
                  className="text-xs text-slate-400 hover:text-cyan-400 flex items-center space-x-1"
                >
                  {copiedIoc === 'raw-log' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy Log</span>
                </button>
              </div>
              <pre className="bg-slate-950 p-4 rounded-lg font-mono text-[11px] text-emerald-400/90 overflow-x-auto max-h-60 border border-slate-850">
                {alert.rawLog}
              </pre>
            </div>

          </div>

          {/* Sidebar Metrics & Key Indicators */}
          <div className="space-y-6">
            
            <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-4">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Top Critical IOCs</h3>
              
              <div className="space-y-2">
                {alert.iocs.slice(0, 5).map((ioc) => (
                  <div key={ioc.id} className="p-2.5 bg-slate-950 rounded-lg border border-slate-850 flex items-center justify-between">
                    <div>
                      <div className="text-xs font-mono font-bold text-cyan-300">{ioc.value}</div>
                      <div className="text-[10px] text-slate-500 uppercase">{ioc.type} • {ioc.reputation}</div>
                    </div>
                    <button
                      onClick={() => handleLookupIoc(ioc.value)}
                      className="p-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] flex items-center space-x-1"
                    >
                      <Search className="w-3 h-3 text-cyan-400" />
                      <span>Lookup</span>
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-3">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Primary ATT&CK Tactic</h3>
              {alert.mitreMappings[0] ? (
                <div className="p-3 bg-slate-950 rounded-lg border border-amber-900/50 space-y-1">
                  <span className="text-xs font-mono font-bold text-amber-400">{alert.mitreMappings[0].tacticId}: {alert.mitreMappings[0].tacticName}</span>
                  <div className="text-xs text-slate-200 font-semibold">{alert.mitreMappings[0].techniqueId} - {alert.mitreMappings[0].techniqueName}</div>
                  <p className="text-[11px] text-slate-400">{alert.mitreMappings[0].description}</p>
                </div>
              ) : (
                <p className="text-xs text-slate-500">No MITRE tactics mapped.</p>
              )}
            </div>

          </div>

        </div>
      )}

      {/* TAB 2: EXTRACTED IOCS & THREAT INTEL */}
      {activeTab === 'iocs' && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Indicators of Compromise (IOC) Inventory</h2>
            <span className="text-xs text-slate-400">{alert.iocs.length} Extracted Artifacts</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                <tr>
                  <th className="p-3">Type</th>
                  <th className="p-3">Indicator Value</th>
                  <th className="p-3">Risk Level</th>
                  <th className="p-3">Tags & Intelligence</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {alert.iocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-850/50 transition-colors">
                    <td className="p-3">
                      <span className="bg-slate-800 border border-slate-700 text-slate-300 text-[10px] px-2 py-0.5 rounded uppercase">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="p-3 text-cyan-300 font-bold max-w-xs truncate">{ioc.value}</td>
                    <td className="p-3">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                        ioc.riskScore >= 80 ? 'bg-rose-950 text-rose-300 border-rose-700' : 'bg-amber-950 text-amber-300 border-amber-700'
                      }`}>
                        Score {ioc.riskScore}
                      </span>
                    </td>
                    <td className="p-3 font-sans">
                      <div className="flex flex-wrap gap-1">
                        {ioc.tags.map((tag, i) => (
                          <span key={i} className="bg-slate-800 text-slate-300 text-[10px] px-1.5 py-0.5 rounded">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="p-3 text-right space-x-2 font-sans">
                      <button
                        onClick={() => handleCopy(ioc.value, ioc.id)}
                        className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs inline-flex items-center space-x-1"
                      >
                        {copiedIoc === ioc.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>Copy</span>
                      </button>
                      <button
                        onClick={() => handleLookupIoc(ioc.value)}
                        className="p-1.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded text-xs inline-flex items-center space-x-1"
                      >
                        <Search className="w-3 h-3 text-cyan-400" />
                        <span>Intel Lookup</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: MITRE ATT&CK MAPPING */}
      {activeTab === 'mitre' && (
        <div className="space-y-4">
          <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-4">
            <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">MITRE ATT&CK Enterprise Matrix Mappings</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {alert.mitreMappings.map((m, idx) => (
                <div key={idx} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="bg-amber-950 text-amber-300 border border-amber-800 text-xs font-mono font-bold px-2 py-0.5 rounded">
                      {m.tacticId}: {m.tacticName}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">Confidence: {m.confidence}%</span>
                  </div>

                  <h3 className="text-sm font-bold text-white mt-1">
                    {m.techniqueId} - {m.techniqueName}
                  </h3>
                  
                  <p className="text-xs text-slate-400 leading-relaxed">{m.description}</p>

                  <a
                    href={`https://attack.mitre.org/techniques/${m.techniqueId.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center space-x-1 text-xs text-cyan-400 hover:text-cyan-300 pt-2"
                  >
                    <span>View on MITRE ATT&CK Framework</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: FORENSIC TIMELINE */}
      {activeTab === 'timeline' && (
        <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-4">
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Chronological Attack Event Timeline</h2>

          <div className="relative border-l-2 border-slate-800 ml-4 space-y-6 py-2">
            {alert.timelineEvents.map((evt) => (
              <div key={evt.id} className="ml-6 relative">
                <div className="absolute -left-[31px] top-1 w-3.5 h-3.5 rounded-full bg-cyan-500 border-2 border-slate-900" />
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-850 space-y-1">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span>{evt.timestamp}</span>
                    <span className="text-cyan-400 font-bold">{evt.actor || 'Threat Actor'}</span>
                  </div>
                  <p className="text-xs font-semibold text-slate-200">{evt.event}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 5: GENERATED RULES & SIGNATURES */}
      {activeTab === 'rules' && alert.rules && (
        <div className="space-y-6">
          <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                <Code className="w-4 h-4 text-cyan-400" />
                <span>Sigma Rule (YAML Detection Format)</span>
              </h2>
              <button
                onClick={() => handleCopy(alert.rules?.sigmaRule || '', 'sigma')}
                className="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded text-slate-200 flex items-center space-x-1"
              >
                {copiedIoc === 'sigma' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy Sigma Rule</span>
              </button>
            </div>
            <pre className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-cyan-300 overflow-x-auto border border-slate-800">
              {alert.rules.sigmaRule}
            </pre>
          </div>

          <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                <FileCode className="w-4 h-4 text-purple-400" />
                <span>YARA Signature Rule</span>
              </h2>
              <button
                onClick={() => handleCopy(alert.rules?.yaraRule || '', 'yara')}
                className="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded text-slate-200 flex items-center space-x-1"
              >
                {copiedIoc === 'yara' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy YARA Rule</span>
              </button>
            </div>
            <pre className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-purple-300 overflow-x-auto border border-slate-800">
              {alert.rules.yaraRule}
            </pre>
          </div>
        </div>
      )}

      {/* Threat Intel Lookup Modal */}
      {selectedIocLookup && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Search className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Threat Intelligence Deep Lookup</h3>
              </div>
              <button onClick={() => setSelectedIocLookup(null)} className="text-slate-400 hover:text-white text-xs">
                ✕ Close
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-500 uppercase text-[10px]">Queried Indicator:</span>
                <p className="text-cyan-300 font-bold text-sm mt-0.5">{selectedIocLookup}</p>
              </div>

              {isLookupLoading ? (
                <p className="text-slate-400 text-center py-4">Querying VirusTotal, AbuseIPDB & AlienVault OTX...</p>
              ) : iocLookupData ? (
                <div className="space-y-3 font-sans">
                  <div className="grid grid-cols-2 gap-2">
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <div className="text-[10px] text-slate-500">VirusTotal Detection</div>
                      <div className="text-rose-400 font-bold font-mono text-sm">
                        {iocLookupData.virustotalStats?.malicious} / 70 Engines
                      </div>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <div className="text-[10px] text-slate-500">AbuseIPDB Score</div>
                      <div className="text-amber-400 font-bold font-mono text-sm">
                        {iocLookupData.abuseipdbScore ? `${iocLookupData.abuseipdbScore}% Confidence` : 'N/A Domain'}
                      </div>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
                    <div className="text-[10px] text-slate-500 uppercase">Threat Actor Attribution</div>
                    <div className="text-xs font-semibold text-cyan-300">{iocLookupData.threatActors?.join(', ')}</div>
                  </div>

                  <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
                    <div className="text-[10px] text-slate-500 uppercase">AlienVault OTX Pulse Tags</div>
                    <div className="flex flex-wrap gap-1">
                      {iocLookupData.alienvaultTags?.map((tag: string, i: number) => (
                        <span key={i} className="bg-purple-950 text-purple-300 border border-purple-800 text-[10px] px-2 py-0.5 rounded">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ) : null}
            </div>

            <button
              onClick={() => setSelectedIocLookup(null)}
              className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 py-2 rounded-lg text-xs font-semibold transition-all"
            >
              Done
            </button>
          </div>
        </div>
      )}

    </div>
  );
};
