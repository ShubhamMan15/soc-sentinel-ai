import React, { useState } from 'react';
import { AlertItem, TriageStatus, Severity } from '../types';
import {
  LayoutDashboard,
  Search,
  Filter,
  ShieldAlert,
  AlertTriangle,
  Clock,
  CheckCircle2,
  UserCheck,
  Download,
  Trash2,
  ChevronRight,
  MessageSquare,
  Sparkles
} from 'lucide-react';

interface SiemQueueViewProps {
  alerts: AlertItem[];
  onSelectAlert: (alert: AlertItem) => void;
  onUpdateStatus: (alertId: string, newStatus: TriageStatus) => void;
  onAddNote: (alertId: string, noteText: string) => void;
  onClearQueue: () => void;
}

export const SiemQueueView: React.FC<SiemQueueViewProps> = ({
  alerts,
  onSelectAlert,
  onUpdateStatus,
  onAddNote,
  onClearQueue,
}) => {
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [activeNoteModalAlertId, setActiveNoteModalAlertId] = useState<string | null>(null);
  const [newNoteText, setNewNoteText] = useState<string>('');

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.rawLog.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.iocs.some((i) => i.value.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesStatus = statusFilter === 'ALL' || alert.status === statusFilter;
    const matchesSeverity = severityFilter === 'ALL' || alert.severity === severityFilter;

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(alerts, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `soc-sentinel-alerts-export-${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleSaveNote = () => {
    if (activeNoteModalAlertId && newNoteText.trim()) {
      onAddNote(activeNoteModalAlertId, newNoteText);
      setNewNoteText('');
      setActiveNoteModalAlertId(null);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Header Banner */}
      <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <LayoutDashboard className="w-6 h-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-wide">
              Active SIEM Alert Triage Queue
            </h1>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            Real-time incident queue. Manage alert statuses, document forensic notes, and track team response metrics.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handleExportJson}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-4 py-2 rounded-lg text-xs font-semibold flex items-center space-x-2 transition-all"
          >
            <Download className="w-4 h-4 text-cyan-400" />
            <span>Export SIEM JSON</span>
          </button>

          {alerts.length > 0 && (
            <button
              onClick={onClearQueue}
              className="bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800 px-3 py-2 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-all"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Queue</span>
            </button>
          )}
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 grid grid-cols-1 sm:grid-cols-3 gap-3">
        
        {/* Search Input */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by Alert Title, ID, IOC or IP..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Status Filter */}
        <div className="flex items-center space-x-2">
          <Filter className="w-4 h-4 text-slate-500" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg p-2 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Triage Statuses</option>
            <option value="NEW">NEW</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINMENT">CONTAINMENT</option>
            <option value="ESCALATED">ESCALATED</option>
            <option value="RESOLVED">RESOLVED</option>
          </select>
        </div>

        {/* Severity Filter */}
        <div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg p-2 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>

      </div>

      {/* Alert List Queue Table */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="p-3.5">Severity / Risk</th>
                <th className="p-3.5">Alert ID & Title</th>
                <th className="p-3.5">Log Type</th>
                <th className="p-3.5">IOC Count</th>
                <th className="p-3.5">Triage Status</th>
                <th className="p-3.5">Timestamp</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-slate-800/70">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-500 text-sm">
                    No active alerts matching search criteria in queue.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-850/60 transition-colors group">
                    
                    {/* Severity Badge */}
                    <td className="p-3.5">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                            alert.severity === 'CRITICAL'
                              ? 'bg-rose-950 border-rose-700 text-rose-300'
                              : alert.severity === 'HIGH'
                              ? 'bg-amber-950 border-amber-700 text-amber-300'
                              : 'bg-yellow-950 border-yellow-700 text-yellow-300'
                          }`}
                        >
                          {alert.severity}
                        </span>
                        <span className="font-mono text-slate-400 text-[11px] font-semibold">{alert.riskScore}/100</span>
                      </div>
                    </td>

                    {/* Title */}
                    <td className="p-3.5 cursor-pointer" onClick={() => onSelectAlert(alert)}>
                      <div className="font-bold text-slate-100 group-hover:text-cyan-400 transition-colors line-clamp-1">
                        {alert.title}
                      </div>
                      <div className="text-[10px] font-mono text-slate-500 mt-0.5">{alert.id} • {alert.threatActor || 'APT'}</div>
                    </td>

                    {/* Log Type */}
                    <td className="p-3.5 uppercase font-mono text-[10px] text-slate-400">
                      {alert.logType}
                    </td>

                    {/* IOCs */}
                    <td className="p-3.5 font-mono text-slate-300">
                      <span className="bg-slate-800 px-2 py-0.5 rounded border border-slate-700 text-[11px]">
                        {alert.iocs.length} IOCs
                      </span>
                    </td>

                    {/* Status Select */}
                    <td className="p-3.5">
                      <select
                        value={alert.status}
                        onChange={(e) => onUpdateStatus(alert.id, e.target.value as TriageStatus)}
                        className={`text-[10px] font-bold px-2 py-1 rounded border focus:outline-none ${
                          alert.status === 'NEW'
                            ? 'bg-rose-950/80 text-rose-300 border-rose-700'
                            : alert.status === 'INVESTIGATING'
                            ? 'bg-amber-950/80 text-amber-300 border-amber-700'
                            : alert.status === 'CONTAINMENT'
                            ? 'bg-purple-950/80 text-purple-300 border-purple-700'
                            : 'bg-emerald-950/80 text-emerald-300 border-emerald-700'
                        }`}
                      >
                        <option value="NEW">NEW</option>
                        <option value="INVESTIGATING">INVESTIGATING</option>
                        <option value="CONTAINMENT">CONTAINMENT</option>
                        <option value="ESCALATED">ESCALATED</option>
                        <option value="RESOLVED">RESOLVED</option>
                      </select>
                    </td>

                    {/* Timestamp */}
                    <td className="p-3.5 font-mono text-[10px] text-slate-400">
                      {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>

                    {/* Actions */}
                    <td className="p-3.5 text-right space-x-2">
                      <button
                        onClick={() => setActiveNoteModalAlertId(alert.id)}
                        className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs inline-flex items-center space-x-1"
                        title="Add Analyst Note"
                      >
                        <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />
                        <span className="hidden sm:inline">{alert.notes?.length || 0}</span>
                      </button>

                      <button
                        onClick={() => onSelectAlert(alert)}
                        className="p-1.5 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 rounded text-xs inline-flex items-center space-x-1"
                      >
                        <span>Inspect</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>

                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Note Modal */}
      {activeNoteModalAlertId && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-white flex items-center space-x-2">
              <MessageSquare className="w-4 h-4 text-cyan-400" />
              <span>Add Analyst Triage Note</span>
            </h3>

            <textarea
              value={newNoteText}
              onChange={(e) => setNewNoteText(e.target.value)}
              placeholder="e.g., Host isolated via EDR API. Verified Mimikatz DLL execution in memory..."
              rows={4}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />

            <div className="flex items-center justify-end space-x-2">
              <button
                onClick={() => setActiveNoteModalAlertId(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveNote}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-cyan-900/40"
              >
                Save Note
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
