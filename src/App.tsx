import React, { useState, useEffect } from 'react';
import { AlertItem, TriageStatus } from './types';
import { SAMPLE_LOGS } from './data/sampleLogs';
import { Navbar } from './components/Navbar';
import { LogParserView } from './components/LogParserView';
import { AnalysisDetailView } from './components/AnalysisDetailView';
import { SiemQueueView } from './components/SiemQueueView';
import { ThreatIntelDashboard } from './components/ThreatIntelDashboard';
import { RuleGeneratorView } from './components/RuleGeneratorView';
import { PortfolioGuideView } from './components/PortfolioGuideView';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('triage');
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [geminiActive, setGeminiActive] = useState<boolean>(true);

  // Check backend health & initialize initial seed alerts
  useEffect(() => {
    fetch('/api/health')
      .then((res) => res.json())
      .then((data) => {
        if (data.geminiActive !== undefined) {
          setGeminiActive(data.geminiActive);
        }
      })
      .catch((err) => console.warn('Health check warning:', err));

    // Seed 2 initial alerts for SIEM Queue demonstration
    const seedAlerts: AlertItem[] = [
      {
        id: 'ALT-981422',
        timestamp: new Date().toISOString(),
        title: 'Windows LSASS Credential Dumping (Mimikatz / Event 4688)',
        summary: 'Process creation event detected command prompt invoking rundll32.exe with mimikatz.dll targeting lsass.exe process memory space to extract plaintext domain credentials.',
        severity: 'CRITICAL',
        riskScore: 95,
        logType: 'windows',
        rawLog: SAMPLE_LOGS[0].rawLog,
        iocs: [
          { id: '1', value: 'a2f58e119bc840a1d90823f9901bd348e89f3014a01c897f22314a51e605d81b', type: 'hash', riskScore: 98, reputation: 'MALICIOUS', tags: ['Mimikatz SHA256', 'Payload'] },
          { id: '2', value: 'C:\\Users\\Public\\mimikatz.dll', type: 'path', riskScore: 95, reputation: 'MALICIOUS', tags: ['Suspicious DLL Path'] },
          { id: '3', value: 'admin_svc', type: 'email', riskScore: 70, reputation: 'SUSPICIOUS', tags: ['Compromised Service Account'] }
        ],
        mitreMappings: [
          { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1003.001', techniqueName: 'OS Credential Dumping: LSASS Memory', confidence: 98, description: 'Direct memory dump targeting Local Security Authority Subsystem Service (lsass.exe)' },
          { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059.001', techniqueName: 'Command and Scripting Interpreter: PowerShell', confidence: 92, description: 'PowerShell execution with hidden window flags' }
        ],
        timelineEvents: [
          { id: 't1', timestamp: '2026-08-08T10:14:20Z', event: 'Compromised admin_svc account logged into FIN-DC01', actor: 'admin_svc' },
          { id: 't2', timestamp: '2026-08-08T10:14:22Z', event: 'cmd.exe spawned powershell with obfuscated encoded payload', actor: 'powershell.exe' },
          { id: 't3', timestamp: '2026-08-08T10:14:22Z', event: 'rundll32.exe loaded C:\\Users\\Public\\mimikatz.dll targeting lsass.exe PID 672', actor: 'rundll32.exe' }
        ],
        recommendations: [
          'Immediately isolate FIN-DC01 from domain network via EDR.',
          'Reset kerberos krbtgt account & administrative credentials.',
          'Deploy LSA Protection (RunAsPPL) registry key across all domain controllers.'
        ],
        threatActor: 'FIN7 / APT29',
        status: 'NEW',
        notes: [
          { id: 'n1', author: 'Senior SOC Lead', text: 'Triage initialized. Verified process creation hash in VirusTotal.', timestamp: new Date().toISOString() }
        ],
        rules: {
          sigmaRule: `title: Detect LSASS Dump via Mimikatz DLL
id: 9a2b8e01-2026
status: experimental
description: Detects rundll32 loading mimikatz to dump LSASS process memory.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'mimikatz'
      - 'DumpLSASS'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001`,
          yaraRule: `rule Detect_Mimikatz_Memory_Dump {
    strings:
        $s1 = "DumpLSASS" ascii wide
        $s2 = "mimikatz" ascii wide nocase
    condition:
        all of them
}`,
          suricataRule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"LSASS Memory Dump Alert"; content:"mimikatz"; sid:9000001; rev:1;)`,
          irPlaybook: `1. Isolate host FIN-DC01 immediately.\n2. Revoke service account credentials.`
        }
      },
      {
        id: 'ALT-182930',
        timestamp: new Date().toISOString(),
        title: 'Suricata C2 Beaconing Alert (Cobalt Strike / EVE JSON)',
        summary: 'Suricata NIDS detected suspicious outgoing TLS traffic matching Cobalt Strike Malleable C2 beaconing profile to external IP 185.220.101.5.',
        severity: 'HIGH',
        riskScore: 88,
        logType: 'suricata',
        rawLog: SAMPLE_LOGS[1].rawLog,
        iocs: [
          { id: '1', value: '185.220.101.5', type: 'ip', riskScore: 92, reputation: 'MALICIOUS', tags: ['Cobalt Strike C2', 'External IPv4'], geo: 'Netherlands' },
          { id: '2', value: 'cdn-update-auth.com', type: 'domain', riskScore: 88, reputation: 'MALICIOUS', tags: ['C2 Domain', 'Dynamic DNS'] }
        ],
        mitreMappings: [
          { tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071.001', techniqueName: 'Application Layer Protocol: Web Protocols', confidence: 95, description: 'Encrypted C2 communication masquerading as standard HTTPS telemetry' }
        ],
        timelineEvents: [
          { id: 't1', timestamp: '2026-08-08T11:42:01Z', event: 'Internal host 192.168.1.105 established TCP session to 185.220.101.5:443', actor: '192.168.1.105' }
        ],
        recommendations: [
          'Block 185.220.101.5 and cdn-update-auth.com on edge firewall & Cloudflare WAF.',
          'Perform memory scan on host 192.168.1.105 for Cobalt Strike reflective DLL beacon.'
        ],
        threatActor: 'Wizard Spider / C2 Infra',
        status: 'INVESTIGATING',
        notes: []
      }
    ];

    setAlerts(seedAlerts);
  }, []);

  const handleAnalysisComplete = (newAlert: AlertItem) => {
    setAlerts((prev) => [newAlert, ...prev]);
    setSelectedAlert(newAlert);
  };

  const handleUpdateStatus = (alertId: string, newStatus: TriageStatus) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
    );
    if (selectedAlert && selectedAlert.id === alertId) {
      setSelectedAlert({ ...selectedAlert, status: newStatus });
    }
  };

  const handleAddNote = (alertId: string, noteText: string) => {
    const newNote = {
      id: `note-${Date.now()}`,
      author: 'Lead SOC Analyst',
      text: noteText,
      timestamp: new Date().toISOString(),
    };

    setAlerts((prev) =>
      prev.map((a) =>
        a.id === alertId ? { ...a, notes: [...(a.notes || []), newNote] } : a
      )
    );

    if (selectedAlert && selectedAlert.id === alertId) {
      setSelectedAlert({
        ...selectedAlert,
        notes: [...(selectedAlert.notes || []), newNote],
      });
    }
  };

  const handleClearQueue = () => {
    setAlerts([]);
    setSelectedAlert(null);
  };

  const handleOpenRuleStudio = (alert: AlertItem) => {
    setSelectedAlert(alert);
    setActiveTab('rules');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-900 selection:text-white">
      
      {/* Navigation Bar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          if (tab !== 'triage') setSelectedAlert(null);
        }}
        alertCount={alerts.filter((a) => a.status === 'NEW').length}
        geminiActive={geminiActive}
      />

      {/* Main Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {selectedAlert && activeTab === 'triage' ? (
          <AnalysisDetailView
            alert={selectedAlert}
            onBack={() => setSelectedAlert(null)}
            onUpdateStatus={handleUpdateStatus}
            onOpenRuleStudio={handleOpenRuleStudio}
          />
        ) : (
          <>
            {activeTab === 'triage' && (
              <LogParserView
                onAnalysisComplete={handleAnalysisComplete}
                isLoading={isLoading}
                setIsLoading={setIsLoading}
              />
            )}

            {activeTab === 'queue' && (
              <SiemQueueView
                alerts={alerts}
                onSelectAlert={(alert) => {
                  setSelectedAlert(alert);
                  setActiveTab('triage');
                }}
                onUpdateStatus={handleUpdateStatus}
                onAddNote={handleAddNote}
                onClearQueue={handleClearQueue}
              />
            )}

            {activeTab === 'intel' && <ThreatIntelDashboard alerts={alerts} />}

            {activeTab === 'rules' && <RuleGeneratorView initialAlert={selectedAlert} />}

            {activeTab === 'portfolio' && <PortfolioGuideView />}
          </>
        )}
      </main>

      {/* Global Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <span className="font-bold text-slate-300">AegisThreat AI</span>
            <span>•</span>
            <span>Cyber Threat Intelligence & Incident Response Copilot</span>
          </div>
          <div className="text-slate-500 font-mono text-[11px]">
            Ready for Kali Linux & GitHub Portfolio
          </div>
        </div>
      </footer>

    </div>
  );
}
