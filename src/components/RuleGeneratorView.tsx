import React, { useState } from 'react';
import { AlertItem, RuleOutput } from '../types';
import { Code, FileCode, Copy, Check, Play, RefreshCw, Sparkles, Download, ShieldCheck } from 'lucide-react';

interface RuleGeneratorViewProps {
  initialAlert?: AlertItem | null;
}

export const RuleGeneratorView: React.FC<RuleGeneratorViewProps> = ({ initialAlert }) => {
  const [customScenario, setCustomScenario] = useState<string>(
    initialAlert
      ? `Generate detection rules for incident "${initialAlert.title}". Log Type: ${initialAlert.logType}. IOCs: ${initialAlert.iocs.map(i => i.value).join(', ')}.`
      : 'Generate Sigma YAML, YARA signature, and Suricata SID for PowerShell encoded command execution attempting Kerberoasting (Event ID 4769).'
  );

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [generatedRules, setGeneratedRules] = useState<RuleOutput | null>(
    initialAlert?.rules || {
      sigmaRule: `title: Detect PowerShell Encoded Command Kerberoasting
id: ${Math.random().toString(36).substring(2, 10)}
status: experimental
description: Detects obfuscated powershell execution attempting Kerberoasting via Ticket Granting Service (TGS) requests.
author: SOC Sentinel AI Copilot
date: ${new Date().toISOString().split('T')[0]}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - ' -e '
      - 'Kerberos'
  condition: selection
falsepositives:
  - Administrative management scripts
level: high
tags:
  - attack.credential_access
  - attack.t1558.003`,
      yaraRule: `rule Detect_Kerberoasting_PowerShell_Payload {
    meta:
        description = "Detects in-memory powershell script executing Kerberoasting"
        author = "SOC Sentinel AI"
        severity = "HIGH"
    strings:
        $s1 = "Invoke-Kerberoast" ascii wide nocase
        $s2 = "Get-DomainSPN" ascii wide nocase
        $s3 = "tgssub.dll" ascii wide
    condition:
        2 of ($s1, $s2, $s3)
}`,
      suricataRule: `alert tcp $HOME_NET any -> $EXTERNAL_NET 88 (msg:"SOC-SENTINEL TGS Ticket Request Anomaly (Kerberoasting)"; content:"|a3|"; offset:0; depth:1; classtype:attempted-recon; sid:9000101; rev:1;)`,
      irPlaybook: `### Incident Response Playbook: Kerberoasting Attack
1. **Containment:** Disable or reset password for target Service Principal Names (SPN).
2. **Analysis:** Audit Event ID 4769 logs for high volume of TGS requests with RC4-HMAC encryption.
3. **Eradication:** Force password rotation for compromised service accounts to 25+ characters.`,
    }
  );

  const [copiedFormat, setCopiedFormat] = useState<string | null>(null);

  const handleCopy = (content: string, formatKey: string) => {
    navigator.clipboard.writeText(content);
    setCopiedFormat(formatKey);
    setTimeout(() => setCopiedFormat(null), 2000);
  };

  const handleGenerate = async () => {
    if (!customScenario.trim()) return;

    setIsLoading(true);

    try {
      const mockAlert: AlertItem = initialAlert || {
        id: 'RULE-GEN-01',
        timestamp: new Date().toISOString(),
        title: 'Custom Detection Rule Request',
        summary: customScenario,
        severity: 'HIGH',
        riskScore: 85,
        logType: 'windows',
        rawLog: customScenario,
        iocs: [
          { id: '1', value: '185.220.101.5', type: 'ip', riskScore: 88, reputation: 'MALICIOUS', tags: ['C2'] },
          { id: '2', value: 'mimikatz.dll', type: 'path', riskScore: 92, reputation: 'MALICIOUS', tags: ['Mimikatz'] }
        ],
        mitreMappings: [
          { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1558.003', techniqueName: 'Kerberoasting', confidence: 90, description: 'Kerberoasting ticket request' }
        ],
        timelineEvents: [],
        recommendations: [],
        status: 'NEW'
      };

      const res = await fetch('/api/generate-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alertData: mockAlert, customPrompt: customScenario }),
      });

      const data = await res.json();
      if (data.success && data.rules) {
        setGeneratedRules(data.rules);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Banner */}
      <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 space-y-2">
        <div className="flex items-center space-x-2">
          <Code className="w-6 h-6 text-cyan-400" />
          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-wide">
            AI Detection Rule Studio
          </h1>
        </div>
        <p className="text-slate-400 text-sm max-w-3xl">
          Auto-generate production-grade Sigma YAML detection rules, YARA malware signatures, Suricata network SIDs, and IR Playbooks directly from incident context or custom prompts.
        </p>
      </div>

      {/* Input Prompt Panel */}
      <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-4">
        <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider">
          Threat Scenario / Detection Requirement
        </label>

        <textarea
          value={customScenario}
          onChange={(e) => setCustomScenario(e.target.value)}
          rows={3}
          placeholder="Describe the attack pattern, log source, or IOCs to generate detection rules for..."
          className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
        />

        <div className="flex justify-end">
          <button
            onClick={handleGenerate}
            disabled={isLoading}
            className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs px-5 py-2.5 rounded-lg flex items-center space-x-2 shadow-lg shadow-cyan-900/30 transition-all disabled:opacity-50"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Architecting Signatures...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4 text-amber-300" />
                <span>Generate Rules with Gemini AI</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Generated Rules Display */}
      {generatedRules && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* SIGMA YAML */}
          <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center space-x-2">
                <Code className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">Sigma Rule (YAML)</span>
              </div>
              <button
                onClick={() => handleCopy(generatedRules.sigmaRule || '', 'sigma')}
                className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded flex items-center space-x-1"
              >
                {copiedFormat === 'sigma' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy</span>
              </button>
            </div>
            <pre className="bg-slate-950 p-4 rounded-lg font-mono text-[11px] text-cyan-300 leading-relaxed overflow-x-auto max-h-80 border border-slate-850">
              {generatedRules.sigmaRule}
            </pre>
          </div>

          {/* YARA */}
          <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center space-x-2">
                <FileCode className="w-4 h-4 text-purple-400" />
                <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">YARA Memory Signature</span>
              </div>
              <button
                onClick={() => handleCopy(generatedRules.yaraRule || '', 'yara')}
                className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded flex items-center space-x-1"
              >
                {copiedFormat === 'yara' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy</span>
              </button>
            </div>
            <pre className="bg-slate-950 p-4 rounded-lg font-mono text-[11px] text-purple-300 leading-relaxed overflow-x-auto max-h-80 border border-slate-850">
              {generatedRules.yaraRule}
            </pre>
          </div>

          {/* SURICATA */}
          <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-amber-400" />
                <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">Suricata NIDS Rule</span>
              </div>
              <button
                onClick={() => handleCopy(generatedRules.suricataRule || '', 'suricata')}
                className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded flex items-center space-x-1"
              >
                {copiedFormat === 'suricata' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy</span>
              </button>
            </div>
            <pre className="bg-slate-950 p-4 rounded-lg font-mono text-[11px] text-amber-300 leading-relaxed overflow-x-auto border border-slate-850">
              {generatedRules.suricataRule}
            </pre>
          </div>

          {/* IR PLAYBOOK */}
          <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">Incident Response Playbook</span>
              </div>
              <button
                onClick={() => handleCopy(generatedRules.irPlaybook || '', 'playbook')}
                className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded flex items-center space-x-1"
              >
                {copiedFormat === 'playbook' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy</span>
              </button>
            </div>
            <div className="bg-slate-950 p-4 rounded-lg font-mono text-[11px] text-slate-300 leading-relaxed overflow-x-auto border border-slate-850 whitespace-pre-wrap">
              {generatedRules.irPlaybook}
            </div>
          </div>

        </div>
      )}

    </div>
  );
};
