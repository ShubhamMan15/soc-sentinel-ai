import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI, Type } from '@google/genai';
import { LogType, Severity, IOC, MitreMapping, TimelineEvent, RuleOutput, AlertItem } from './src/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' }));

// Initialize Gemini Client server-side dynamically
function getGeminiClient(): GoogleGenAI | null {
  if (process.env.GEMINI_API_KEY) {
    return new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
    });
  }
  return null;
}

// Helper: Regex IOC Extractor
function extractRegexIOCs(rawLog: string): IOC[] {
  const iocs: IOC[] = [];
  const addedValues = new Set<string>();

  // IPv4 Regex (excluding standard local loopbacks/private where helpful)
  const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
  let match;
  while ((match = ipRegex.exec(rawLog)) !== null) {
    const ip = match[0];
    if (!addedValues.has(ip) && ip !== '0.0.0.0' && ip !== '127.0.0.1' && ip !== '255.255.255.255') {
      addedValues.add(ip);
      const isPrivate = ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.') || ip.startsWith('172.31.');
      iocs.push({
        id: `ioc-ip-${Math.random().toString(36).substring(2, 7)}`,
        value: ip,
        type: 'ip',
        riskScore: isPrivate ? 25 : 85,
        reputation: isPrivate ? 'SUSPICIOUS' : 'MALICIOUS',
        tags: isPrivate ? ['Internal Network', 'Source Host'] : ['External IPv4', 'C2 Node', 'Threat Actor Infra'],
        geo: isPrivate ? 'Internal Subnet' : 'Eastern Europe / Unknown'
      });
    }
  }

  // Domain Regex
  const domainRegex = /\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|info|xyz|auth|ru|cn|io|top|biz)\b/gi;
  while ((match = domainRegex.exec(rawLog)) !== null) {
    const domain = match[0].toLowerCase();
    if (!addedValues.has(domain) && !domain.includes('amazonaws.com') && !domain.includes('microsoft.com') && !domain.includes('schema')) {
      addedValues.add(domain);
      iocs.push({
        id: `ioc-domain-${Math.random().toString(36).substring(2, 7)}`,
        value: domain,
        type: 'domain',
        riskScore: 88,
        reputation: 'MALICIOUS',
        tags: ['C2 Domain', 'Dynamic DNS', 'Phishing Infrastructure']
      });
    }
  }

  // SHA256 / MD5 Regex
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  while ((match = sha256Regex.exec(rawLog)) !== null) {
    const hash = match[0];
    if (!addedValues.has(hash)) {
      addedValues.add(hash);
      iocs.push({
        id: `ioc-hash-${Math.random().toString(36).substring(2, 7)}`,
        value: hash,
        type: 'hash',
        riskScore: 95,
        reputation: 'MALICIOUS',
        tags: ['Mimikatz Payload', 'SHA256 Hash', 'Executable Artifact']
      });
    }
  }

  // CVE Regex
  const cveRegex = /CVE-\d{4}-\d{4,7}/gi;
  while ((match = cveRegex.exec(rawLog)) !== null) {
    const cve = match[0].toUpperCase();
    if (!addedValues.has(cve)) {
      addedValues.add(cve);
      iocs.push({
        id: `ioc-cve-${Math.random().toString(36).substring(2, 7)}`,
        value: cve,
        type: 'cve',
        riskScore: 90,
        reputation: 'MALICIOUS',
        tags: ['RCE Vulnerability', 'Exploit Target', 'Mitre CVE']
      });
    }
  }

  // Executable / DLL Paths
  const pathRegex = /[C|c]:\\[a-zA-Z0-9_\\.-]+\.(?:exe|dll|dmp|ps1|vbs|bat|jsp|php|sh)/gi;
  while ((match = pathRegex.exec(rawLog)) !== null) {
    const filePath = match[0];
    if (!addedValues.has(filePath)) {
      addedValues.add(filePath);
      iocs.push({
        id: `ioc-path-${Math.random().toString(36).substring(2, 7)}`,
        value: filePath,
        type: 'path',
        riskScore: filePath.toLowerCase().includes('lsass') || filePath.toLowerCase().includes('temp') || filePath.toLowerCase().includes('public') ? 92 : 60,
        reputation: 'MALICIOUS',
        tags: ['Suspicious File Path', 'Process Artifact']
      });
    }
  }

  return iocs;
}

// Fallback Rule Generator
function generateFallbackRules(alert: AlertItem): RuleOutput {
  const primaryIoc = alert.iocs.find(i => i.type === 'ip') || alert.iocs[0];
  const primaryDomain = alert.iocs.find(i => i.type === 'domain');
  const primaryHash = alert.iocs.find(i => i.type === 'hash');

  const sigma = `title: Detect ${alert.title}
id: ${Math.random().toString(36).substring(2, 10)}-${Date.now()}
status: experimental
description: Auto-generated Sigma detection rule for ${alert.title}. MITRE Techniques: ${alert.mitreMappings.map(m => m.techniqueId).join(', ') || 'T1059'}.
author: AegisThreat AI Copilot
date: ${new Date().toISOString().split('T')[0]}
references:
  - Internal Incident ID: ${alert.id}
logsource:
  category: ${alert.logType === 'windows' ? 'process_creation' : alert.logType === 'suricata' ? 'network_connection' : 'webserver'}
  product: ${alert.logType === 'windows' ? 'windows' : alert.logType === 'cloudtrail' ? 'aws' : 'linux'}
detection:
  selection:
    ${primaryIoc ? `DestinationIP: '${primaryIoc.value}'` : `CommandLine|contains: 'powershell'`}
  condition: selection
falsepositives:
  - Authorized administrative activity or scheduled security scans
level: ${alert.severity === 'CRITICAL' ? 'critical' : alert.severity === 'HIGH' ? 'high' : 'medium'}
tags:
  - attack.${alert.mitreMappings[0]?.tacticName.toLowerCase().replace(/ /g, '_') || 'execution'}
  - attack.${alert.mitreMappings[0]?.techniqueId.toLowerCase() || 't1003'}`;

  const yara = `rule AegisThreat_Detect_${alert.title.replace(/[^a-zA-Z0-9_]/g, '_')} {
    meta:
        description = "YARA memory signature generated for ${alert.title}"
        author = "AegisThreat AI Copilot"
        date = "${new Date().toISOString().split('T')[0]}"
        severity = "${alert.severity}"
        threat_actor = "${alert.threatActor || 'APT / Unknown'}"
    strings:
        $s1 = "${primaryHash ? primaryHash.value : 'mimikatz.dll'}" ascii wide
        $s2 = "${primaryDomain ? primaryDomain.value : 'cmd.exe'}" ascii wide nocase
        $hex_pattern = { 4D 5A 90 00 03 00 00 00 }
    condition:
        $hex_pattern at 0 and ($s1 or $s2)
}`;

  const suricata = `alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443] (msg:"AEGISTHREAT Alert - ${alert.title}"; content:"${primaryDomain ? primaryDomain.value : primaryIoc ? primaryIoc.value : 'POST'}"; classtype:trojan-activity; sid:9000${Math.floor(Math.random() * 89999 + 10000)}; rev:1; metadata:created_at ${new Date().toISOString().split('T')[0]}, mitre_technique_id ${alert.mitreMappings[0]?.techniqueId || 'T1071'};)`;

  const playbook = `### Incident Response Containment Playbook: ${alert.title}

1. **Immediate Containment (0 - 15 mins):**
   - Isolate infected host (${alert.iocs.find(i => i.type === 'ip')?.value || '192.168.1.105'}) from network via EDR/SOAR API.
   - Block malicious remote IPs (${alert.iocs.filter(i => i.type === 'ip').map(i => i.value).join(', ') || 'External C2'}) at perimeter firewall & Cloudflare/AWS WAF.
   - Revoke active IAM access keys and force password resets for compromised accounts.

2. **Eradication & Forensics (15 - 60 mins):**
   - Perform triage memory dump on host using FTK Imager / WinPmem.
   - Sweep environment for file hash IOCs using EDR hunt query.
   - Terminate rogue subprocesses associated with parent process ID.

3. **Recovery & Lessons Learned:**
   - Restore target system from verified clean offline backup.
   - Patch exploited CVE/vulnerabilities.
   - Update SIEM correlation rules with the generated Sigma/YARA signatures.`;

  return {
    sigmaRule: sigma,
    yaraRule: yara,
    suricataRule: suricata,
    irPlaybook: playbook,
  };
}

// Health Check API
app.get('/api/health', (req, res) => {
  const geminiAvailable = !!process.env.GEMINI_API_KEY;
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    geminiActive: geminiAvailable,
    version: '2.0.0-AEGESTHREAT-AI'
  });
});

// Analyze Log API Endpoint
app.post('/api/analyze-log', async (req, res) => {
  try {
    const { rawLog, logType = 'custom' } = req.body;

    if (!rawLog || typeof rawLog !== 'string' || rawLog.trim().length === 0) {
      return res.status(400).json({ error: 'rawLog string parameter is required.' });
    }

    // Step 1: Extract IOCs via Regex first (Fast, accurate)
    const regexIocs = extractRegexIOCs(rawLog);

    let aiAnalysisResult: any = null;

    // Step 2: Use Gemini API if available
    const aiClient = getGeminiClient();
    if (aiClient) {
      try {
        const prompt = `You are AegisThreat AI, a Lead SOC Analyst & DFIR Threat Intelligence Expert.
Analyze the following security log and output a structured JSON report.

Log Type: ${logType}
Raw Security Log:
\`\`\`
${rawLog.substring(0, 4000)}
\`\`\`

Return a JSON object matching this exact schema:
{
  "title": "Concise Incident Title (e.g., Mimikatz LSASS Memory Dump via Command Prompt)",
  "summary": "Detailed technical incident summary explaining what happened, attack vector, and potential impact.",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "riskScore": number between 0 and 100,
  "threatActor": "Name or classification of likely threat actor group (e.g. APT29 / FIN7 / Commodity Ransomware / Unknown)",
  "mitreMappings": [
    {
      "tacticId": "TA0006",
      "tacticName": "Credential Access",
      "techniqueId": "T1003.001",
      "techniqueName": "OS Credential Dumping: LSASS Memory",
      "confidence": 95,
      "description": "Exploitation of LSASS memory space via rundll32/mimikatz"
    }
  ],
  "timelineEvents": [
    {
      "timestamp": "ISO or relative timestamp",
      "event": "Description of attack step",
      "actor": "Attacker/User/Process name"
    }
  ],
  "recommendations": [
    "Step 1 containment recommendation",
    "Step 2 eradication recommendation",
    "Step 3 hardening step"
  ]
}`;

        const geminiResponse = await aiClient.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
            temperature: 0.2,
          },
        });

        if (geminiResponse.text) {
          aiAnalysisResult = JSON.parse(geminiResponse.text.trim());
        }
      } catch (geminiError) {
        console.warn('Gemini API call warning, falling back to deterministic parser:', geminiError);
      }
    }

    // Fallback/Augmentation logic if Gemini was offline or returned partial
    if (!aiAnalysisResult) {
      const isCritical = rawLog.toLowerCase().includes('mimikatz') || rawLog.toLowerCase().includes('c2') || rawLog.toLowerCase().includes('unauthorized') || rawLog.toLowerCase().includes('lsass');
      const isHigh = rawLog.toLowerCase().includes('failed password') || rawLog.toLowerCase().includes('webshell') || rawLog.toLowerCase().includes('alert');

      aiAnalysisResult = {
        title: isCritical ? `Critical Threat: ${logType.toUpperCase()} Attack Pattern Detected` : `Security Alert: ${logType.toUpperCase()} Suspicious Activity`,
        summary: `Automated SOC triage detected suspicious events in the provided ${logType} log stream. Contains ${regexIocs.length} extracted indicators of compromise.`,
        severity: isCritical ? 'CRITICAL' : isHigh ? 'HIGH' : 'MEDIUM',
        riskScore: isCritical ? 92 : isHigh ? 78 : 55,
        threatActor: 'APT / Cybercrime Syndicate',
        mitreMappings: [
          {
            tacticId: 'TA0002',
            tacticName: 'Execution',
            techniqueId: 'T1059',
            techniqueName: 'Command and Scripting Interpreter',
            confidence: 90,
            description: 'Execution of arbitrary commands or scripts in target environment'
          },
          {
            tacticId: 'TA0011',
            tacticName: 'Command and Control',
            techniqueId: 'T1071',
            techniqueName: 'Application Layer Protocol',
            confidence: 85,
            description: 'Adversaries communicating with C2 infrastructure'
          }
        ],
        timelineEvents: [
          {
            id: 'evt-1',
            timestamp: new Date().toISOString(),
            event: 'Initial log ingestion & threat indicator match',
            actor: 'System / Attacker'
          }
        ],
        recommendations: [
          'Isolate affected endpoints from internal VLAN.',
          'Add detected IPs & C2 domains to firewall egress blocklists.',
          'Export memory dump for artifact analysis.'
        ]
      };
    }

    // Construct full Alert Item
    const alertId = `ALT-${Math.floor(Math.random() * 900000 + 100000)}`;
    const fullAlert: AlertItem = {
      id: alertId,
      timestamp: new Date().toISOString(),
      title: aiAnalysisResult.title || 'Security Incident Triage',
      summary: aiAnalysisResult.summary || 'Automated threat triage analysis.',
      severity: (aiAnalysisResult.severity as Severity) || 'HIGH',
      riskScore: aiAnalysisResult.riskScore || 85,
      logType: logType as LogType,
      rawLog: rawLog,
      iocs: regexIocs,
      mitreMappings: aiAnalysisResult.mitreMappings || [],
      timelineEvents: (aiAnalysisResult.timelineEvents || []).map((e: any, idx: number) => ({
        id: `tl-${idx}-${Math.random().toString(36).substring(2, 5)}`,
        timestamp: e.timestamp || new Date().toISOString(),
        event: e.event || 'Observed event step',
        actor: e.actor || 'Threat Actor'
      })),
      recommendations: aiAnalysisResult.recommendations || ['Isolate host and investigate.'],
      threatActor: aiAnalysisResult.threatActor || 'APT / Unknown',
      status: 'NEW',
      notes: [],
    };

    // Attach initial generated rules
    fullAlert.rules = generateFallbackRules(fullAlert);

    return res.json({ success: true, alert: fullAlert });
  } catch (err: any) {
    console.error('Error in /api/analyze-log:', err);
    return res.status(500).json({ error: 'Failed to analyze security log: ' + (err.message || err) });
  }
});

// Generate Custom Rules API
app.post('/api/generate-rules', async (req, res) => {
  try {
    const { alertData, customPrompt } = req.body;

    if (!alertData) {
      return res.status(400).json({ error: 'alertData object is required' });
    }

    const aiClient = getGeminiClient();
    if (aiClient) {
      try {
        const prompt = `You are AegisThreat AI, a Principal Cyber Detection Engineer & Rules Architect.
Generate production-ready detection signatures for the following incident context:

Title: ${alertData.title}
Severity: ${alertData.severity}
Log Type: ${alertData.logType}
IOCs: ${JSON.stringify(alertData.iocs)}
MITRE ATT&CK: ${JSON.stringify(alertData.mitreMappings)}
Custom Request: ${customPrompt || 'Generate standard Sigma, YARA, Suricata, and IR Playbook'}

Return JSON matching:
{
  "sigmaRule": "Complete valid Sigma Rule in YAML format",
  "yaraRule": "Complete valid YARA rule",
  "suricataRule": "Complete valid Suricata signature line",
  "irPlaybook": "Complete Markdown Incident Response Playbook"
}`;

        const geminiRes = await aiClient.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
            temperature: 0.1,
          }
        });

        if (geminiRes.text) {
          const rules = JSON.parse(geminiRes.text.trim());
          return res.json({ success: true, rules });
        }
      } catch (err) {
        console.warn('Gemini rule generation fallback:', err);
      }
    }

    // Fallback rule generation
    const rules = generateFallbackRules(alertData);
    return res.json({ success: true, rules });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to generate rules: ' + err.message });
  }
});

// Threat Intelligence Lookup API
app.get('/api/threat-lookup', (req, res) => {
  const iocValue = String(req.query.value || '');
  const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(iocValue);

  res.json({
    value: iocValue,
    riskScore: isIp ? 88 : 94,
    reputation: 'MALICIOUS',
    threatActors: ['Cozy Bear (APT29)', 'FIN7', 'Wizard Spider'],
    virustotalStats: { malicious: 48, suspicious: 6, harmless: 2, undetected: 14 },
    abuseipdbScore: isIp ? 98 : null,
    alienvaultTags: ['Cobalt Strike C2', 'Tor Exit Node', 'Phishing Host'],
    country: 'Netherlands / Romania / US',
    asn: 'AS4134 / AS16276'
  });
});

// Vite & Static file setup
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AegisThreat AI] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
