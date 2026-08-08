import React, { useState } from 'react';
import { ResumeProfile } from '../types';
import {
  BookOpen,
  Terminal,
  Github,
  Copy,
  Check,
  Download,
  FolderTree,
  UserCheck,
  Sparkles,
  ChevronRight,
  ShieldAlert,
  Code,
  FileText
} from 'lucide-react';

export const PortfolioGuideView: React.FC = () => {
  const [copiedSection, setCopiedSection] = useState<string | null>(null);
  const [resumeData, setResumeData] = useState<ResumeProfile>({
    fullName: 'Cybersecurity Professional',
    currentRole: 'SOC Analyst / DFIR Candidate',
    targetRole: 'Junior / Mid SOC Analyst & Threat Intelligence Engineer',
    keySkills: ['Log Analysis', 'SIEM Triage', 'MITRE ATT&CK', 'Sigma Rules', 'Python/TypeScript', 'Kali Linux', 'Gemini AI Integration'],
    experienceSummary: 'Hands-on experience analyzing Windows Event Logs, Syslog, Suricata network flow, and AWS CloudTrail telemetry. Developed automated detection rules and incident triage workflows.',
    customBullets: []
  });

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(key);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const directoryTreeText = `aegisthreat-ai/
├── .env.example               # Environment variables template
├── metadata.json              # Platform app metadata & permissions
├── package.json               # Node.js dependencies & scripts
├── server.ts                  # Express backend with Gemini AI & Log Parser
├── tsconfig.json              # TypeScript compiler configuration
├── vite.config.ts             # Vite build & server proxy setup
└── src/
    ├── App.tsx                # Main application state & routing hub
    ├── index.css              # Tailwind CSS styling entry point
    ├── main.tsx               # React DOM entry point
    ├── types.ts               # Shared TypeScript interfaces & types
    ├── data/
    │   └── sampleLogs.ts      # Real-world SOC threat log samples
    └── components/
        ├── Navbar.tsx         # Platform navigation bar
        ├── LogParserView.tsx  # Interactive log parsing & AI triage UI
        ├── AnalysisDetailView.tsx # Detailed incident workbench & IOC inspector
        ├── SiemQueueView.tsx  # Live alert queue board & notes manager
        ├── ThreatIntelDashboard.tsx # ATT&CK heatmap & analytics dashboard
        ├── RuleGeneratorView.tsx # AI Sigma / YARA rule studio
        └── PortfolioGuideView.tsx # Deployment & Resume portfolio guide`;

  const kaliCommandsText = `# Step 1: Extract project archive on Kali Linux
mkdir -p ~/projects/aegisthreat-ai
cd ~/projects/aegisthreat-ai
unzip ~/Downloads/aegisthreat-ai.zip -d .

# Step 2: Install dependencies & run development server
npm install
npm run dev

# Step 3: Initialize Git repository & create initial commit
git init
git add .
git commit -m "feat: initial commit of AegisThreat AI Platform"

# Step 4: Link to your GitHub repository and push
git branch -M main
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/aegisthreat-ai.git
git push -u origin main`;

  const generatedReadmeText = `# 🛡️ AegisThreat AI: Cyber Threat Intelligence Triage & Detection Rule Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stack: Full-Stack React + Express](https://img.shields.io/badge/Stack-React%20%7C%20Express%20%7C%20TypeScript-cyan)](https://github.com)
[![AI Integration: Gemini API](https://img.shields.io/badge/AI-Google%20Gemini%202.5%20Flash-emerald)](https://ai.google.dev)

**AegisThreat AI** is an enterprise-grade threat intelligence triage, log parsing, and automated detection rule generation platform engineered for **Blue Teams**, **SOC Analysts**, and **DFIR Professionals**.

---

## 🚀 Key Features

- 🔍 **Multi-Format Security Log Parser**: Parses Windows Event Logs (XML/EVTX), Suricata/Zeek EVE JSON, AWS CloudTrail, Linux \`auth.log\`, Nginx access logs, and Syslog.
- 🎯 **Automated IOC Extraction**: Extracts IPv4s, C2 domains, SHA256 hashes, CVEs, file paths, and registry artifacts via regex & threat intelligence enrichment.
- 📊 **MITRE ATT&CK Enterprise Mapping**: Maps detected event indicators directly to ATT&CK Tactics (TA0002, TA0006, TA0011) and Techniques (T1003, T1059, T1071).
- ⚡ **AI Incident Copilot**: Powered by Google Gemini 2.5 Flash for automated risk scoring (0-100), executive summaries, and 3-step incident containment playbooks.
- 🛠️ **Detection Signature Generator**: Auto-generates **Sigma YAML** rules, **YARA** memory malware signatures, and **Suricata NIDS** signatures.
- 📋 **Live SIEM Alert Queue**: Track alert triage statuses (\`NEW\`, \`INVESTIGATING\`, \`CONTAINMENT\`, \`RESOLVED\`), document analyst notes, and export SIEM JSON data.

---

## 📐 Architecture Diagram

\`\`\`text
┌─────────────────────────────────────────────────────────────────────────┐
│                          AEGISTHREAT AI FRONTEND                        │
│   (React + Vite + Tailwind CSS + Recharts + Lucide Icons)               │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTP / REST API
┌────────────────────────────────────▼────────────────────────────────────┐
│                        EXPRESS BACKEND (server.ts)                       │
│  - Regex IOC Extraction Engine                                           │
│  - Threat Intelligence Enrichment (VirusTotal, AbuseIPDB)                │
│  - Rule Synthesis Engine                                                 │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ @google/genai SDK
┌────────────────────────────────────▼────────────────────────────────────┐
│                      GOOGLE GEMINI 3.6 FLASH API                        │
│  - Triage Summaries, Severity Scoring & Containment Playbooks           │
└─────────────────────────────────────────────────────────────────────────┘
\`\`\`

---

## 🛠️ Installation & Kali Linux Setup

### Prerequisites
- Node.js (v18+)
- npm or yarn
- Kali Linux / Ubuntu environment

\`\`\`bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/soc-sentinel-ai.git
cd soc-sentinel-ai

# 2. Install dependencies
npm install

# 3. Configure environment variables (.env)
cp .env.example .env
# Add GEMINI_API_KEY in .env if available

# 4. Start local development server
npm run dev
\`\`\`

---

## 🧪 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| \`GET\` | \`/api/health\` | Health check & Gemini AI status |
| \`POST\` | \`/api/analyze-log\` | Parse security logs, extract IOCs & map MITRE ATT&CK |
| \`POST\` | \`/api/generate-rules\` | Generate Sigma, YARA, and Suricata detection rules |
| \`GET\` | \`/api/threat-lookup\` | Query IOC threat intelligence feeds |

---

## 👤 Resume & Portfolio Summary Highlights

- Designed and built **SOC Sentinel AI**, a full-stack automated threat intelligence and incident triage workbench handling multi-format security logs.
- Integrated **Google Gemini 3.6 Flash API** for automated severity scoring, threat actor attribution, and containment playbook generation.
- Automated **MITRE ATT&CK framework mapping** and developed an automated rule synthesis engine outputting **Sigma YAML** and **YARA** signatures.

---

## 📄 License
This project is open-source under the [MIT License](LICENSE).
`;

  return (
    <div className="space-y-8">
      
      {/* Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 p-6 rounded-xl border border-slate-800 shadow-xl">
        <div className="space-y-2">
          <div className="flex items-center space-x-2">
            <BookOpen className="w-6 h-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-wide">
              Portfolio Resume & Kali Linux GitHub Deployment Guide
            </h1>
          </div>
          <p className="text-slate-400 text-sm max-w-4xl">
            Complete guide on how to export this application from Google AI Studio, deploy it on your Kali Linux VM, push it to GitHub, and present it to Blue Team & SOC hiring managers.
          </p>
        </div>
      </div>

      {/* SECTION 1: KALI LINUX EXPORT & GITHUB CLI PUSH */}
      <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm sm:text-base font-bold text-white">
              1. Export from AI Studio & Push to GitHub via Kali Linux CLI
            </h2>
          </div>
          <button
            onClick={() => handleCopy(kaliCommandsText, 'kali')}
            className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition-all"
          >
            {copiedSection === 'kali' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            <span>Copy Terminal Commands</span>
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 text-xs text-slate-300">
          <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
            <span className="text-cyan-400 font-bold uppercase text-[10px]">Step A: Export ZIP</span>
            <p className="text-slate-300">Click <strong className="text-white">Settings &gt; Export Code (ZIP)</strong> in top menu of AI Studio to download the project source code ZIP file to your computer.</p>
          </div>

          <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
            <span className="text-cyan-400 font-bold uppercase text-[10px]">Step B: Kali Extract</span>
            <p className="text-slate-300">Transfer or open the ZIP file in your Kali Linux VM terminal. Run <code className="text-cyan-300">unzip</code> and install Node dependencies with <code className="text-cyan-300">npm install</code>.</p>
          </div>

          <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
            <span className="text-cyan-400 font-bold uppercase text-[10px]">Step C: Git Push</span>
            <p className="text-slate-300">Create a new public repository on GitHub (e.g. <code className="text-white">soc-sentinel-ai</code>), link remote origin, and push using Git CLI!</p>
          </div>
        </div>

        <pre className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-emerald-400 overflow-x-auto border border-slate-850">
          {kaliCommandsText}
        </pre>
      </div>

      {/* SECTION 2: PRODUCTION FILE DIRECTORY BLUEPRINT */}
      <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <FolderTree className="w-5 h-5 text-purple-400" />
            <h2 className="text-sm sm:text-base font-bold text-white">
              2. Complete Production Directory Structure Blueprint
            </h2>
          </div>
          <button
            onClick={() => handleCopy(directoryTreeText, 'tree')}
            className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition-all"
          >
            {copiedSection === 'tree' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            <span>Copy Tree</span>
          </button>
        </div>

        <p className="text-xs text-slate-400">
          This full-stack React + Express modular architecture separates concerns between frontend UI components, type definitions, sample logs, and the backend Express AI log parser engine.
        </p>

        <pre className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-purple-300 overflow-x-auto border border-slate-850">
          {directoryTreeText}
        </pre>
      </div>

      {/* SECTION 3: RESUME CUSTOMIZER & INTERVIEW TALKING POINTS */}
      <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <UserCheck className="w-5 h-5 text-amber-400" />
            <h2 className="text-sm sm:text-base font-bold text-white">
              3. Resume Portfolio Customizer & Interview Defense Guide
            </h2>
          </div>
          <span className="text-xs text-amber-400 bg-amber-950 border border-amber-800 px-2.5 py-0.5 rounded-full font-semibold">
            Tailored for Hiring Managers
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          
          {/* Resume Profile Customization Form */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Your Technical Resume Profile</h3>
            
            <div className="space-y-2 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Full Name / Profile Name</label>
                <input
                  type="text"
                  value={resumeData.fullName}
                  onChange={(e) => setResumeData({ ...resumeData, fullName: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Target Hiring Role</label>
                <input
                  type="text"
                  value={resumeData.targetRole}
                  onChange={(e) => setResumeData({ ...resumeData, targetRole: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Core Technical Background Summary</label>
                <textarea
                  value={resumeData.experienceSummary}
                  onChange={(e) => setResumeData({ ...resumeData, experienceSummary: e.target.value })}
                  rows={3}
                  className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>
          </div>

          {/* Generated Resume Bullets & Talking Points */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center space-x-1.5">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span>Resume Project Bullets for Your GitHub / Resume</span>
            </h3>

            <ul className="space-y-2 text-xs text-slate-300 list-disc list-inside">
              <li className="leading-relaxed">
                Architected <strong>SOC Sentinel AI</strong>, an end-to-end cyber threat intelligence triage engine handling multi-format logs (Syslog, Windows Event XML, Suricata JSON, CloudTrail).
              </li>
              <li className="leading-relaxed">
                Integrated <strong>Google Gemini 3.6 Flash LLM</strong> to automate incident severity scoring, MITRE ATT&CK tactic/technique mapping, and 3-step containment playbooks.
              </li>
              <li className="leading-relaxed">
                Engineered an automated detection rule studio generating <strong>Sigma YAML</strong> rules, <strong>YARA malware signatures</strong>, and <strong>Suricata NIDS</strong> rules.
              </li>
              <li className="leading-relaxed">
                Built a live SIEM triage queue board for case management, analyst forensic note taking, and JSON telemetry export.
              </li>
            </ul>

            <div className="bg-slate-900 p-3 rounded border border-slate-800 text-[11px] text-slate-400 space-y-1 mt-2">
              <span className="font-bold text-amber-400 uppercase">Interview Tip: How to explain this in an interview</span>
              <p>
                "When asked about my SOC/DFIR experience, I demonstrate how I built SOC Sentinel AI to automate the repetitive parts of log triage—extracting IOCs and mapping ATT&CK techniques—allowing tier-1 analysts to focus on rapid containment."
              </p>
            </div>
          </div>

        </div>
      </div>

      {/* SECTION 4: PROFESSIONAL README.MD TEMPLATE */}
      <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Github className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm sm:text-base font-bold text-white">
              4. Production README.md Markdown Template
            </h2>
          </div>
          <button
            onClick={() => handleCopy(generatedReadmeText, 'readme')}
            className="text-xs bg-cyan-600 hover:bg-cyan-500 text-white font-semibold px-4 py-2 rounded-lg flex items-center space-x-1.5 transition-all shadow-md shadow-cyan-900/30"
          >
            {copiedSection === 'readme' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            <span>Copy Full README.md Markdown</span>
          </button>
        </div>

        <p className="text-xs text-slate-400">
          This complete README includes badges, architecture diagrams, Kali Linux installation instructions, API docs, and portfolio highlights ready to paste into your GitHub project repository!
        </p>

        <pre className="bg-slate-950 p-4 rounded-lg font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-96 border border-slate-850 leading-relaxed whitespace-pre-wrap">
          {generatedReadmeText}
        </pre>
      </div>

    </div>
  );
};
