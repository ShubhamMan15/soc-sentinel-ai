# AegisThreat AI — Enterprise Threat Triage & DFIR Platform

AegisThreat AI is an advanced, full-stack threat intelligence, log parsing, and MITRE ATT&CK mapping platform engineered for SOC Analysts, Blue Teams, and DFIR professionals.

## 🛡️ Core Capabilities
- **Multi-Format Log Parser**: Ingests Windows Event Logs, Suricata EVE JSON, AWS CloudTrail, and Syslog.
- **Automated Threat Intelligence**: Extracts IPs, C2 domains, hashes (MD5/SHA256), CVEs, and registry paths.
- **MITRE ATT&CK Enterprise Mapping**: Maps findings directly to ATT&CK Tactics & Techniques.
- **AI Rule Studio**: Synthesizes ready-to-use Sigma YAML rules, YARA signatures, and Suricata NIDS rules.

## 🚀 Local Setup & Installation

```bash
# 1. Clone repository
git clone [https://github.com/ShubhamMan15/soc-sentinel-ai.git](https://github.com/ShubhamMan15/soc-sentinel-ai.git)
cd soc-sentinel-ai

# 2. Install dependencies
npm install

# 3. Launch Development Server
npm run dev
