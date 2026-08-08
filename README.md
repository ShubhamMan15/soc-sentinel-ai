<div align="center">

# 🛡️ AegisThreat AI (formerly SOC Sentinel)

**AI-Powered Threat Intelligence Triage, Log Parser, MITRE ATT&CK Mapping & Detection Rule Generator**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stack](https://img.shields.io/badge/Stack-React%20%7C%20TypeScript%20%7C%20Node.js%20%7C%20Tailwind-blueviolet)](#-tech-stack)
[![AI Powered](https://img.shields.io/badge/AI Engine-Google%20Gemini%203.6%20Flash-orange)](#-key-features)

</div>

---

## 📌 Project Overview

**AegisThreat AI** is an enterprise-grade automated Security Operations Center (SOC) copilot and Digital Forensics & Incident Response (DFIR) triage workbench. Built to empower Blue Teams and Security Analysts, AegisThreat AI ingests raw, multi-format security telemetry, extracts Indicators of Compromise (IOCs), maps threat actor behavior to the **MITRE ATT&CK Enterprise Framework**, and synthesizes actionable containment playbooks alongside production-ready detection rules (**Sigma YAML**, **YARA**, **Suricata NIDS**).

---

## 🔥 Key Features

* **Multi-Format Log Ingestion:** Parses Syslog, Windows Event Logs (XML/EVTX), Suricata/Zeek EVE JSON, AWS CloudTrail, Linux `auth.log`, and Web Server (Nginx/Apache) access logs.
* **Automated IOC Extraction:** Identifies IPv4 addresses, domain names, file hashes (SHA256/MD5), CVEs, file paths, and Windows registry keys automatically.
* **AI Incident Triage (Gemini 3.6 Flash):** Computes risk scores (0–100), evaluates severity levels, provides threat actor attribution, and outlines 3-step incident containment playbooks.
* **MITRE ATT&CK Mapping:** Links indicators directly to specific tactics and technique IDs (e.g., *TA0006 Credential Access / T1003.001 LSASS Dumping*).
* **AI Rule Studio:** Auto-synthesizes ready-to-deploy **Sigma YAML**, **YARA signatures**, and **Suricata NIDS rules** based on ingested incident telemetry.
* **Active SIEM Queue & Analytics:** Real-time case tracking (*NEW*, *INVESTIGATING*, *CONTAINMENT*, *RESOLVED*), analyst forensic notes manager, interactive ATT&CK heatmaps, and SIEM JSON telemetry export.

---

## 🏗️ System Architecture

```text
+-----------------------------------------------------------------------------------+
|                                 USER INTERFACE                                    |
|              (React 18 / TypeScript / Tailwind CSS / Lucide Icons)                |
+-----------------------------------------------------------------------------------+
       |                                                                     ^
       | Raw Logs / Ingestion                                                | Triage Telemetry & Rules
       v                                                                     |
+-----------------------------------------------------------------------------------+
|                              EXPRESS BACKEND SERVER                               |
|                     (Node.js / Express / TypeScript Engine)                       |
+-----------------------------------------------------------------------------------+
       |                                                                     ^
       | Log Context / Prompt Assembly                                       | Structured JSON Triage
       v                                                                     |
+-----------------------------------------------------------------------------------+
|                                 AI TRIAGE ENGINE                                  |
|                 (Google Gemini 3.6 Flash API via @google/genai)                   |
+-----------------------------------------------------------------------------------+
