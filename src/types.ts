export type LogType = 'syslog' | 'windows' | 'suricata' | 'cloudtrail' | 'auth_log' | 'apache_nginx' | 'custom';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type TriageStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINMENT' | 'ESCALATED' | 'RESOLVED';

export interface IOC {
  id: string;
  value: string;
  type: 'ip' | 'domain' | 'hash' | 'cve' | 'path' | 'registry' | 'email';
  riskScore: number; // 0-100
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';
  tags: string[];
  geo?: string;
  firstSeen?: string;
  threatActor?: string;
}

export interface MitreMapping {
  tacticId: string;
  tacticName: string;
  techniqueId: string;
  techniqueName: string;
  confidence: number; // 0-100
  description: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event: string;
  actor?: string;
  sourceIp?: string;
  targetUser?: string;
  details?: string;
}

export interface RuleOutput {
  sigmaRule?: string;
  yaraRule?: string;
  suricataRule?: string;
  irPlaybook?: string;
}

export interface AlertItem {
  id: string;
  timestamp: string;
  title: string;
  summary: string;
  severity: Severity;
  riskScore: number; // 0-100
  logType: LogType;
  rawLog: string;
  iocs: IOC[];
  mitreMappings: MitreMapping[];
  timelineEvents: TimelineEvent[];
  recommendations: string[];
  threatActor?: string;
  status: TriageStatus;
  assignee?: string;
  notes?: { id: string; author: string; text: string; timestamp: string }[];
  rules?: RuleOutput;
}

export interface LogSample {
  id: string;
  name: string;
  description: string;
  logType: LogType;
  rawLog: string;
}

export interface ResumeProfile {
  fullName: string;
  currentRole: string;
  targetRole: string;
  keySkills: string[];
  experienceSummary: string;
  customBullets: string[];
}
