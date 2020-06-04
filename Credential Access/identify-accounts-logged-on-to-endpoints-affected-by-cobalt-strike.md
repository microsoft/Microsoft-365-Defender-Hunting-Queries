
# Identify accounts that have logged on to endpoints affected by Cobalt Strike

This query was originally published in the threat analytics report, *Ransomware continues to hit healthcare, critical services*.

It finds all user accounts that have logged on to an endpoint affected by [Cobalt Strike](https://attack.mitre.org/software/S0154/), a penetration tool.

Assume that all credentials on endpoints affected by Cobalt Strike were available to attackers and that all associated accounts are compromised. Note that attackers will not only dump credentials for accounts that have logged on to interactive or RDP sessions, but will also dump cached credentials and passwords for service accounts and scheduled tasks that are stored in the LSA Secrets section of the registry.

## Query

```Kusto
// Check for specific alerts
AlertInfo
// This checks over the previous 7 days -- alter Timestamp value for other periods
| where Timestamp > ago(7d)
// Attempts to clear security event logs.
| where Title in("Event log was cleared",
// List alerts flagging attempts to delete backup files.
"File backups were deleted",
// Potential Cobalt Strike activity - Note that other threat activity can also trigger alerts for suspicious decoded content
"Suspicious decoded content",
// Cobalt Strike activity
"\'Atosev\' malware was detected",
"\'Bynoco\' malware was detected",
"\'Cosipor\' malware was detected")
| extend AlertTime = Timestamp
| join AlertEvidence on AlertId
| project DeviceId, AlertTime, AlertId, Title
| join DeviceLogonEvents on DeviceId
// Creating 10 day Window surrounding alert activity
| where Timestamp < AlertTime +5d and Timestamp > AlertTime - 5d
// Projecting specific columns
| project Title, DeviceName, DeviceId, Timestamp, LogonType, AccountDomain,
AccountName, AccountSid, AlertTime, AlertId, RemoteIP, RemoteDeviceName
```

## Category

This query can be used the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access | v | If you've identified affected endpoints that have not onboarded to Microsoft Defender ATP, check the Windows Event Log for post-compromise logons — those that occur after or during the earliest suspected breach activity — with *event ID 4624* and *logon type 2* or *10*. For any other timeframe, check for *logon type 4* or *5*. |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
