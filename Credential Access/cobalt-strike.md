# Find user accounts potentially affected by Cobalt Strike

This query was originally published in the threat analytics report, *Ransomware continues to hit healthcare, critical services*. There is also a related [blog](https://www.microsoft.com/security/blog/2020/04/28/ransomware-groups-continue-to-target-healthcare-critical-services-heres-how-to-reduce-risk/).

In April of 2020, security researchers observed multiple ransomware campaigns using the same set of techniques. The attackers would compromise a web-facing endpoint and employ tools such as Cobalt Strike to steal users' credentials.

[Cobalt Strike](https://www.cobaltstrike.com/) is commercial software used to conduct simulated threat campaigns against a target; however, malicious actors also use Cobalt Strike in real attacks. The software has a large range of [capabilities](https://attack.mitre.org/software/S0154/), including credential theft.

The following query identifies accounts that have logged on to compromised endpoints and have potentially had their credentials stolen.

> [!IMPORTANT]
> This query can only check endpoints onboarded to Microsoft Defender ATP.
>
> ​If you've identified affected endpoints that have not onboarded to Microsoft Defender ATP, check the Windows Event Log for post-compromise logons—those that occur during or after the earliest suspected breach activity—with event ID *4624* and logon type *2* or *10*. For any other timeframe, check for logon type *4* or *5*.

## Query

```Kusto
// Check for specific alerts
AlertInfo
// Attempts to clear security event logs.
| where Title in("Event log was cleared", 
// List alerts flagging attempts to delete backup files.
"File backups were deleted", 
// Potential Cobalt Strike activity - Note that other threat activity can also 
//trigger alerts for suspicious decoded content
"Suspicious decoded content", 
// Cobalt Strike activity
"\'Atosev\' malware was detected", 
"\'Ploty\' malware was detected", 
"\'Bynoco\' malware was detected")
| extend AlertTime = Timestamp
| join AlertEvidence on AlertId 
| distinct DeviceName, AlertTime, AlertId, Title
| join DeviceLogonEvents on $left.DeviceName == $right.DeviceName
// Creating 10 day Window surrounding alert activity
| where Timestamp < AlertTime +5d and Timestamp > AlertTime - 5d 
// Projecting specific columns
| project Title, DeviceName, DeviceId, Timestamp, LogonType, AccountDomain, 
AccountName, AccountSid, AlertTime, AlertId, RemoteIP, RemoteDeviceName
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access | v |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access | v | Attackers will not only dump credentials for accounts that have logged on to interactive or RDP sessions, but will also dump cached credentials and passwords for service accounts and scheduled tasks that are stored in the LSA Secrets section of the registry. |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component | v |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
