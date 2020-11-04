# Network Logons with Local Accounts

This query looks for a large number of network-based authentications using local credentials coming from a single source IP address. High counts of logons involving a large number of distinct machines may identify an attacker beachhead within an enterprise.

## Query
```
DeviceLogonEvents
| where Timestamp > ago(30d)
| where AccountDomain == DeviceName and isnotempty( RemoteIP) and RemoteIP !in ('::1','-', '0.0.0.0') and RemoteIP !startswith "127."
| summarize LogonAttempts = count(), DistinctMachines = dcount(DeviceId), Successes = countif(ActionType == 'Success'), RemoteDeviceName = any(RemoteDeviceName)  by RemoteIP, Protocol, LogonType, AccountName
| order by Successes desc, LogonAttempts desc
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement | v |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
**Contributor:** Michael Melone

**GitHub alias:** mjmelone

**Organization:** Microsoft

**Contact info:** @PowershellPoet
