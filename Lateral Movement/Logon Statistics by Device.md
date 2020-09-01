# Logon Statistics by Device

This query provides logon statistics per device including the
number of logons that occurred, the number of successes, the 
number of attempts logged, the number of failures, and approx.
how many distinct accounts have registered a logon.

## Query

```
DeviceLogonEvents
| summarize LogonCount = count(), SuccessCount = countif(ActionType == 'LogonSuccess'), AttemptCount = countif(ActionType == 'LogonAttempted'), FailureCount = countif(ActionType == 'LogonFailed'), DistinctAccounts = dcount(AccountSid) by DeviceId, DeviceName
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

