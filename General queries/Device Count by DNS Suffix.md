# Device Count by DNS Suffix

This query will count the number of devices in Defender ATP based
on their DNS suffix.  For a full list of devices with the DNS 
suffix, comment out or remove the last line.

## Query

```
DeviceInfo
| where isnotempty(OSPlatform)
| summarize arg_max(Timestamp, DeviceName) by DeviceId
| extend DeviceMachineName = split(DeviceName, '.')[0]
| extend DeviceDomain = substring(DeviceName, strlen(DeviceMachineName) + 1, strlen(DeviceName) - strlen(DeviceMachineName) - 1)
| summarize count() by DeviceDomain
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
| Lateral movement |  |  | 
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
