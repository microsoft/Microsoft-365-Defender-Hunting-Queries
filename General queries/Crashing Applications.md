# Crash Detector

This query identifies crashing processes based on parameters passed
to werfault.exe and attempts to find the associated process launch
from DeviceProcessEvents.

## Query

```
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ 'werfault.exe'
| project CrashTime = Timestamp, DeviceId, WerFaultCommand = ProcessCommandLine, CrashProcessId = extract("-p ([0-9]{1,5})", 1, ProcessCommandLine) 
| join kind= inner hint.strategy=shuffle DeviceProcessEvents on DeviceId
| where CrashProcessId == ProcessId and Timestamp between (datetime_add('day',-1,CrashTime) .. CrashTime)
| project-away ActionType
| project-rename ProcessStartTimestamp = Timestamp
```
## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
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
| Misconfiguration | v |  |
| Malware, component |  |  |


## Contributor info

**Contributor:** Michael Melone

**GitHub alias:** mjmelone

**Organization:** Microsoft

**Contact info:** @PowershellPoet
