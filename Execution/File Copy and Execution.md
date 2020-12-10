# File Copy and Execution
This query identifies files that are copied to a device over SMB, then executed within a
specified threshold. Default is 5 seconds, but is configurable by tweaking the value for 
ToleranceInSeconds.
## Query
```
let ToleranceInSeconds = 5;
DeviceNetworkEvents
| where LocalPort == 445 and isnotempty(RemoteIP)
| join kind = inner DeviceLogonEvents on DeviceId
| where Timestamp1 between (Timestamp .. datetime_add('second',ToleranceInSeconds,Timestamp)) and RemoteIP endswith RemoteIP1
| join kind=inner (
    DeviceFileEvents
    | where ActionType in ('FileModified','FileCreated') and (InitiatingProcessFileName =~ 'System' or InitiatingProcessFolderPath endswith "ntoskrnl.exe")
) on DeviceId
| where Timestamp2 between (Timestamp .. datetime_add('second',ToleranceInSeconds,Timestamp))
| join kind=inner DeviceProcessEvents on DeviceId, FolderPath
| where Timestamp3 between (Timestamp .. datetime_add('second',ToleranceInSeconds,Timestamp))
| project Timestamp, DeviceName, RemoteIP, RemotePort, AccountDomain, AccountName, AccountSid, Protocol, LogonId, RemoteDeviceName, IsLocalAdmin, FileName, FolderPath, SHA1, SHA256, MD5, ProcessCommandLine
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
| Persistence | v |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement | v |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration |  |  | 
| Impact | v |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
**Contributor:** Michael Melone
**GitHub alias:** mjmelone
**Organization:** Microsoft
**Contact info:** @PowershellPoet
