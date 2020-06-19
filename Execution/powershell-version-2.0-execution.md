
# PowerShell Version 2.0 Execution

Find the execution of PowerShell Version 2.0, eather to discover legacy scripts using version 2 or to find attackers trying to hide from script logging and AMSI.

## Query

```
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "powershell_ise.exe")
| where ProcessCommandLine has "-v 2"
   or ProcessCommandLine has "-v 2.0"
   or ProcessCommandLine has "-version 2"
   or ProcessCommandLine has "-version 2.0"
```
## Category

This query can be used the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v|  |
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

**Contributor:** Manuel Hauch

**GitHub alias:** manuelhauch

**Organization:** Microsoft

**Contact info:** manuel.hauch@microsoft.com
