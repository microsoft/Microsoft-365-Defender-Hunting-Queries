# Macaw ransomware - Inhibit recovery by disabling tools and functionality 
Prior to deploying Macaw ransomware in an organization, the adversary will disable several tools and functions in order to inhibit later recovery efforts. 

## Query
This query looks for instances where the attacker has disabled various tools including Task Manager, CMD, and Registry Tools.
```
DeviceProcessEvents 
| where ProcessCommandLine has_all ("reg", "add") 
| where ProcessCommandLine has_any("DisableTaskMgr", "DisableCMD", "DisableRegistryTools", "NoRun") and ProcessCommandLine has "REG_DWORD /d \"1\"" 
| summarize ProcessCount = dcount(ProcessCommandLine), make_set(ProcessCommandLine) by InitiatingProcessCommandLine, DeviceId, bin(Timestamp, 3m) 
| where ProcessCount > 2 
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
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware | v |  |

## Contributor info

**Contributor:** Microsoft 365 Defender team
