# Jupyter's evasive PowerShell executions

The following query checks for instances of Jupyter or SolarMarker malware that launch a lengthy PowerShell script, which in turn reads from encoded strings to parse the next malicious script. The initiating process name for this will almost always end in ".tmp" and reflect the original downloaded executable name. 

## Query
```
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_all
("-command","FromBase64String","));remove-item $",".length;$j++){$","$i++;if($i -ge $","-bxor","UTF8.GetString")
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
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |


## Contributor info

**Contributor:** Microsoft Threat Protection team
