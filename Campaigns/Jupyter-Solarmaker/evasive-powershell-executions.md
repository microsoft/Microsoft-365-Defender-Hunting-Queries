# Jupyter's evasive PowerShell executions

The following query checks for instances of Jupyter or SolarMarker malware that launch a lengthy PowerShell script, which in turn reads from encoded strings to parse the next malicious script.  

'''kusto
DeviceProcessEvents 
| where FileName == "powershell.exe" 
| where InitiatingProcessFileName endswith ".tmp" and InitiatingProcessCommandLine has_all("/SL5=","Downloads",".exe") 
| where ProcessCommandLine has_all("-command","=[System.Convert]::FromBase64String([System.IO.File]::ReadAllText($","));remove-item $",".length;$j++){$","$i++;if($i -ge $","=[System.Text.Encoding]::UTF8.GetString($")
'''

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
