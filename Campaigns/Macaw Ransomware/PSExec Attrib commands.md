# Macaw ransomware - PSExec Attrib commands 
Prior to deploying Macaw ransomware in an organization, adversaries wil use Attrib to display file attribute information on multiple drives and all subfolders. 

## Query
This query looks for PSExec utilizing a .bat file to run the attrib command with parameters observed in Macaw incidents.
```
DeviceProcessEvents 
| where InitiatingProcessParentFileName endswith "PSEXESVC.exe" 
| where InitiatingProcessCommandLine has ".bat" 
| where FileName =~ "cmd.exe" and ProcessCommandLine has_all("-s", "-h", "-r", "-a", "*.*") 
| take 100 
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
| Discovery | v |  |
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
