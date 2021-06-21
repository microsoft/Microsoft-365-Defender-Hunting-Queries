# Detect malicious use of RegAsm, RegSvcs, and InstallUtil by Snip3

Snip3 is a family of related remote access trojans. Although the malware in this family contain numerous small variations, they all exhibit similar behaviors and techniques.

The following query looks for potentially hollowed processes that may be used to facilitate command-and-control or exfiltration by Snip3 malware. This technique has been used in recent cases to exfiltrate data, including credentials. 

The query may return additional malware or campaigns not necessarily associated with Snip3. However, Microsoft recommends triaging all non-benign results as potential malware.

## Query

```kusto
DeviceNetworkEvents 
| where InitiatingProcessFileName in ("RegSvcs.exe","RegAsm.exe", "InstallUtil.exe") 
| where InitiatingProcessCommandLine in ("\"RegAsm.exe\"","\"RegSvcs.exe\"","\"InstallUtil.exe\"") 
| where InitiatingProcessParentFileName endswith "Powershell.exe"
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
| Command and control | v |  |
| Exfiltration | v |  |
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
