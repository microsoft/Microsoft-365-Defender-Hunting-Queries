# Python-based attacks on macOS

This query was originally published in the threat analytics report, *Python abuse on macOS*

The Python programming language comes bundled with macOS. In threat intelligence gathered from macOS endpoints, we have observed numerous attacks run with *[EmPyre](https://github.com/EmpireProject/EmPyre)*, a Python-based post-exploitation framework similar to [PowerShell Empire](https://www.powershellempire.com/) for Windows.

The following query checks for Microsoft Office documents that run Python scripts.

## Query

```Kusto
DeviceProcessEvents
| where InitiatingProcessParentFileName in ("Microsoft Word", "Microsoft Excel")
| where FileName =~ "Python"
| where ProcessCommandLine matches regex "[A-Za-z0-9]{50}"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
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
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
