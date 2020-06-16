# Detect Office products launching wmic.exe

This query was originally published in the threat analytics report, *Ursnif (Gozi) continues to evolve*.

[Windows Management Instrumentation](https://docs.microsoft.com/windows/win32/wmisdk/about-wmi), or *WMI*, is a legitimate Microsoft framework used to obtain management data and perform administrative tasks on remote devices. However, attackers can also use WMI to gather information about a target or hijack control of a device. The MITRE ATT&CK framework includes [WMI](https://attack.mitre.org/techniques/T1047/) among its list of common enterprise attack techniques.

The following query detects when Microsoft Office software spawns an instance of the WMI command-line utility, *[wmic.exe](https://docs.microsoft.com/windows/win32/wmisdk/wmic)*. This would be fairly unusual under ordinary circumstances and might indicate that an attack is in progress.

## Query

```Kusto
​​// Office products spawning WMI
ProcessCreationEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe") 
and FileName =~"wmic.exe"
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
