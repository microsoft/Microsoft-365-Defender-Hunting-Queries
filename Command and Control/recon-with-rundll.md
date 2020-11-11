# Detect rundll.exe being used for reconnaissance and command-and-control

This query was originally published in the threat analytics report, *Trickbot: Pervasive & underestimated*.

[Trickbot](https://attack.mitre.org/software/S0266/) is a very prevalent piece of malware with an array of malicious capabilities. Originally designed to steal banking credentials, it has since evolved into a modular trojan that can deploy other malware, disable security software, and perform command and control (C2) operations.

Trickbot operators are known to use the legitimate Windows process *rundll.exe* to perform malicious activities, such as reconnaissance. Once a target is infected, the operator will drop a batch file that runs several commands and connects to a C2 server for further action.

The following query detects suspicious rundll.exe activity associated with Trickbot campaigns.

See [Office applications launching wscript.exe to run JScript](../Execution/office-apps-launching-wscipt.md) for another query related to Trickbot activity.

## Query

```Kusto
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "rundll32.exe"
// Empty command line
| where InitiatingProcessCommandLine has "rundll32.exe" and InitiatingProcessCommandLine !contains " " 
and InitiatingProcessCommandLine != "" 
| summarize DestinationIPCount = dcount(RemoteIP), make_set(RemoteIP), make_set(RemoteUrl), 
make_set(RemotePort) by InitiatingProcessCommandLine, DeviceId, bin(Timestamp, 5m)
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery | v |  |
| Lateral movement |  |  |
| Collection | v |  |
| Command and control | v |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team
