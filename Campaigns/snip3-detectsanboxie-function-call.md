# Detect Snip3 loader call to DetectSandboxie function

Snip3 is a family of related remote access trojans. Although the malware in this family contain numerous small variations, they all exhibit similar behaviors and techniques.

The following query looks for a function call to a method named *DetectSandboxie*. This method is used in RevengeRAT and AsyncRAT instances involved in a campaign targeting the aviation industry, first observed in 2021. It has also been associated in the past other malware, such as WannaCry and QuasarRAT. Individual PowerShell functions can be detected in the same way in some instances, though care should be taken to ensure that the command name is unique -- otherwise, this query may return many false positives.

## Query

```kusto
DeviceEvents
| where ActionType == "PowerShellCommand" 
| where AdditionalFields == "{\"Command\":\"DetectSandboxie\"}"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion | v |  |
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
