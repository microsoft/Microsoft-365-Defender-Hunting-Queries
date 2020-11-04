# Reverse shell associated with ransomware on macOS

This query was originally published in the threat analytics report, *EvilQuest signals the rise of Mac ransomware*.

As of the time of this writing (October 2020), ransomware designed to target macOS is relatively rare. EvilQuest is one of the few examples of this kind of malware on the platform.

The query below can help locate a reverse shell established by an attacker. The command the query searches for is associated with, but not definitely indicative of, EvilQuest infections.

Other queries related to EvilQuest ransomware can be found under the [See also](#see-also) section below.

## Query

```kusto
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ProcessCommandLine has "bash -i >& /dev/tcp/"
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
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control | v |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Ransom note 'say' alert associated with ransomware on macOS](..\Impact\ransom-note-creation-macos.md)
* [Launching questd ransomware using osascript](..\Execution\launch-questd-w-osascript.md)
* [Python usage associated with ransomware on macOS](python-use-by-ransomware-macos.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
