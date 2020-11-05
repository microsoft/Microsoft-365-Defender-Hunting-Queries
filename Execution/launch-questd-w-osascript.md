# Launching questd ransomware using osascript

This query was originally published in the threat analytics report, *EvilQuest signals the rise of Mac ransomware*.

As of the time of this writing (October 2020), ransomware designed to target macOS is relatively rare. EvilQuest is one of the few examples of this kind of malware on the platform.

The query below can detect events associated with the launch of the EvilQuest executable, *questd*, from the shell.

Other queries related to EvilQuest ransomware can be found under the [See also](#see-also) section below.

## Query

```kusto
union DeviceFileEvents, DeviceProcessEvents  
| where Timestamp >= ago(7d)  
| where ProcessCommandLine has "osascript -e do shell script \"launchctl load" and  
ProcessCommandLine contains "questd"
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
| Impact | v |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Ransom note 'say' alert associated with ransomware on macOS](..\Impact\ransom-note-creation-macos.md)
* [Reverse shell associated with ransomware on macOS](..\Command%20and%20Control\reverse-shell-ransomware-macos.md)
* [Python usage associated with ransomware on macOS](..\Command%20and%20Control\python-use-by-ransomware-macos.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
