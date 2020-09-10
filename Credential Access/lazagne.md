# Detect credential theft via SAM database export by LaZagne

This query was originally published in the threat analytics report, *Ryuk ransomware*. There is also a related [blog](https://www.microsoft.com/security/blog/2020/03/05/human-operated-ransomware-attacks-a-preventable-disaster/).

[Ryuk](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/Ryuk&threatId=-2147232689) is human-operated ransomware. Much like [DoppelPaymer](https://www.microsoft.com/security/blog/2020/03/05/human-operated-ransomware-attacks-a-preventable-disaster/) ransomware, Ryuk is spread manually, often on networks that are already infected with Trickbot.

During a typical Ryuk campaign, an operator will use [LaZagne](https://github.com/AlessandroZ/LaZagne), a credential theft tool, to access stored passwords for service accounts. The accounts are then used to jump from desktop clients to servers or domain controllers, allowing for better reconnaissance, faster movement, and a more severe impact on the target.

The following query detects credential theft by LaZagne.

The [See also](#See-also) section below lists links to other queries associated with Ryuk ransomware.

## Query

```Kusto
// Find credential theft via SAM database export by LaZagne
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ 'reg.exe'
    and ProcessCommandLine has 'save'
    and ProcessCommandLine has 'hklm'
    and ProcessCommandLine has 'sam'
| project DeviceId, Timestamp, InitiatingProcessId, 
InitiatingProcessFileName, ProcessId, FileName, ProcessCommandLine
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
| Credential Access | v |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Detect PsExec being used to spread files](../Lateral%20Movement/remote-file-creation-with-psexec.md)
* [Detect Cobalt Strike invoked via WMI](../Campaigns/cobalt-strike-invoked-w-wmi.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
