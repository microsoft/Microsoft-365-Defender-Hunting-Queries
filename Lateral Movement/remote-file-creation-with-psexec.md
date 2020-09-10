# Detect PsExec being used to spread files

This query was originally published in the threat analytics report, *Ryuk ransomware*. There is also a related [blog](https://www.microsoft.com/security/blog/2020/03/05/human-operated-ransomware-attacks-a-preventable-disaster/).

[Ryuk](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/Ryuk&threatId=-2147232689) is human-operated ransomware. Much like [DoppelPaymer](https://www.microsoft.com/security/blog/2020/03/05/human-operated-ransomware-attacks-a-preventable-disaster/) ransomware, Ryuk is spread manually, often on networks that are already infected with Trickbot.

Ryuk operators use [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) to manually spread the ransomware to other devices.

The following query detects remote file creation events that might indicate an active attack.

The [See also](#See-also) section below lists links to other queries associated with Ryuk ransomware.

## Query

```Kusto
// Find PsExec creating multiple files on remote machines in a 10-minute window
DeviceFileEvents
| where Timestamp > ago(7d)
// Looking for PsExec by accepteula command flag
| where InitiatingProcessCommandLine has "accepteula"
// Remote machines and file is exe
| where FolderPath has "\\\\" and FileName endswith ".exe"
| extend Exe = countof(InitiatingProcessCommandLine, ".exe")
// Checking to see if command line has 2 .exe or .bat
| where InitiatingProcessCommandLine !has ".ps1" and Exe > 1 or 
InitiatingProcessCommandLine has ".bat"
// Exclusions: Remove the following line to widen scope of AHQ
| where not(InitiatingProcessCommandLine has_any("batch", "auditpol", 
"script", "scripts", "illusive", "rebootrequired"))
| summarize FileCount = dcount(FolderPath), make_set(SHA1), make_set(FolderPath), 
make_set(FileName), make_set(InitiatingProcessCommandLine) by DeviceId, 
TimeWindow=bin(Timestamp, 10m), InitiatingProcessFileName
| where FileCount > 4
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
| Lateral movement | v |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Detect credential theft via SAM database export by LaZagne](../Credential%20Access/lazagne.md)
* [Detect Cobalt Strike invoked via WMI](../Campaigns/cobalt-strike-invoked-w-wmi.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
