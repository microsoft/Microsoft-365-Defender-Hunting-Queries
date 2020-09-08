# Detect DoppelPaymer operators spreading files with PsExec

This query was originally published in the threat analytics report, *Doppelpaymer: More human-operated ransomware*. There is also a related [blog](https://msrc-blog.microsoft.com/2019/11/20/customer-guidance-for-the-dopplepaymer-ransomware/).

[DoppelPaymer](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/DoppelPaymer!MTB&threatId=-2147205372) is ransomware that is spread manually by human operators. These operators have exhibited extensive knowledge of system administration and common network security misconfigurations. They often use stolen credentials from over-privileged service accounts to turn off security software, run malicious commands, and spread malware throughout an organization. More specifically, they use common remote execution tools, such as [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), to move laterally and distribute ransomware.

The following query detects suspicious usage of PsExec to create files on a remote device.

The [See also](#See-also) section below lists links to other queries associated with DoppelPaymer.

## Query

```Kusto
// PsExec creating files on remote machines
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName startswith "psexe"
| summarize CommandCount = dcount(ProcessCommandLine), makeset(ProcessCommandLine),
makeset(FileName) by DeviceId, bin(Timestamp, 1d)
| where CommandCount > 2
| where set_ProcessCommandLine has "copy"
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

* [Detect DoppelPaymer performing reconnaissance with net.exe](../Discovery/doppelpaymer.md)
* [Detect DoppelPaymer operators stopping services](../Defense%20evasion/doppelpaymer-stop-services.md)
* [Detect DoppelPaymer operators dumping credentials with ProcDump](../Credential%20Access/doppelpaymer-procdump.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
