# Detect DoppelPaymer performing reconnaissance with net.exe

This query was originally published in the threat analytics report, *Doppelpaymer: More human-operated ransomware*. There is also a related [blog](https://msrc-blog.microsoft.com/2019/11/20/customer-guidance-for-the-dopplepaymer-ransomware/).

[DoppelPaymer](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/DoppelPaymer!MTB&threatId=-2147205372) is ransomware that is spread manually by human operators. These operators have exhibited extensive knowledge of system administration and common network security misconfigurations. For example, they may use *net.exe* to run reconnaissance and find service accounts to target. They often use stolen credentials from over-privileged service accounts to turn off security software, run malicious commands, and spread malware throughout an organization.

The following query detects the *net.exe* reconnaissance method described above.

The [See also](#See-also) section below lists links to other queries associated with DoppelPaymer.

## Query

```Kusto
// Finds Net commands used to locate high-value accounts
DeviceProcessEvents
| where Timestamp > ago(7d)
| where  FileName == "net.exe"
// Create a set for the command lines
| summarize makeset(ProcessCommandLine) by DeviceId, bin(Timestamp, 5m)
// Other process launches by Net in that same timeframe
| where (set_ProcessCommandLine has "admin" 
and set_ProcessCommandLine has_any("domain", "enterprise", "backup operators"))
and set_ProcessCommandLine has "group" and set_ProcessCommandLine contains "/do"
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
| Lateral movement | v |  |
| Collection |  |  |
| Command and control |  |  |
| Exfiltration |  |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Detect DoppelPaymer operators spreading files with PsExec](../Lateral%20Movement/doppelpaymer-psexec.md)
* [Detect DoppelPaymer operators stopping services](../Defense%20evasion/doppelpaymer-stop-services.md)
* [Detect DoppelPaymer operators dumping credentials with ProcDump](../Credential%20Access/doppelpaymer-procdump.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
