# Detect DoppelPaymer operators stopping services

This query was originally published in the threat analytics report, *Doppelpaymer: More human-operated ransomware*. There is also a related [blog](https://msrc-blog.microsoft.com/2019/11/20/customer-guidance-for-the-dopplepaymer-ransomware/).

[DoppelPaymer](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/DoppelPaymer!MTB&threatId=-2147205372) is ransomware that is spread manually by human operators. These operators have exhibited extensive knowledge of system administration and common network security misconfigurations. They often use stolen credentials from over-privileged service accounts to turn off security software, run malicious commands, and spread malware throughout an organization.

The following query detects attempts to stop security services.

The [See also](#See-also) section below lists links to other queries associated with DoppelPaymer.

## Query

```Kusto
// Attempts to stop services and allow ransomware execution
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName startswith "psexe" and FileName =~ "powershell.exe" and 
ProcessCommandLine has "stop-service"
and ProcessCommandLine has "sql" and ProcessCommandLine has "msexchange"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|-|-|-|
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
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Detect DoppelPaymer performing reconnaissance with net.exe](../Discovery/doppelpaymer.md)
* [Detect DoppelPaymer operators spreading files with PsExec](../Lateral%20Movement/doppelpaymer-psexec.md)
* [Detect DoppelPaymer operators dumping credentials with ProcDump](../Credential%20Access/doppelpaymer-procdump.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
