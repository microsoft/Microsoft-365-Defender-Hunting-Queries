# Detect DoppelPaymer operators dumping credentials with ProcDump

This query was originally published in the threat analytics report, *Doppelpaymer: More human-operated ransomware*. There is also a related [blog](https://msrc-blog.microsoft.com/2019/11/20/customer-guidance-for-the-dopplepaymer-ransomware/).

[DoppelPaymer](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/DoppelPaymer!MTB&threatId=-2147205372) is ransomware that is spread manually by human operators. These operators have exhibited extensive knowledge of system administration and common network security misconfigurations. For example, they use SysInternal utilities such as [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to dump credentials from [LSASS](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection). They often use these stolen credentials to turn off security software, run malicious commands, and spread malware throughout an organization.

The following query detects ProcDump being used to dump credentials from LSASS.

The [See also](#See-also) section below lists links to other queries associated with DoppelPaymer.

## Query

```Kusto
// Dumping of LSASS memory using procdump
DeviceProcessEvents
| where Timestamp > ago(7d)
// Command lines that include "lsass" and -accepteula or -ma flags used in procdump
| where (ProcessCommandLine has "lsass" and (ProcessCommandLine has "-accepteula" or
ProcessCommandLine contains "-ma"))
// Omits possible FPs where the full command is just "procdump.exe lsass" 
or (FileName in~ ('procdump.exe','procdump64.exe') and ProcessCommandLine has 'lsass')
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

* [Detect DoppelPaymer performing reconnaissance with net.exe](../Discovery/doppelpaymer.md)
* [Detect DoppelPaymer operators spreading files with PsExec](../Lateral%20Movement/doppelpaymer-psexec.md)
* [Detect DoppelPaymer operators stopping services](../Defense%20evasion/doppelpaymer-stop-services.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
