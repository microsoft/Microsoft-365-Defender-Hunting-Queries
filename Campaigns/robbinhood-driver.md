# Detect loading of vulnerable drivers by Robbinhood ransomware campaign

This query was originally published in the threat analytics report, *Ransomware continues to hit healthcare, critical services*. There is also a related [blog](https://www.microsoft.com/security/blog/2020/04/28/ransomware-groups-continue-to-target-healthcare-critical-services-heres-how-to-reduce-risk/).

[Robbinhood](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/Robinhood.A&ThreatID=2147735370) is ransomware that has been involved in several high-profile incidents, including a 2019 [attack](https://www.nytimes.com/2019/05/22/us/baltimore-ransomware.html) on the city of Baltimore, Maryland. Robbinhood operators often employ a distinctive defense evasion technique, where they load a vulnerable driver on to a target and exploit it, in order to turn off security software -- essentially using the driver as malware.

The following query detects if a device contains the vulnerable drivers. These are often, but not always, implanted on the target by operators seeking to use this technique to turn off security software.

For a query that detects a later stage of this technique, see [Detect security evasion related to the Robbinhood ransomware campaign](robbinhood-driver.md).

## Query

```Kusto
DeviceFileEvents 
| where Timestamp > ago(7d) 
| where SHA1 in('0b15b5cc64caf0c6ad9bd759eb35383b1f718edf3d7ab4cd912d0d8c1826edf8', 
'31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427')
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

## Contributor info

**Contributor:** Microsoft Threat Protection team
