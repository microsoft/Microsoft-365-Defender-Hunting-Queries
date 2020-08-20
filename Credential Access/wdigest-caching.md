# Credential harvesting through WDigest cache

This query was originally published in the threat analytics report, *WDigest credential harvesting*.

[WDigest](https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc778868(v=ws.10)?redirectedfrom=MSDN) is a legacy authentication protocol dating from Windows XP. While still used on some corporate networks, this protocol can be manipulated by attackers to dump system credentials.

The Microsoft Security Response Center published an [overview](https://msrc-blog.microsoft.com/2014/06/05/an-overview-of-kb2871997/) of [KB2871997](https://www.catalog.update.microsoft.com/Search.aspx?q=KB2871997), which addresses WDigest use on older platforms. More recent versions of Windows can be protected with a holistic security approach that follows the [principle of least privilege](https://docs.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models).

The following query returns any attempts to turn WDigest credential caching on through the registry.

## Query

```Kusto
​union DeviceRegistryEvents, DeviceProcessEvents
// Find attempts to turn on WDigest credential caching
| where RegistryKey contains "wdigest" and RegistryValueName == "UseLogonCredential" and 
RegistryValueData == "1" or 
// Find processes created with commandlines that attempt to turn on WDigest caching
ProcessCommandLine has "WDigest" and ProcessCommandLine has "UseLogonCredential" and 
ProcessCommandLine has "dword" and ProcessCommandLine has "1"
| project Timestamp, DeviceName, PreviousRegistryValueData,  
RegistryKey, RegistryValueName, RegistryValueData, FileName, ProcessCommandLine, 
InitiatingProcessAccountName, InitiatingProcessFileName, 
InitiatingProcessCommandLine, InitiatingProcessParentFileName
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
| Vulnerability | v |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info

**Contributor:** Microsoft Threat Protection team