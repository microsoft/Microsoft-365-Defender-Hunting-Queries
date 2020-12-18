# Locate SolarWinds processes launching command prompt with the echo command

This query was originally published in the threat analytics report, *Solorigate supply chain attack*.

Microsoft detects the [2020 SolarWinds supply chain attack](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/) implant and its other components as *Solorigate*. A threat actor silently added malicious code to legitimate software updates for Orion, which is IT monitoring software provided by SolarWinds. In this way, malicious dynamic link libraries (DLLs) were distributed to SolarWinds customers.

The following query detects events when SolarWinds processes attempted to launch the [cmd.exe](https://docs.microsoft.com/windows-server/administration/windows-commands/cmd) command prompt using the `echo` command. Using `echo` in this way is suspicious, as it is an indirect way of issuing commands, and may not be readily detected by certain kinds of security solutions.

More Solorigate-related queries can be found listed under the [See-also](#see-also) section of this document.

## Query

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "SolarWinds.BusinessLayerHost.exe"
| where FileName == "cmd.exe" and ProcessCommandLine has "echo"
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
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

* [Credentials were added to an Azure AD application after 'Admin Consent' permissions granted [Solorigate]](../Persistence/CredentialsAddAfterAdminConsentedToApp[Solorigate].md)
* [Locate Solorigate-related malicious DLLs loaded in memory](solorigate-locate-dll-loaded-in-memory.md)
* [Locate Solorigate-related malicious DLLs created in the system or locally](solorigate-locate-dll-created-locally.md)
* [Locate SolarWinds processes launching suspicious PowerShell commands](solorigate-launching-base64-powershell.md)
* [Locate Solorigate attempting DNS lookup of command-and-control infrastructure](solorigate-c2-lookup-from-nonbrowser.md)
* [Locate Solorigate receiving DNS response](solorigate-c2-lookup-response.md)
* [Get an inventory of SolarWinds Orion software possibly affected by Solorigate](solorigate-possible-affected-software-orion.md)

## Contributor info

**Contributor:** Microsoft Threat Protection team
