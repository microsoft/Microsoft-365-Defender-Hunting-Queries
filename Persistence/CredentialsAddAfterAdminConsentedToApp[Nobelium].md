# Credentials were added to an Azure AD application after 'Admin Consent' permissions granted [Nobelium]

Credentials were added to an application by UserA, after the application was granted admin consent rights by UserB

The Nobelium activity group has been observed adding credentials (x509 keys or password credentials) for one or more legitimate OAuth Applications or Service Principals, usually with existing Mail.Read or Mail.ReadWrite permissions, which grants the ability to read mail content from Exchange Online via Microsoft Graph or Outlook REST. Examples include mail archiving applications.

See [*Customer Guidance on Recent Nation-State Cyber Attacks*](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/) for more on the Nobelium campaign (formerly known as Solorigate).

See [*Grant tenant-wide admin consent to an application*](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/grant-admin-consent) for how to add admin consent to an application.

More Nobelium-related queries can be found listed under the [See also](#see-also) section of this document.

## Query

```Kusto
CloudAppEvents
| where Application == "Office 365"
| where ActionType == "Consent to application."
| where RawEventData.ModifiedProperties[0].Name == "ConsentContext.IsAdminConsent" and RawEventData.ModifiedProperties[0].NewValue == "True"
| extend spnID = tostring(RawEventData.Target[3].ID)
| parse RawEventData.ModifiedProperties[4].NewValue with * "=> [[" dummpy "Scope: " After "]]" *
| extend PermissionsGranted = split(After, "]",0)
| project ConsentTime = Timestamp , AccountDisplayName , spnID , PermissionsGranted
| join (
 CloudAppEvents
 | where Application == "Office 365"
 | where ActionType == "Add service principal credentials." or ActionType == "Update application – Certificates and secrets management "
 | extend spnID = tostring(RawEventData.Target[3].ID) 
 | project AddSecretTime = Timestamp, AccountDisplayName , spnID 
 ) on spnID 
| where ConsentTime < AddSecretTime and AccountDisplayName <> AccountDisplayName1
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence | V |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
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

* [Locate SolarWinds processes launching suspicious PowerShell commands](../Campaigns/launching-base64-powershell[Solorigate].md)
* [Locate Solorigate-related malicious DLLs loaded in memory](../Campaigns/locate-dll-loaded-in-memory[Solorigate].md)
* [Locate Solorigate-related malicious DLLs created in the system or locally](../Campaigns/locate-dll-created-locally[Solorigate].md)
* [Locate SolarWinds processes launching command prompt with the echo command](../Campaigns/launching-cmd-echo[Solorigate].md)
* [Locate Solorigate attempting DNS lookup of command-and-control infrastructure](../Campaigns/c2-lookup-from-nonbrowser[Solorigate]..md)
* [Locate Solorigate receiving DNS response](../Campaigns/c2-lookup-response[Solorigate].md)
* [Get an inventory of SolarWinds Orion software possibly affected by Solorigate](../Campaigns/possible-affected-software-orion[Solorigate].md)
* [View data on software identified as affected by Solorigate](../Campaigns/known-affected-software-orion[Solorigate].md)

## Contributor info

**Contributor:** Tal Maor
**GitHub alias:** @talthemaor
**Organization:** Microsoft 365 Defender
**Contact info:** talma@microsoft.com
