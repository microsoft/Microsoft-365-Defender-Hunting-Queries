# Anomalous use of MailItemAccess on other users' mailboxes [Nobelium]

This query looks for users accessing multiple other users' mailboxes, or accessing multiple folders in another user's mailbox.

This query is inspired by an Azure Sentinel [detection](https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/OfficeActivity/AnomolousUserAccessingOtherUsersMailbox.yaml).

## Query

```Kusto
// Adjust this value to exclude historical activity as known good
let LookBack = 30d;
// Adjust this value to change hunting timeframe
let TimeFrame = 14d;
// Adjust this value to alter how many mailbox (other than their own) a user needs to access before being included in results
let UserThreshold = 1;
// Adjust this value to alter how many mailbox folders in other's email accounts a users needs to access before being included in results.
let FolderThreshold = 5;
let relevantMailItems = materialize (
    CloudAppEvents
    | where Timestamp > ago(LookBack)
    | where ActionType == "MailItemsAccessed"
    | where RawEventData['ResultStatus'] == "Succeeded"
    | extend UserId = tostring(RawEventData['UserId'])
    | extend MailboxOwnerUPN = tostring(RawEventData['MailboxOwnerUPN'])
    | where tolower(UserId) != tolower(MailboxOwnerUPN)
    | extend Folders = RawEventData['Folders']
    | where isnotempty(Folders)
    | mv-expand parse_json(Folders)
    | extend foldersPath = tostring(Folders.Path)  
    | where isnotempty(foldersPath)
    | extend ClientInfoString = RawEventData['ClientInfoString']
    | extend MailBoxGuid = RawEventData['MailboxGuid']
    | extend ClientIP = iif(IPAddress startswith "[", extract("\\[([^\\]]*)", 1, IPAddress), IPAddress)
    | project Timestamp, ClientIP, UserId, MailboxOwnerUPN, tostring(ClientInfoString), foldersPath, tostring(MailBoxGuid)    
);
let relevantMailItemsBaseLine = 
    relevantMailItems
    | where Timestamp between(ago(LookBack) ..  ago(TimeFrame))    
    | distinct MailboxOwnerUPN, UserId;
let relevantMailItemsHunting = 
    relevantMailItems
    | where Timestamp between(ago(TimeFrame) .. now())
    | distinct ClientIP, UserId, MailboxOwnerUPN, ClientInfoString, foldersPath, MailBoxGuid; 
relevantMailItemsBaseLine 
    | join kind=rightanti relevantMailItemsHunting
    on MailboxOwnerUPN, UserId
    | summarize FolderCount = dcount(tostring(foldersPath)),
                UserCount = dcount(MailBoxGuid),
                foldersPathSet = make_set(foldersPath),
                ClientInfoStringSet = make_set(ClientInfoString), 
                ClientIPSet = make_set(ClientIP),
                MailBoxGuidSet = make_set(MailBoxGuid),
                MailboxOwnerUPNSet = make_set(MailboxOwnerUPN)
            by UserId
    | where UserCount > UserThreshold or FolderCount > FolderThreshold
    | extend Reason = case( 
                            UserCount > UserThreshold and FolderCount > FolderThreshold, "Both User and Folder Threshold Exceeded",
                            FolderCount > FolderThreshold and UserCount < UserThreshold, "Folder Count Threshold Exceeded",
                            "User Threshold Exceeded"
                            )
    | sort by UserCount desc
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion |  |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection | V |  |
| Command and control |  |  |
| Exfiltration | |  |
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## See also

* [Locate Nobelium implant receiving DNS response](../Campaigns/c2-lookup-from-nonbrowser[Nobelium].md)
* [Locate Nobelium implant receiving DNS response](../Campaigns/c2-lookup-response[Nobelium].md)
* [Compromised certificate [Nobelium]](../Campaigns/compromised-certificate[Nobelium].md)
* [FireEye Red Team tool CVEs [Nobelium]](../Campaigns/fireeye-red-team-tools-CVEs%20[Nobelium].md)
* [FireEye Red Team tool HASHs [Nobelium]](../Campaigns/fireeye-red-team-tools-HASHs%20[Nobelium].md)
* [View data on software identified as affected by Nobelium campaign](../Campaigns/known-affected-software-orion[Nobelium].md)
* [Locate SolarWinds processes launching suspicious PowerShell commands](../Campaigns/launching-base64-powershell[Nobelium].md)
* [Locate SolarWinds processes launching command prompt with the echo command](../Campaigns/launching-cmd-echo[Nobelium].md)
* [Locate Nobelium-related malicious DLLs created in the system or locally](../Campaigns/locate-dll-created-locally[Nobelium].md)
* [Locate Nobelium-related malicious DLLs loaded in memory](../Campaigns/locate-dll-loaded-in-memory[Nobelium].md)
* [Get an inventory of SolarWinds Orion software possibly affected by Nobelium](../Campaigns/possible-affected-software-orion[Nobelium].md)
* [Nobelium campaign DNS pattern](../Command%20and%20Control/DNSPattern%20[Nobelium].md)
* [Nobelium encoded domain in URL](../Command%20and%20Control/EncodedDomainURL%20[Nobelium].md)
* [Domain federation trust settings modified](../Defense%20evasion/ADFSDomainTrustMods[Nobelium].md)
* [Discovering potentially tampered devices [Nobelium]](../Defense%20evasion/Discovering%20potentially%20tampered%20devices%20[Nobelium].md)
* [Mail.Read or Mail.ReadWrite permissions added to OAuth application](../Defense%20evasion/MailPermissionsAddedToApplication[Nobelium].md)
* [Suspicious enumeration using Adfind tool](../Discovery/SuspiciousEnumerationUsingAdfind[Nobelium].md)
* [Anomalous use of MailItemAccess by GraphAPI [Nobelium]](../Exfiltration/Anomaly%20of%20MailItemAccess%20by%20GraphAPI%20[Nobelium].md)
* [MailItemsAccessed throttling [Nobelium]](../Exfiltration/MailItemsAccessed%20Throttling%20[Nobelium].md)
* [OAuth apps accessing user mail via GraphAPI [Nobelium]](../Exfiltration/OAuth%20Apps%20accessing%20user%20mail%20via%20GraphAPI%20[Nobelium].md)
* [OAuth apps reading mail via GraphAPI and directly [Nobelium]](../Exfiltration/OAuth%20Apps%20reading%20mail%20both%20via%20GraphAPI%20and%20directly%20[Nobelium].md)
* [OAuth apps reading mail via GraphAPI anomaly [Nobelium]](../Exfiltration/OAuth%20Apps%20reading%20mail%20via%20GraphAPI%20anomaly%20[Nobelium].md)
* [Credentials were added to an Azure AD application after 'Admin Consent' permissions granted [Nobelium]](../Persistence/CredentialsAddAfterAdminConsentedToApp[Nobelium].md)
* [New access credential added to application or service principal](../Persistence/NewAppOrServicePrincipalCredential[Nobelium].md)
* [Add uncommon credential type to application [Nobelium]](../Privilege%20escalation/Add%20uncommon%20credential%20type%20to%20application%20[Nobelium].md)
* [ServicePrincipalAddedToRole [Nobelium]](../Privilege%20escalation/ServicePrincipalAddedToRole%20[Nobelium].md)

## Contributor info

**Contributor:** Stefan Sellmer
**GitHub alias:** @stesell
**Organization:** Microsoft 365 Defender
**Contact info:** stesell@microsoft.com