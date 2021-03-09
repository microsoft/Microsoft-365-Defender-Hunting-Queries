# Anomalous use of MailItemAccess by GraphAPI [Nobelium]

This query looks for anomalies in mail item access events made by Graph API. It uses standard deviation to determine if the number of events is anomalous. The query returns all clientIDs where the amount of mail sent per day was larger than value given by the formula, `average + STDThreshold(2.5)*(standard deviation)`.

See [*The MailItemsAccessed mailbox auditing action*](https://docs.microsoft.com/en-us/microsoft-365/compliance/mailitemsaccessed-forensics-investigations?view=o365-worldwide#the-mailitemsaccessed-mailbox-auditing-action).

## Query

```kusto
let starttime = 30d;
let STDThreshold = 2.5;
let allMailAccsessByGraphAPI = CloudAppEvents
| where   ActionType == "MailItemsAccessed"
| where Timestamp between (startofday(ago(starttime))..now())
| where isnotempty(RawEventData['ClientAppId'] ) and RawEventData['AppId'] has "00000003-0000-0000-c000-000000000000"
| extend ClientAppId = tostring(RawEventData['ClientAppId'])
| extend OperationCount = toint(RawEventData['OperationCount'])
| project Timestamp,OperationCount , ClientAppId;
let calculateNumberOfMailPerDay = allMailAccsessByGraphAPI
| summarize NumberOfMailPerDay =sum(toint(OperationCount)) by ClientAppId,format_datetime(Timestamp, 'y-M-d');
let calculteAvgAndStdev=calculateNumberOfMailPerDay
| summarize avg=avg(NumberOfMailPerDay),stev=stdev(NumberOfMailPerDay) by ClientAppId;
calculteAvgAndStdev  | join calculateNumberOfMailPerDay on ClientAppId
| sort by ClientAppId
|  where NumberOfMailPerDay > avg + STDThreshold * stev
| project ClientAppId,Timestamp,NumberOfMailPerDay,avg,stev 
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
| Collection |  |  |
| Command and control |  |  |
| Exfiltration | V |  |
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
* [Anomalous use of MailItemAccess on other users' mailboxes [Nobelium]](../Collection/Anomaly%20of%20MailItemAccess%20by%20Other%20Users%20Mailbox%20[Nobelium].md)
* [Nobelium campaign DNS pattern](../Command%20and%20Control/DNSPattern%20[Nobelium].md)
* [Nobelium encoded domain in URL](../Command%20and%20Control/EncodedDomainURL%20[Nobelium].md)
* [Domain federation trust settings modified](../Defense%20evasion/ADFSDomainTrustMods[Nobelium].md)
* [Discovering potentially tampered devices [Nobelium]](../Defense%20evasion/Discovering%20potentially%20tampered%20devices%20[Nobelium].md)
* [Mail.Read or Mail.ReadWrite permissions added to OAuth application](../Defense%20evasion/MailPermissionsAddedToApplication[Nobelium].md)
* [Suspicious enumeration using Adfind tool](../Discovery/SuspiciousEnumerationUsingAdfind[Nobelium].md)
* [MailItemsAccessed throttling [Nobelium]](./MailItemsAccessed%20Throttling%20[Nobelium].md)
* [OAuth apps accessing user mail via GraphAPI [Nobelium]](./OAuth%20Apps%20accessing%20user%20mail%20via%20GraphAPI%20[Nobelium].md)
* [OAuth apps reading mail via GraphAPI and directly [Nobelium]](./OAuth%20Apps%20reading%20mail%20both%20via%20GraphAPI%20and%20directly%20[Nobelium].md)
* [OAuth apps reading mail via GraphAPI anomaly [Nobelium]](./OAuth%20Apps%20reading%20mail%20via%20GraphAPI%20anomaly%20[Nobelium].md)
* [Credentials were added to an Azure AD application after 'Admin Consent' permissions granted [Nobelium]](../Persistence/CredentialsAddAfterAdminConsentedToApp[Nobelium].md)
* [New access credential added to application or service principal](../Persistence/NewAppOrServicePrincipalCredential[Nobelium].md)
* [Add uncommon credential type to application [Nobelium]](../Privilege%20escalation/Add%20uncommon%20credential%20type%20to%20application%20[Nobelium].md)
* [ServicePrincipalAddedToRole [Nobelium]](../Privilege%20escalation/ServicePrincipalAddedToRole%20[Nobelium].md)

## Contributor info

**Contributor:** Shilo Yair
**GitHub alias:** shilo.yair
**Organization:** Microsoft 365 Defender
**Contact info:** shyair@microsoft.com
