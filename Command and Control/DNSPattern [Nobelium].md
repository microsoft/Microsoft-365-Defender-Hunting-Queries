# Nobelium campaign DNS pattern

This query looks for the DGA pattern of the domain associated with the Nobelium campaign, in order to find other domains with the same activity pattern.

This query is inspired by an Azure Sentinel [detection](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/Solorigate-DNS-Pattern.yaml).

## Query

```Kusto
let cloudApiTerms = dynamic(["api", "east", "west"]);
let timeFrame = ago(1d);
let relevantDeviceNetworkEvents = 
  DeviceNetworkEvents  
  | where Timestamp >= timeFrame
  | where RemoteUrl !has "\\" and RemoteUrl !has "/"
  // performance filter
  | where RemoteUrl has_any(cloudApiTerms)
  | project-rename DomainName = RemoteUrl
  | project Timestamp, DomainName, DeviceId, DeviceName;
let relevantDeviceEvents =   
  DeviceEvents 
  | where Timestamp >= timeFrame
   | where ActionType == "DnsQueryResponse"
   // performance filter
   | where AdditionalFields has_any(cloudApiTerms)
   | extend query = extractjson("$.DnsQueryString", AdditionalFields)  
   | where isnotempty(query)
   | project-rename DomainName = query
   | project Timestamp, DomainName, DeviceId, DeviceName;
let relevantIdentityQueryEvents =
  IdentityQueryEvents 
  | where Timestamp >= timeFrame
  | where ActionType == "DNS query"
  | where Protocol == "Dns"
  // performance filter
  | where QueryTarget has_any(cloudApiTerms)
  | project-rename DomainName = QueryTarget   
  | project Timestamp, DomainName, DeviceId = "", DeviceName;
let relevantData =
  relevantIdentityQueryEvents
  | union
  relevantDeviceNetworkEvents  
  | union
  relevantDeviceEvents;
let tokenCreation =
  relevantData
  | extend domain_split = split(DomainName, ".")
  | where tostring(domain_split[-5]) != "" and tostring(domain_split[-6]) == ""
  | extend sub_domain = tostring(domain_split[0])
  | where sub_domain !contains "-"
  | extend sub_directories = strcat(domain_split[-3], " ", domain_split[-4])
  | where sub_directories has_any(cloudApiTerms);
tokenCreation
  //Based on sample communications the subdomain is always between 20 and 30 bytes
  | where strlen(domain_split) < 32 or strlen(domain_split) > 20
  | extend domain = strcat(tostring(domain_split[-2]), ".", tostring(domain_split[-1])) 
  | extend subdomain_no = countof(sub_domain, @"(\d)", "regex")
  | extend subdomain_ch = countof(sub_domain, @"([a-z])", "regex")
  | where subdomain_no > 1
  | extend percentage_numerical = toreal(subdomain_no) / toreal(strlen(sub_domain)) * 100
  | where percentage_numerical < 50 and percentage_numerical > 5
  | summarize rowcount = count(), make_set(DomainName), make_set(DeviceId), make_set(DeviceName), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DomainName
  | order by rowcount asc
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  |
| Privilege escalation |  |  |
| Defense evasion | |  |
| Credential Access |  |  |
| Discovery |  |  |
| Lateral movement |  |  |
| Collection |  |  |
| Command and control | V |  |
| Exfiltration |  |  |
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
* [Nobelium encoded domain in URL](./EncodedDomainURL%20[Nobelium].md)
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
