# Nobelium encoded domain in URL

Looks for a logon domain in the Azure AD logs,  encoded with the same DGA encoding used in the Nobelium campaign.

See [*Important steps for customers to protect themselves from recent nation-state cyberattacks*](https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/) for more on the Nobelium campaign (formerly known as Solorigate).

This query is inspired by an Azure Sentinel [detection](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/Solorigate-Encoded-Domain-URL.yaml).

## Query

```Kusto
let timeFrame = ago(1d);
let relevantDeviceNetworkEvents = 
  DeviceNetworkEvents
  | where Timestamp >= timeFrame
  | where RemoteUrl !has "\\" and RemoteUrl !has "/"
  | project-rename DomainName = RemoteUrl
  | summarize by DomainName;
let relevantDeviceEvents =
  DeviceEvents
  | where Timestamp >= timeFrame
  | where ActionType == "DnsQueryResponse"
  | extend query = extractjson("$.DnsQueryString", AdditionalFields)  
  | where isnotempty(query)
  | project-rename DomainName = query
  | summarize by DomainName;
let relevantIdentityQueryEvents =
  IdentityQueryEvents 
  | where Timestamp >= timeFrame
  | where ActionType == "DNS query"
  | where Protocol == "Dns"
  | project-rename DomainName = QueryTarget
  | summarize by DomainName;
let DnsEvents =
  relevantIdentityQueryEvents
  | union
  relevantDeviceNetworkEvents  
  | union
  relevantDeviceEvents
  | summarize by DomainName;
let dictionary = dynamic(["r","q","3","g","s","a","l","t","6","u","1","i","y","f","z","o","p","5","7","2","d","4","9","b","n","x","8","c","v","m","k","e","w","h","j"]);
let regex_bad_domains =
   AADSignInEventsBeta
   //Collect domains from tenant from signin logs
   | where Timestamp >= timeFrame
   | extend domain = tostring(split(AccountUpn, "@", 1)[0])
   | where domain != ""
   | summarize by domain
   | extend split_domain = split(domain, ".")
   //This cuts back on domains such as na.contoso.com by electing not to match on the "na" portion
   | extend target_string = iff(strlen(split_domain[0]) <= 2, split_domain[1], split_domain[0])
   | extend target_string = split(target_string, "-")  | mv-expand target_string
   //Rip all of the alphanumeric out of the domain name
   | extend string_chars = extract_all(@"([a-z0-9])", tostring(target_string))
   //Guid for tracking our data
   | extend guid = new_guid()//Expand to get all of the individual chars from the domain
   | mv-expand string_chars
   | extend chars = tostring(string_chars)
   //Conduct computation to encode the domain as per actor spec
   | extend computed_char = array_index_of(dictionary, chars)
   | extend computed_char = dictionary[(computed_char + 4) % array_length(dictionary)] 
   | summarize make_list(computed_char) by guid, domain
   | extend target_encoded = tostring(strcat_array(list_computed_char, ""))
   //These are probably too small, but can be edited (expect FP's when going too small)
   | where strlen(target_encoded) > 5
   | distinct target_encoded
   | summarize make_set(target_encoded)
   //Key to join to DNS
   | extend key = 1;
DnsEvents
  | extend key = 1
  //For each DNS query join the malicious domain list
  | join kind=inner (
      regex_bad_domains
  ) on key
  | project-away key
  //Expand each malicious key for each DNS query observed
  | mv-expand set_target_encoded
  //IndexOf allows us to fuzzy match on the substring
  | extend match = indexof(DomainName, set_target_encoded)
  | where match > -1
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
* [Nobelium campaign DNS pattern](./DNSPattern%20[Nobelium].md)
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
