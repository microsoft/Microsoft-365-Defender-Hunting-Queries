# Solorigate DNS Pattern
Looks for DGA pattern of the domain associated with Solorigate in order to find other domains with the same activity pattern.

Query insprired by Azure Sentinel Query https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/Solorigate-DNS-Pattern.yaml
## Query
```
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

## Contributor info
**Contributor:** Stefan Sellmer
**GitHub alias:** @stesell
**Organization:** Microsoft 365 Defender
**Contact info:** stesell@microsoft.com
