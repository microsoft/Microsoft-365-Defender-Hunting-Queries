# Jupyter AKA SolarMarker
Jupyter, otherwise known as SolarMarker, is a malware family and cluster of components known for its info-stealing and backdoor capabilities that mainly proliferates through search engine optimization manipulation and malicious advertising in order to successfully encourage users to download malicious templates and documents. This malware has been popular since 2020 and currently is still active as of 2021. 

# Jupyter's SEO Delivery via .TK domains

The following query checks for more than 5 instances of a .tk domain being contacted within a 10 minutes interval. This malware frequently will use anywhere from 5-10 .TK domains as well as other uncommon TLDs such as .blog, .site, .ml, and .gq., which will appear randomly generated and appear after a query to a hosting provider or advertising site from a search engine. Activity would be succeeded by the download of the malicious file. 

## Query
```
DeviceNetworkEvents
| where RemoteUrl endswith ".tk"
| summarize make_set(RemoteUrl) by DeviceId,bin(Timestamp, 10m)
| extend domainCount = array_length(set_RemoteUrl)
| where  domainCount >= 5
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
| Execution |   |  |
| Persistence |  |  |
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
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |


## Contributor info

**Contributor:** Microsoft Threat Protection team
