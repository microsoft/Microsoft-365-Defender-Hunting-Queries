# Detect keywords associated with Snip3 campaign emails

Snip3 is a family of related remote access trojans. Although the malware in this family contain numerous small variations, they all exhibit similar behaviors and techniques.

The following query looks for keywords observed in emails involved in a Snip3-associated campaign in April and May of 2021. The emails often have an aviation theme, and the campaign primarily targets organizations involved in travel or  aviation. Note that keywords may change overtime. These emails were used to send malicious legitimate hosting provider links that redirected to VBS documents hosting loaders. The loaders initiate RevengeRAT or AsyncRAT downloads that eventually establish persistence on targets and exfiltrate data.

## Query

```kusto
let SubjectTerms = 
pack_array("Cargo Charter","Airbus Meeting","WorldWide Symposium","Airbus Family","Flight Request",
"Advice from NetJets","May/ACMI","AIRCRAFT PRESENTATION","Airworthiness", "Air Quote", "RFQ #9B17811");
EmailEvents
| where SenderDisplayName has_any(SubjectTerms)
// Optional Sender restriction for organizations with high FP
// where SenderIpv4 == "192.145.239.18"  
| where EmailDirection == "Inbound"  
| join EmailUrlInfo on $left.NetworkMessageId == $right.NetworkMessageId
| where Url has_any("drive.google.com","1drv.ms","onedrive.live.com")
| take 100
```

## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
| Execution |  |  |
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
