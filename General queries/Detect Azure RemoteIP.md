# Detect Azure RemoteIP

This query is a function that consumes the publicly available Azure IP address list and checks a list of remote IP addresses against it to see if they are Azure IP addresses or not.

To use this, replace the demo portion of the query (DeviceNetworkEvents | take 10000) with your query with the column name of the IP address to check named RemoteIP. The function will add a new column to the end called IsAzure denoting if the IP address range is in the published list or not.

Please note that over time the URL to the Azure IP address list may need to be updated.

## Query
```
let AzureSubnets = toscalar (
    externaldata (xml:string)
    [
        @'https://download.microsoft.com/download/0/1/8/018E208D-54F8-44CD-AA26-CD7BC9524A8C/PublicIPs_20200824.xml'
    ]
    with (format="txt")
    | extend Subnet = tostring(parse_xml(xml).IpRange.['@Subnet'])
    | where isnotempty(Subnet)
    | summarize make_set(Subnet)
);
let IsItAzure = (SourceData:(RemoteIP:string)) {
    SourceData
    | extend AzureSubnet = AzureSubnets
    | mv-expand AzureSubnet to typeof(string)
    | extend IsAzure = ipv4_is_in_range(RemoteIP, AzureSubnet)
    | summarize IsAzure = max(IsAzure) by RemoteIP
};
// BEGIN SAMPLE QUERY //
DeviceNetworkEvents
| take 10000
// END SAMPLE QUERY
| invoke IsItAzure()
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
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |


## Contributor info
**Contributor:** Michael Melone
**GitHub alias:** mjmelone
**Organization:** Microsoft
**Contact info:** @PowershellPoet
