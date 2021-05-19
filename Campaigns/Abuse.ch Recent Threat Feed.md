# Abuse.ch Recent Threat Feed

This query will hunt for files matching the current abuse.ch recent threat feed based on Sha256. Currently the query is set up to analyze the last day worth of events, but this is configurable using the MaxAge variable.

## Query
```
let MaxAge = ago(1d);
let AbuseFeed = materialize (
    (externaldata(report:string)
    [@"https://bazaar.abuse.ch/export/csv/recent/"]
    with (format = "txt"))
    | where report !startswith '#'
    | extend report = parse_csv(report)
    | extend FirstSeenUtc = tostring(report[0])
    | project FirstSeenUtc = todatetime(FirstSeenUtc)
        ,SHA256 = trim('[ "]+',tostring(report[1]))
        , MD5 = trim('[ "]+',tostring(report[2]))
        , SHA1 = trim('[ "]+',tostring(report[3]))
        , Reporter = trim('[ "]+',tostring(report[4]))
        , FileName = trim('[ "]+',tostring(report[5]))
        , FileType = trim('[ "]+',tostring(report[6]))
        , MimeType = trim('[ "]+',tostring(report[7]))
        , Signer = iff(report[8] == 'n/a', '', trim('[ "]+',tostring(report[8])))
        , ClamAV = iff(report[9] == 'n/a', '', trim('[ "]+',tostring(report[9])))
        , VTPercent = iff(report[10] == 'n/a', 0.0, todouble(report[10]))
        , ImpHash = iff(report[11] == 'n/a', '', trim('[ "]+',tostring(report[11])))
        , SSDeep = iff(report[12] == 'n/a', '', trim('[ "]+',tostring(report[12])))
        , TLSH = iff(report[13] == 'n/a', '', trim('[ "]+',tostring(report[13])))
);
union (
    AbuseFeed
    | join (
        DeviceProcessEvents
        | where Timestamp > MaxAge
    ) on SHA256
), (
    AbuseFeed
    | join (
        DeviceFileEvents
        | where Timestamp > MaxAge
    ) on SHA256
), ( 
    AbuseFeed
    | join (
        DeviceImageLoadEvents
        | where Timestamp > MaxAge
    ) on SHA256
)
```

...or if you don't care about the details from Malware Bazaar you might consider this slightly more lightweight version

```
let MaxAge = ago(1d);
let AbuseFeed = toscalar (
    (externaldata(report:string)
    [@"https://bazaar.abuse.ch/export/txt/sha256/recent/"]
    with (format = "txt"))
    | where report !startswith '#'
    | summarize make_set(report)
);
union (
    DeviceProcessEvents
    | where Timestamp > MaxAge and SHA256 in (AbuseFeed)
), (
    DeviceFileEvents
    | where Timestamp > MaxAge and SHA256 in (AbuseFeed)
), ( 
    DeviceImageLoadEvents
    | where Timestamp > MaxAge and SHA256 in (AbuseFeed)
)
```

## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
| Persistence | v |  | 
| Privilege escalation | v |  |
| Defense evasion |  |  | 
| Credential Access | v |  | 
| Discovery | v |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration |  |  | 
| Impact | v |  |
| Vulnerability |  |  |
| Exploit | v |  |
| Misconfiguration |  |  |
| Malware, component | v |  |
| Ransomware | v |  |


## Contributor info
**Contributor:** Michael Melone
**GitHub alias:** mjmelone
**Organization:** Microsoft
**Contact info:** @PowershellPoet
