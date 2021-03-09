# Anomaly Of MailItemAccess By GraphAPI [Nobelium]

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

## Contributor info

**Contributor:** Shilo Yair
**GitHub alias:** shilo.yair
**Organization:** Microsoft 365 Defender
**Contact info:** shyair@microsoft.com
