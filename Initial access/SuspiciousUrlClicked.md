
# SuspiciousUrlClicked  

This query correlates Office 365 Advanced Threat Protection (ATP) signals and Azure Active Directory (Azure AD) identity data to find the relevant endpoint event BrowerLaunchedToOpen in Microsoft Defender ATP.
This event reflects relevant clicks on the malicious URL in the spear-phishing email recognized by Office 365 ATP. 

## Query

```
// Some URL are wrapped with a safelink
// Let's get the the unwrapped url and clicks 
AlertInfo
| where ServiceSource == "Office 365 ATP"
| join (
        AlertEvidence
        | where EntityType =="Url"
        | project AlertId, RemoteUrl 
    )
    on AlertId
| join (
        AlertEvidence
        | where EntityType =="MailMessage"
        | project AlertId, NetworkMessageId 
    )
    on AlertId
// Get the unique NetworkMessageId for the email containing the Url
| distinct RemoteUrl, NetworkMessageId
| join EmailEvents on NetworkMessageId
// Get the email RecipientEmailAddress and ObjectId from the email 
| distinct RemoteUrl, NetworkMessageId, RecipientEmailAddress , RecipientObjectId
| join kind = inner IdentityInfo on $left.RecipientObjectId  == $right.AccountObjectId 
// get the UserSid of the Recipient
| distinct RemoteUrl, NetworkMessageId, RecipientEmailAddress , RecipientObjectId, OnPremSid 
// Get the Url click event on the recipient device.
| join kind = inner  
    (DeviceEvents 
    | where ActionType == "BrowserLaunchedToOpenUrl"| where isnotempty(RemoteUrl) 
    | project UrlDeviceClickTime = Timestamp , UrlClickedByUserSid = RemoteUrl, 
                InitiatingProcessAccountSid, DeviceName, DeviceId, InitiatingProcessFileName
    ) 
   on $left.OnPremSid == $right.InitiatingProcessAccountSid and $left.RemoteUrl == $right.UrlClickedByUserSid
| distinct UrlDeviceClickTime, RemoteUrl, NetworkMessageId, RecipientEmailAddress, RecipientObjectId, 
    OnPremSid, UrlClickedByUserSid, DeviceName, DeviceId, InitiatingProcessFileName 
| sort by UrlDeviceClickTime desc 
```
## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | V | https://attack.mitre.org/techniques/T1566/002/ |
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
| Misconfiguration |  |  |
| Malware, component |  |  |


## Contributor info

Microsoft threat protection team
