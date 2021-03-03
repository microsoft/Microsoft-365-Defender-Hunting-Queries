# Active Directory Sensitive/Tier 0 Group Modifications
This query shows all modifications to highly sensitive active directory groups (also known as Tier 0). An example of these groups include Domain Admins, Schema Admins and Enterprise Admins.  
More info can be found here:  
https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model#evolution-from-the-legacy-ad-tier-model
https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory

This advanced hunting query requires Defender for Identity be deployed due to it's reliance on the IdentityDirectoryEvents table.

## Query
```
// Detects changes in Tier 0 group memberships
// Command leverages MDI schema
// Execute from https://security.microsoft.com or through the M365D advanced hunting API
let Events = materialize (
IdentityDirectoryEvents
| where ActionType == 'Group Membership changed'
| extend ActivityType = iff(isnotempty(tostring(AdditionalFields['TO.GROUP'])),"Added Account", "Removed Account")
| where isnotempty(AccountSid)
);
let Tier0Adds = (
Events
| where ActivityType == "Added Account"
| extend TargetGroup = tostring(AdditionalFields['TO.GROUP'])
| extend TargetObject = iff(isempty(tostring(AdditionalFields['TARGET_OBJECT.USER'])), tostring(AdditionalFields['TARGET_OBJECT.GROUP']), tostring(AdditionalFields['TARGET_OBJECT.USER']))
| extend TargetType = iff(isempty(tostring(AdditionalFields['TARGET_OBJECT.USER'])), "Security Group", "User Account")
//| extend TargetObject = AdditionalFields['TARGET_OBJECT.USER']
);
let Tier0Removes = (
Events
| where ActivityType == "Removed Account"
| extend TargetGroup = tostring(AdditionalFields['FROM.GROUP'])
| extend TargetObject = iff(isempty(tostring(AdditionalFields['TARGET_OBJECT.USER'])),tostring(AdditionalFields['TARGET_OBJECT.GROUP']), tostring(AdditionalFields['TARGET_OBJECT.USER']))
| extend TargetType = iff(isempty(tostring(AdditionalFields['TARGET_OBJECT.USER'])), "Security Group", "User Account")
);
let Tier0Groups = datatable(TargetGroup:string)
[
'Enterprise Admins',
'Domain Admin',
'Domain Controllers'
'Administrators',
'Enterprise Key Admins',
'Account Operators',
'Organization Management',
'Backup Operators',
'RTCDomainServerAdmins',
'ENTERPRISE DOMAIN CONTROLLERS',
'Cert Publishers',
'Schema Admins',
'DnsAdmins',
'Exchange Recipient Administrators',
'Replicator',
'Read-Only Domain Controllers',
'Print Operators'
];
Tier0Groups
| join (union Tier0Adds, Tier0Removes) on TargetGroup
| project Timestamp, ActionType, ActivityType,TargetType, ActorUpn=AccountUpn, TargetObject, TargetAccountUpn, TargetGroup
// If you are setting up a detection rule in M365D, you'll need to add ReportId and AccountSid to the projected columns
```
## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  | 
| Privilege escalation | V |  |
| Defense evasion |  |  | 
| Credential Access | V |  | 
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
**Contributor:** Dylan J  
**Organization:** Microsoft  
**Twitter:** @Dylface2
