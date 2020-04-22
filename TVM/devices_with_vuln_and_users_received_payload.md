# Devices with vulnerability 

// Author: jan geisbauer 

// @janvonkirchheim

// ------------------------

// 1.	A list of all devices that have this vulnerability

// 2.	A list of all users that uses those devices

// 3.	If these users received .mkv files recently

```
let all_computers_with_vlcvln=
DeviceTvmSoftwareInventoryVulnerabilities 
| where SoftwareName contains "vlc" 
| summarize makelist(DeviceName);
let all_affected_users=
DeviceInfo
| where DeviceName in (all_computers_with_vlcvln)
| mvexpand todynamic(LoggedOnUsers)
| extend ParsedFields = parsejson(LoggedOnUsers)
| project UserName = ParsedFields.UserName
| summarize makelist(tolower(UserName));
let all_email_addresses_aff_users=
AccountInfo
| where tolower(AccountName) in (all_affected_users)
| summarize makelist(tolower(EmailAddress));
EmailAttachmentInfo
| where FileName contains ".mkv"
| where tolower(RecipientEmailAddress) in (all_email_addresses_aff_users)
```

```
// If these users opened those .mkv files

let all_computers_with_vlcvln=
DeviceTvmSoftwareInventoryVulnerabilities 
| where SoftwareName contains "vlc" 
| summarize makelist(DeviceName);
DeviceFileEvents 
| where DeviceName  in (all_computers_with_vlcvln)
| where FileName contains "mkv" 
```
