# Insider Threat Detection Queries

Intent:
    - Use MTP capability to look for insider threat potential risk indicators
    - Indicators would then serve as the building block for insider threat risk modeling in subsequent tools

 Definition of Insider Threat:

  "The potential for an individual who has or had authorized access to an organization’s assets to use their access, either maliciously or unintentionally, to act in a way that could negatively affect the organization."

This collection of queries describes the different indicators that could be used to model and look for patterns suggesting an increased risk of an individual becoming a potential insider threat.

Note: no single indicator should be used as a lone determinant of insider threat activity, but should be part of an overall program to understand the increased risk to your organization's critical assets. This in turn is used to feed an investigation by a formal insider threat program to look at the context associated with the whole person to understand the implication of a set of indicators.

## Queries

```
// --------------------------------------------------------------------------------------------------------------------------- //
//
//Local Administrator
//
DeviceLogonEvents
| where IsLocalAdmin ==0
| where InitiatingProcessAccountName != "system"

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Zip/Encrypt Sensitive File
//
//This is using a very basic indicator of a "Confidential" document in that it must be stored in a folder named Confidential or Restricted
//Using the Information Protection tags (DeviceFileEvents: SensitivityLabel) might be a more appropriate 
 DeviceFileEvents 
| where
    InitiatingProcessFileName in ("7z.exe", "7zG.exe", "AxCrypt.exe", "BitLocker.exe", "Diskcryptor.exe", "GNUPrivacyGuard.exe", "GPG4Win.exe", "PeaZip.exe", "VeraCrypt.exe", "WinRAR.exe", "WinZip.exe")
    and FolderPath matches regex ".*Confidential|Restricted.*" 
| project Timestamp, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, DeviceName

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Use of Steganography Application
//
// Extend stegnames array with know steganography tools
// We could also use the known hash for steganography tools and use those hashes in this table
let stegnames = pack_array ("camouflage","crypture", "hidensend", "openpuff","picsel","slienteye","steg","xiao");
let ProcessQuery = view(){
DeviceProcessEvents 
| where ProcessCommandLine has_any (stegnames)
};
let FileQuery = view(){
DeviceFileEvents
| where FileName has_any (stegnames)
};
union ProcessQuery, FileQuery
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Screenshots
//
let PRINT_THRESHOLD = 3;  // adjust accordingly
//-----
DeviceProcessEvents 
| where FileName in ("SnippingTool.exe", "ScreenSketch.exe") //and Timestamp > ago(20d)
| summarize count(AccountName) by AccountName
| where count_AccountName > PRINT_THRESHOLD
| sort by count_AccountName desc

//Secondary Query
//This eventtype exists, but seems to be a bit noisy
DeviceEvents
| where ActionType startswith "ScreenshotTaken"

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Personal Email Account
//
//This query searches for connections to specific webmail URLs
let webmailURLs = pack_array ("mail.google.com", "mail.yahoo.com", "mail.protonmail.com"); // Change or append additional webmail URLs
DeviceNetworkEvents 
| where Timestamp > ago(30d)
and RemoteUrl has_any (webmailURLs)

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Access after Termination
//
// Look for any activity by a terminated employee account creating a
// DeviceNetworkEvents after they were released
let TermAccount = 'FORMER_EMPLOYEE_NAME';  // Could also use SID
let ReleaseTime = datetime("01/16/2022 00:00:00");
//
DeviceNetworkEvents 
| where InitiatingProcessAccountName =~ TermAccount
| where Timestamp  > ReleaseTime
| project Timestamp , DeviceName, InitiatingProcessAccountName
| sort by Timestamp  desc

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Download Large File Volume over VPN
//
DeviceFileEvents
| where FileName endswith ".docx" or FileName endswith ".pptx" or FileName endswith ".xlsx" or FileName endswith ".pdf"
| join DeviceNetworkInfo on DeviceId 
| where ConnectedNetworks !contains '"Category":"Domain"'
| summarize TotalFiles=count() by bin(Timestamp, 5m), InitiatingProcessAccountName 
|where TotalFiles >100
| project TotalFiles,Timestamp,InitiatingProcessAccountName

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Usage of Source Control Management (SCM) Tool
//
//Update SCMTools with any additional SCM software specific to an organization.
let SCMTools = pack_array ("git.exe", "svn.exe", "hg.exe");
DeviceProcessEvents
| where FileName has_any (SCMTools) 
or ProcessCommandLine  has_any (SCMTools) 

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Browse to Job Search website
//
// This query finds network communication to specific job search related URL
let partialRemoteUrlToDetect = pack_array (
"careerbuilder.com",
"career",
"glassdoor.com",
"indeed.com",
"internship",
"job",
"linkdin.com",
"monster.com",
"recruit",
"resume",
"simplyhired.com"); 
DeviceNetworkEvents  
| where Timestamp > ago(30d)
and RemoteUrl has_any (partialRemoteUrlToDetect)

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Email to Competitor
//
let competitorDomains = pack_array("competitor", "company2");
EmailEvents
| where RecipientEmailAddress has_any (competitorDomains)
| project TimeEmail = Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, AccountName = tostring(split(SenderFromAddress, "@")[0]);

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Sensitive Information Copied
//
let sensitivepath = pack_array ("confidential", "restricted");
DeviceFileEvents
| where
   FolderPath has_any (sensitivepath) or FileName has_any (sensitivepath)
   
// --------------------------------------------------------------------------------------------------------------------------- //
//
//Administrative Remote Desktop
//
DeviceNetworkEvents 
| where LocalPort == 3389
| join ( DeviceLogonEvents ) on DeviceId 
| where AccountName == "administrator"
| project InitiatingProcessCommandLine, AccountDomain, AccountName, LogonType, IsLocalAdmin, RemoteDeviceName, AdditionalFields

// --------------------------------------------------------------------------------------------------------------------------- //
//
//SSH Connection from untrusted Subnet
//
//Look for SSH connections *not* initiated from the "Management" subnet 
let subnet = "xx.xx.xx.0"; // Adjust for your "Trusted" or "Management" subnet
DeviceNetworkEvents 
| where RemotePort == 22 and LocalIP !contains (subnet)

// --------------------------------------------------------------------------------------------------------------------------- //
// Concealment (Create/Delete Backdoor Account)
DeviceEvents
| where ActionType == "UserAccountCreated"

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Use of Suspicious Executable
//
// Replace and extend with any desired .exes
let SuspiciousEXEs = pack_array ("dnscat2.exe", "dnscat.exe");
DeviceProcessEvents
| where ProcessCommandLine has_any (SuspiciousEXEs) or FileName has_any (SuspiciousEXEs)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessParentFileName, ProcessCommandLine, InitiatingProcessCommandLine

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Open Scanner Software
//
// Replace and extend with any desired .exes
let ScannerEXEs = pack_array ("WFS.exe");
DeviceProcessEvents
| where ProcessCommandLine has_any (ScannerEXEs) or FileName has_any (ScannerEXEs)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessParentFileName, ProcessCommandLine, InitiatingProcessCommandLine

// --------------------------------------------------------------------------------------------------------------------------- //
//
//After-Hours Login
//
//Change the StartTime and EndTime to reflect typical working hours
//This query needs some adjustments, as the default for a datetime object with no date is to only query "today"
let StartTime = datetime("8:00:00 AM");
let EndTime = datetime("5:00:00 PM");
DeviceLogonEvents
| where InitiatingProcessAccountName != "system"
| where Timestamp between ((EndTime) .. StartTime)

// --------------------------------------------------------------------------------------------------------------------------- //
//
//High Volume File Copy Operation
//
//Copy large number of files (over 100) within a 5 minute timespan
//Unfortunately there does not appear to be an easy way to determine that a file originated from a network share
DeviceFileEvents
| where FileName endswith ".docx" or FileName endswith ".pptx" or FileName endswith ".xlsx" or FileName endswith ".pdf"
| summarize TotalFiles=count() by bin(Timestamp, 5m), InitiatingProcessAccountName 
|where TotalFiles >100
| project TotalFiles,Timestamp,InitiatingProcessAccountName 

// --------------------------------------------------------------------------------------------------------------------------- //
//
//Service Account Use
//
let ServiceAccountPrefix = pack_array(       // Declare Account Prefix to identify Service Accounts
    '_',
    'svc',
    'service'
);
let InteractiveTypes = pack_array(           // Declare Interactive logon type names
    'Interactive',
    'CachedInteractive',
    'Unlock',
    'RemoteInteractive',
    'CachedRemoteInteractive',
    'CachedUnlock'
);
let WhitelistedAccounts = pack_array(
      'WhitelistAccount1',
      'WhitelistAccount2'
);                                              // List of accounts that match criteria but are able to logon interactively
DeviceLogonEvents                               // Get all logon events...
| where AccountName !in~ (WhitelistedAccounts)  // ...where it is not a whitelisted account...
| where ActionType == "LogonSuccess"            // ...and the logon was successful...
| where AccountName !contains "$"               // ...and not a machine logon. . .
| where AccountName startswith ServiceAccountPrefix                // ...and not a machine logon. . .
| where LogonType in (InteractiveTypes)         // Determine if the logon is interactive (True=1,False=0)...

//Reference: https://github.com/microsoft/Microsoft-threat-protection-Hunting-Queries/blob/master/Lateral%20Movement/ServiceAccountsPerformingRemotePS.txt
// --------------------------------------------------------------------------------------------------------------------------- //
//
//Outbound Email with Attachments of Interest
//
// This snippet looks for anyone sending code as an attachment based on
// extension.  A more advanced version would use depend on DLP to determine
// attachment type and indicate as a potential field in EmailAttachmentInfo
//
// whitelist any senders
let okaySenders = dynamic(["postmaster@finnet.onmicrosoft.com"]);
//
let eattach = EmailAttachmentInfo
| where SenderFromAddress !in (okaySenders)
| project Timestamp, FileName, SenderFromAddress, NetworkMessageId
// add list of extensions relevant to your organization
| where FileName endswith ".cs" or
        FileName endswith ".c" or
        FileName endswith ".h" or
        FileName endswith ".hpp" or
        FileName endswith ".hxx" or
        FileName endswith ".cpp" or
        FileName endswith ".hh" or
        FileName endswith ".cpp" or
        FileName endswith ".cc" or
        FileName endswith ".cxx" or
        FileName endswith ".py";
// get the emails associated with attachements
eattach
| join EmailEvents on NetworkMessageId
// Remove (or change) this line for email direction
| where DeliveryLocation == "On-premises/external"
//
// report stats
// include this line if you want just summary of how often it occurs
//| summarize outbound_emails_with_attachments=count()
// or include this line if you want to know per sender
//| summarize outbound_emails_with_attachments=count() by SenderFromAddress

// --------------------------------------------------------------------------------------------------------------------------- //
//Backdoor Account Usage
//
//Look for newly created local accounts that log in within 30 minutes
DeviceEvents
| where ActionType == "UserAccountCreated"
| project DeviceId , AccountName, Start=Timestamp
| join kind=inner
    (
    DeviceLogonEvents 
    | project AccountName, DeviceId, End=Timestamp
    ) on AccountName 
| where (End - Start) between (0min.. 30min)
//Reference https://github.com/microsoft/Microsoft-threat-protection-Hunting-Queries/blob/master/Persistence/Create%20account.txt 

// --------------------------------------------------------------------------------------------------------------------------- //
//Usage of Cloud Storage//
//
let CloudEXEs = pack_array ("dropbox.exe", "box.exe", "Googledrivesync.exe");
DeviceNetworkEvents
| where InitiatingProcessFileName has_any (CloudEXEs)
 and isnotempty(RemoteUrl)
 
// --------------------------------------------------------------------------------------------------------------------------- //
//
//Examples that combine multiple indicators//
//
//This query searches for 
//email events matching the desired recipients . . .
EmailEvents
| where RecipientEmailAddress contains "competitor"
//. . .that contain attachments. . .
and AttachmentCount >=1
| join (
EmailAttachmentInfo
| where isnotempty(SHA256)
)on NetworkMessageId
//. . .which were generated from the specific zip or encryption executables . . .
| join (
DeviceFileEvents
| where InitiatingProcessFileName in ("7z.exe", "7zG.exe", "AxCrypt.exe", "BitLocker.exe", "Diskcryptor.exe", "GNUPrivacyGuard.exe", "GPG4Win.exe", "PeaZip.exe", "VeraCrypt.exe", "WinRAR.exe", "WinZip.exe")
//. . .and  that came from a specific “confidential” or “restricted” folder (could substitute sensitivity labels).
and FolderPath matches regex ".*Confidential|Restricted.*"
) on FileName
```
## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | V |  |
| Execution |  |  |
| Persistence | v |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration | v |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |


## Contributor info

**Contributor:** SEI National Insider Threat Center

**GitHub alias:** sei-nitc

**Organization:** Carnegie Mellon University Software Engineering Institute

**Contact info:** insider-threat-feedback@cert.org

&copy; Carnegie Mellon University, 2020. All rights reserved
