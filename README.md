# Threat Hunt Report: Suspicious Creation of Hidden Folder and File
- [Scenario Creation](https://github.com/huyrocks123/threat-hunting-scenario-suspicious-creation-of-hidden-folder-and-file/blob/main/threat-hunting-scenario-suspicious-creation-of-hidden-folder-and-file-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Windows built-in tools: mkdir.exe, attrib.exe, powershell.exe

##  Scenario

Security monitoring detected suspicious creation of a hidden folder named secret_stuff inside a user's Documents directory, followed by the placement and execution of a PowerShell script inside that folder. This technique is often used by threat actors to hide malicious scripts or tools from casual inspection and evade detection by standard security tools.

The hunt aims to identify the creation of hidden directories, creation of suspicious files within those directories, and subsequent execution of any scripts originating from these hidden locations.

### High-Level TOR-Related IoC Discovery Plan

- **Check DeviceFileEvents** for folder creation events involving a folder named secret_stuff with the hidden attribute set.
- **Check DeviceFileEvents** for script file creation inside the hidden folder.
- **Check DeviceProcessEvents** for execution of scripts launched from paths containing secret_stuff.

---

## Steps Taken

### 1. Detected Creation of the Hidden Folder and Files Inside

To detect suspicious folder creation activity, I queried the DeviceFileEvents table for any file system events where the folder path contained the string \Documents\secret_stuff. At 2025-05-19T21:20:23.1352634Z, a new file named runme.ps1 was created inside the hidden folder C:\Users\huy\Documents\secret_stuff on the device named "huy." The file creation was initiated by powershell_ise.exe, indicating that a PowerShell script was saved in a concealed location, potentially for malicious use.

**Query used to locate events:**
```kql
DeviceFileEvents
| where FolderPath contains @"\Documents\secret_stuff"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ActionType
```
<img width="971" alt="Screenshot 2025-05-19 at 5 46 21 PM" src="https://github.com/user-attachments/assets/ea3e8a4f-a8fb-4c0d-8ec4-5d8140486ff7" />

---

### 2. Identified Execution of Scripts from the Hidden Folder

To confirm malicious activity, I searched the DeviceProcessEvents table for any processes launched with command lines containing the path secret_stuff. At 2025-05-19T21:20:08Z, the folder C:\Users\huy\Documents\secret_stuff was hidden using the command attrib +h. Shortly after, at 2025-05-19T21:20:32Z, the PowerShell script runme.ps1 located in that hidden folder was executed with bypassed execution policy, indicating possible malicious or suspicious activity.

**Query used to locate event:**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "secret_stuff"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, ActionType
```
<img width="833" alt="Screenshot 2025-05-19 at 5 50 56 PM" src="https://github.com/user-attachments/assets/8b43bc7b-439a-4275-b952-0a59a47a0af5" />

---

## Chronological Event Timeline 

### 1. Hidden folder named secret_stuff was created and set to hidden attribute by user huy.

- **Timestamp:** 2025-05-19T21:20:08.0000000Z
- **Event:** The folder C:\Users\huy\Documents\secret_stuff was hidden using the Windows attrib +h command.
- **Action:** The folder was intentionally concealed from casual view to evade detection.
- **Command:** attrib.exe +h C:\Users\huy\Documents\secret_stuff

### 2. A PowerShell script named runme.ps1 was created inside the hidden folder.

- **Timestamp:** 2025-05-19T21:20:23.1352634Z
- **Event:** The file runme.ps1 was created inside the hidden secret_stuff folder by powershell_ise.exe.
- **Action:** Suspicious script file placed in a hidden directory, which may indicate preparation for malicious activity.
- **File Path:** C:\Users\huy\Documents\secret_stuff\runme.ps1

### 3. The PowerShell script runme.ps1 was executed with bypassed execution policy.

- **Timestamp:** 2025-05-19T21:20:32.0000000Z
- **Event:** The script runme.ps1 located in the hidden folder was executed using powershell.exe with the -ExecutionPolicy Bypass flag.
- **Action:** Suspicious script execution from a hidden folder, indicative of potential malicious or unauthorized activity.
- **Command:** powershell.exe -ExecutionPolicy Bypass -File C:\Users\huy\Documents\secret_stuff\runme.ps1
---

## Summary

This threat hunt identified suspicious activity involving the creation and concealment of a hidden folder named secret_stuff within a user’s Documents directory, followed by the placement and execution of a PowerShell script inside that folder. The use of the attrib +h command to hide the folder combined with the execution of a script using powershell.exe with an execution policy bypass strongly suggests an attempt to evade standard detection and potentially execute malicious code. These behaviors align with known adversary techniques to hide payloads and run unauthorized scripts in Windows environments.

The investigation leveraged Microsoft Defender for Endpoint telemetry and Kusto Query Language (KQL) queries to detect these indicators of compromise (IoCs). The findings emphasize the importance of monitoring hidden file system objects and unusual script executions originating from concealed locations as part of an effective security posture.
---

## Response Taken

1. Immediate Containment:
The affected user account and endpoint device were isolated from the network to prevent potential lateral movement or further execution of suspicious scripts.

2. Further Investigation:
Additional analysis was conducted to identify any other hidden directories or scripts created in similar paths across the environment, expanding the search to detect possible related malicious activity.

3. Malware and Script Analysis:
The suspicious PowerShell script runme.ps1 was extracted and analyzed in a sandbox environment to determine its intent, payload, and any associated indicators of compromise.

4. Remediation:
The hidden folder and associated files were deleted after confirming malicious intent. The system was scanned with endpoint protection tools to remove any residual threats.

5. Policy and Detection Enhancements:
Security monitoring rules were updated to alert on the creation of hidden folders, usage of the attrib command to set hidden attributes, and execution of scripts from hidden directories. Endpoint Detection and Response (EDR) configurations were fine-tuned to detect and block script execution with bypassed policies.

6. User Awareness:
The affected user was informed about the incident and educated on security best practices regarding suspicious file handling and script execution to prevent recurrence.


---
