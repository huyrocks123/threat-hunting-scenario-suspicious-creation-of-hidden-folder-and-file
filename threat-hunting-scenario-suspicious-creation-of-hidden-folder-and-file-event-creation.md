# Threat Event (Suspicious Creation of Hidden Folder and File)
**Attacker creates a hidden folder and places a suspicious script inside to evade casual detection**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. The attacker opens a command prompt or PowerShell window.
2. Creates a new folder named secret_stuff in the user's Documents directory:
```kql
mkdir $env:USERPROFILE\Documents\secret_stuff
```
4. Sets the folder attribute to "hidden" so it doesn’t show up in File Explorer by default:
```kql
attrib +h $env:USERPROFILE\Documents\secret_stuff
```
5. Creates a simple script file inside the hidden folder, e.g., a PowerShell script named runme.ps1 with some basic content:
```kql
echo "Write-Output 'This is a test script'" > $env:USERPROFILE\Documents\secret_stuff\runme.ps1
```
6. Executes the script to generate process logs:
```kql
powershell.exe -ExecutionPolicy Bypass -File $env:USERPROFILE\Documents\secret_stuff\runme.ps1
```

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose**| 	Detect creation of hidden folders and new script files. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/deviceprocessevents-table |
| **Purpose**| 	Detect execution of suspicious scripts from unusual locations. |

---

## Related Queries:
```kql
// Find hidden folder creation events
DeviceFileEvents
| where FolderPath contains @"\Documents\secret_stuff"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ActionType

// Find execution of scripts from that folder
DeviceProcessEvents
| where ProcessCommandLine contains "secret_stuff"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, ActionType
```

---

## Created By:
- **Author Name**: Huy Tang
- **Author Contact**: https://www.linkedin.com/in/huy-t-892a51317/
- **Date**: May 19, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | May 19, 2025  | Huy Tang  
