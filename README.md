<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/zainabissa29/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "zeemakay" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at `2025-09-16T14:52:56.5772084Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "zee"
| where InitiatingProcessAccountName == "zeemakay"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-09-16T14:52:56.5772084Z)
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1466" height="442" alt="image" src="https://github.com/user-attachments/assets/658b04ea-5524-4860-924b-5b9f81773346" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.7.exe". Based on the logs returned, at `2025-09-16T14:56:24.978953Z`, User zeemakay on the "zee" device ran the file `tor-browser-windows-x86_64-portable-14.5.7.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "zee"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.7.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Checked for any indication that firefox.exe, tor.exe, or tor-browser.exe was run by "zeemakay" on device "zee". Found that firefox.exe was launched at 2025-09-16T17:20:55.9374501Z from within the Tor Browser folder.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "zee"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-09-16T15:21:34.1188002Z`, an employee on the "zee" device successfully established a connection to the remote IP address `127.0.0.1` on port `9150`. The connection was initiated by the process `firefox.exe`, located in the folder `c:\users\zee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "zee"  
| where InitiatingProcessAccountName == "zeemakay"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-09-16T14:56:24.978953Z`
- **Event:** The user "zeemakay" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\zeemakay\Downloads\tor-browser-windows-x86_64-portable-14.5.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-09-16T14:56:24.978953Z`
- **Event:** The user "zeemakay" executed the file `tor-browser-windows-x86_64-portable-14.5.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.7.exe /S`
- **File Path:** `C:\Users\zeemakay\Downloads\tor-browser-windows-x86_64-portable-14.5.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-09-16T17:20:55.9374501Z`
- **Event:** User "zeemakay" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\zeemakay\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-09-16T15:21:34.1188002Z`
- **Event:** A network connection to IP `127.0.0.1` on port `9150` by user "zeemakay" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `firefox.exe`
- **File Path:** `c:\users\zeemakay\desktop\tor browser\browser\torbrowser\tor\firefox.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**  `2025-09-16T17:21:34.1188002Z`
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "zeemakay" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-09-16T18:36:30.4086437Z`
- **Event:** The user "zeemakay" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\zeemakay\Desktop\tor-shopping-list.txt`

---

## Summary

The user "zeemakay" on the "zee" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `zeemakay`. The device was isolated, and the user's direct manager was notified.

---# threat-hunting-scenario-tor-
