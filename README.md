# windows-security-lab
Windows endpoint investigation lab using Sysmon, Event Viewer, Process Explorer, Autoruns, and Wireshark.

Objective:
The purpose of this lab was to practice basic Windows endpoint investigation using Sysmon, Event Viewer, Process Explorer, Autoruns, and Wireshark/Npcap. The lab focused on tracking process execution, DNS activity, network connections, and persistence locations.

Tools Used:
- Sysmon
- Windows Event Viewer
- Process Explorer
- Autoruns
- Wireshark / Npcap
- PowerShell 

Lab Activity:
I began test activity by running commands from PowerShell, including curl.exe, nslookup, ping, and notepad.exe. This created process, DNS, and network artifacts that could be reviewed using Sysmon and Windows analysis tools.

Findings:

1. Process Creation:
Sysmon Event ID 1 showed curl.exe being launched from PowerShell. The command line showed curl.exe connecting to https://www.google.com. The parent process was powershell.exe, which confirmed that the activity was manually generated during the lab.

<img width="752" height="674" alt="Event1_CyberLab" src="https://github.com/user-attachments/assets/937af8b4-a85e-4cca-9b0e-001806d95fd3" />

2. Network Connection:
Sysmon Event ID 3 showed outbound network connection activity. One observed event showed chrome.exe using UDP traffic to destination port 53, which is commonly associated with DNS traffic. The hostname console.gl-inet.com appeared related to the router/repeater environment.

<img width="751" height="593" alt="Event3_CyberLab" src="https://github.com/user-attachments/assets/164ee8f6-8a57-4b55-bd0f-dbc4ff5be08a" />

3. DNS Query:
Sysmon Event ID 22 showed svchost.exe performing a DNS query for v10.events.data.microsoft.com. The query succeeded and returned Microsoft traffic management results. This appeared consistent with normal Windows background telemetry activity.

<img width="758" height="598" alt="Event22_CyberLab" src="https://github.com/user-attachments/assets/1a956aee-b42d-43c5-ba8d-f79736d27b01" />

4. Live Process Review:
Process Explorer was used to inspect notepad.exe after launching it from PowerShell. The process ran from the expected Windows System32 directory and showed a normal parent-child relationship between powershell.exe and notepad.exe.

5. Persistence Review:
Autoruns was used to review Logon entries, Scheduled Tasks, and Services. These areas were reviewed because attackers may use them to maintain persistence after reboot or user login. No suspicious persistence was identified. NpcapWatchdog was observed, but it appeared consistent with the Wireshark/Npcap lab setup.

<img width="1166" height="539" alt="autoruns-logon-tab" src="https://github.com/user-attachments/assets/17d7ad35-7307-47d5-9845-13639ff9b44f" />

<img width="362" height="506" alt="autoruns-scheduled-tasks" src="https://github.com/user-attachments/assets/bcf4ae2e-99aa-4574-8048-a8fb9dde5af0" />

<img width="806" height="543" alt="autoruns-services-tab" src="https://github.com/user-attachments/assets/55870b32-0ee6-4464-8202-333266d73a81" />

Assessment:
The process execution, DNS lookups, and network connections were either manually generated during the lab or related to known Windows/router activity. No suspicious executable path, unknown command line, abnormal persistence mechanism, or clearly malicious external destination was identified.

Conclusion:
This lab demonstrated how Sysmon, Event Viewer, Process Explorer, Autoruns, and Wireshark can be used together to investigate endpoint activity. The skills used included reviewing process creation events, identifying parent-child process relationships, checking DNS and network activity, reviewing startup persistence, and writing an analyst-style incident summary.
