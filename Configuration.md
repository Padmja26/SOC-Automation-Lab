
# Wazuh, TheHive, and Shuffle Configuration Guide

## Prerequisites
Before proceeding with the configuration, ensure you have:
- **VirtualBox** installed
- **Wazuh OVA** file
- **TheHive OVA** file
- **Windows 10 ISO/VM** for testing
- **Sysmon** downloaded for Windows 10

## 1. Configure Wazuh OVA in VirtualBox
1. Open **VirtualBox**.
2. Click on **File > Import Appliance**.
3. Select the **Wazuh OVA** file and proceed with the import.
4. Once imported, start the Wazuh VM.
5. Login using default credentials:
   ```
   Username: admin
   Password: admin
   ```
6. Check if the Wazuh manager is running:
   ```bash
   sudo systemctl status wazuh-manager
   ```
7. If not running, start it:
   ```bash
   sudo systemctl start wazuh-manager
   ```

## 2. Configure TheHive OVA in VirtualBox
1. Open **VirtualBox**.
2. Click on **File > Import Appliance**.
3. Select the **TheHive OVA** file and proceed with the import.
4. Start the TheHive VM.
5. Login to the VM and check if TheHive service is running:
   ```bash
   sudo systemctl status thehive
   ```
6. If TheHive is not running, start it:
   ```bash
   sudo systemctl start thehive
   ```

## 3. Setup Windows 10 VM as Test System for Wazuh
1. Create a **new VM** in VirtualBox and install Windows 10.
2. Configure network settings to allow communication with Wazuh.
3. Install necessary updates and drivers.

## 4. Download and Install Sysmon on Windows 10
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Extract the files and install it using:
   ```powershell
   sysmon -accepteula -i
   ```
3. Verify Sysmon is running:
   ```powershell
   Get-Service Sysmon
   ```

## 5. Add Windows 10 as an Agent in the Wazuh Manager
1. On the Wazuh Manager, add a new agent:
   ```bash
   sudo wazuh-agent-auth -a -m <Windows10-IP>
   ```
2. Install the Wazuh agent on Windows 10 from the [official site](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html).
3. Configure the **ossec.conf** file on Windows 10 to point to the Wazuh Manager.
4. Restart the Wazuh agent:
   ```powershell
   Restart-Service Wazuh
   ```

## 6. Add the Sysmon Path to the ossec.conf File in Windows 10
1. Open the **ossec.conf** file in Notepad with admin privileges.
2. Add the following entry:
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx</location>
   </localfile>
   ```
3. Save and restart the Wazuh agent.

## 7. Enable Logs and Archives in the Wazuh Manager ossec.conf File
1. Open the **ossec.conf** file on the Wazuh Manager.
2. Enable logs and archives by adding:
   ```xml
   <global>
     <logall>yes</logall>
     <log_format>json</log_format>
   </global>
   ```
3. Restart Wazuh Manager:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

## 8. Add Wazuh Alerts Index Pattern in Kibana
1. Access Kibana and go to **Stack Management** > **Index Patterns**.
2. Add **wazuh-alerts-*** with `@timestamp` as the primary field.
3. Save and verify alert logs are being received.

## 9. Create Custom Rule for Mimikatz Detection
1. On Wazuh Manager, navigate to:
   ```bash
   cd /var/ossec/etc/rules
   ```
2. Create a new custom rules file:
   ```bash
   sudo nano custom-rules.xml
   ```
3. Add the following rule for Mimikatz detection:
   ```xml
   <group name="mimikatz,attack,malware">
     <rule id="100001" level="15">
       <decoded_as>json</decoded_as>
       <field name="win.system">EventID: 1</field>
       <description>Potential Mimikatz execution detected</description>
     </rule>
   </group>
   ```
4. Save the file and restart Wazuh Manager.
   ```bash
   sudo systemctl restart wazuh-manager
   ```

## 10. Configure Shuffle for Wazuh Alerts
1. Open **Shuffle**.
2. Keep the **Changeme** icon as it is.
3. Add a **webhook** to receive alerts from Wazuh Manager.
4. Use this webhook to automate alerts forwarding and integrations with TheHive.

## Next Steps
- Further integrations with TheHive for SOC automation.
- Setting up incident response workflows.

---
This guide will be updated as new configuration steps are added.
