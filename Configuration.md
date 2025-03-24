
# Wazuh, TheHive, and Shuffle Configuration Guide

## Prerequisites
Before proceeding with the configuration, ensure you have:
- **VirtualBox** installed
- **Wazuh OVA** file
- **TheHive OVA** file
- **Windows 10 VM** for testing
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
   sudo systemctl restart Wazuh-manager
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

## 11. Prerequisites

Ensure you have the following components installed and configured:

- **Wazuh Manager** (For collecting and analyzing security events)
- **Shuffle** (For SOAR automation)
- **TheHive** (For case management and threat intelligence)
- **VirusTotal API Key** (For automated threat intelligence lookups)
- **Email Server Details** (For sending notifications)

## 12. Setting Up Webhooks in Wazuh

1. Log in to the Wazuh Manager.
2. Edit the `/var/ossec/etc/ossec.conf` file and add the following webhook configuration under the `<global>` section:

   ```xml
   <integration>
       <name>webhook</name>
       <hook_url>http://shuffle-instance:8000/hooks/wazuh_alerts</hook_url>
       <level>10</level>
   </integration>
   ```

3. Restart Wazuh for the changes to take effect:
   ```sh
   systemctl restart wazuh-manager
   ```

## 13. Creating a Workflow in Shuffle

1. Log in to Shuffle.
2. Navigate to **Workflows** and create a new workflow.
3. Add a **Webhook Trigger**:
   - Set the trigger URL (e.g., `http://shuffle-instance:8000/hooks/wazuh_alerts`).
   - Configure it to listen for incoming Wazuh alerts.
   - Parse the alert JSON to extract relevant information.

## 14. Automating Threat Intelligence with VirusTotal

1. Add the **VirusTotal app** in Shuffle.
2. Configure it to extract file hashes, IPs, or URLs from Wazuh alerts.
3. Use the VirusTotal API to check if the entity is malicious.
4. Store the response in Shuffle for further processing.

## 15. Creating an Incident in TheHive

1. Add **TheHive app** in Shuffle.
2. Create an action to automatically generate a case in TheHive if an alert meets specific criteria (e.g., high severity, multiple detections).
3. Map Wazuh alert fields to TheHive case attributes.

## 16. Sending Email Notifications

1. Add the **Email App** in Shuffle.
2. Configure SMTP settings for outgoing alerts.
3. Automate email notifications for critical alerts, including threat intelligence results and incident details.

## 17. Testing the Workflow

1. Trigger a test alert in Wazuh (e.g., run `logger "Test Wazuh Alert"`).
2. Verify that Shuffle receives the webhook.
3. Check if VirusTotal enriches the data.
4. Ensure TheHive logs the case correctly.
5. Confirm that email notifications are sent.

## 18. Configure TheHive for Alert Management

- **Define the Alert Fields:**
  - PAP (Permissible Actions Protocol): Set exposure level.
  - Severity: Set as `2` for moderate severity.
  - Source: Define as Wazuh.
  - Source Reference: Use Rule ID (e.g., `1002`).
  - Status: Set as `New`.
  - Summary: Provide context, e.g., "Mimikatz activity detected on host."
  - Host Information: Retrieve host details from the alert.
  - Process ID & Command Line: Extract relevant details.
  - Tags: Add MITRE ATT&CK mapping (e.g., `T1003 - Credential Dumping`).
  - Title: Set dynamically, e.g., "Mimikatz Detected".
  - Traffic Light Protocol (TLP): Set as `2` (Green/Restricted Sharing).
  - Alert Type: Mark as **Internal**.

- **Save & Deploy Workflow:**
  - Store the alert configuration in Shuffle.

## 19. Modify Cloud Firewall for TheHive Connectivity

1. Navigate to **DigitalOcean** (or your cloud provider).
2. Go to **Networking > Firewalls**.
3. Select your firewall instance.
4. Create a new rule:
   - **Port:** `9000`
   - **Allow IPv4 traffic** from any source (for temporary testing).
   - **Disable IPv6**.
   - **Save and apply** the rule.

## 20. Run & Validate TheHive Alert Automation

1. In Shuffle, navigate to the workflow.
2. Click on **Run Workflow** to execute the alert pipeline.
3. Open **TheHive** and check if the alert is created with:
   - **Title:** "Mimikatz Usage Detected"
   - **Host Information**
   - **User Information**
   - **Process ID & Command Line**

## 21. Configure Email Alerting

1. In Shuffle, add the **Email Application** to the workflow.
2. Connect the **VirusTotal module** (if integrated).
3. Set recipient email (can be a disposable email from SquareX).
4. Define email fields:
   - **Subject:** "Mimikatz Detected - Immediate Attention Required"
   - **Timestamp (UTC)**
   - **Affected Host Name**
   - **Process ID & Command Line**
5. **Run the Workflow:**
   - Confirm email receipt with the necessary details.

## 22. Set Up a Virtual Machine for Testing (Ubuntu)

1. Deploy an **Ubuntu VM** (Cloud or On-Prem).
2. Allow all **TCP connections** to simulate an attack scenario.
3. Create a firewall rule to allow inbound **SSH connections** for testing.

## 23. Detect SSH Brute Force Attacks & Automate Blocking

1. Add **HTTP Application** in Shuffle.
2. Define a **GET API Action** with a `curl` request to fetch logs from Wazuh.
3. Extract **Source IP Addresses** from unauthorized SSH attempts.
4. Implement **User Input Decision**:
   - Prompt user: "Do you want to block this IP?"
   - If "Yes" → Execute block command via **Wazuh API**.
5. Set up **Wazuh Firewall Rule** to block malicious IPs.

## 24. Validate Incident Response

1. Run a simulated **brute-force attack** on the Ubuntu VM.
2. Observe if the **automated blocking rule** is applied successfully.
3. Check logs to verify if **Wazuh blocked the attacking IP**.

---
Keep checking this repo for more updates and screenshots on this project !!🚀

