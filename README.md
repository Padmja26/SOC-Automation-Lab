# SOC-Automation-Lab
## **SOC Automation Home Lab Setup**
This repository documents the implementation of an automated SOC (Security Operations Center) workflow using **Wazuh**, **Shuffle**, and **TheHive**.

### **Project Overview**
This setup automates the detection, enrichment, and response to security incidents in a SOC environment. The workflow involves:
- **Wazuh Agent** monitoring Windows systems
- **Wazuh Manager** analyzing security events
- **Shuffle** automating threat intelligence enrichment and response actions
- **TheHive** handling incident management and escalation

---

## **Architecture Diagram**
![](https://github.com/user-attachments/assets/268f9667-0520-44b1-a785-f6731edbb750)

---

## **Stepwise Workflow**
### **1. Event Generation (Windows 10 Client with Wazuh Agent)**
- The **Wazuh Agent** is installed on a Windows 10 system.
- It collects logs and security events, forwarding them to the **Wazuh Manager**.
- **Example:** If an unauthorized login attempt occurs, the event is logged.

**Why Wazuh Agent?**
✔️ Real-time security event monitoring  
✔️ Open-source and highly scalable  
✔️ Detects file integrity changes, malware, and anomalies  

---

### **2. Event Reception (Wazuh Manager)**
- **Wazuh Manager** receives logs from the agent.
- It applies **rules and decoders** to detect threats and generate alerts.
- If a critical alert is detected, it is sent to **Shuffle**.

**Why Wazuh Manager?**
✔️ Centralized security event analysis  
✔️ Correlates logs from multiple endpoints  
✔️ Generates alerts based on predefined security rules  

---

### **3. Alert Forwarding (Wazuh to Shuffle)**
- Alerts are **sent to Shuffle** for automation and orchestration.

---

### **4. Enriching Threat Intelligence (Shuffle)**
- Shuffle fetches **Indicator of Compromise (IOC)** details using:
  - **Threat Intelligence APIs** (VirusTotal, AbuseIPDB, etc.)
  - **Custom enrichment scripts**

**Why Shuffle?**
✔️ Automates SOC workflows  
✔️ Connects various security tools without complex coding  
✔️ Saves analyst time by reducing manual effort  

---

### **5. Sending Alerts to TheHive**
- **Shuffle forwards enriched alerts to TheHive** for case creation.
- TheHive assigns incidents based on severity.

**Why TheHive?**
✔️ Open-source SOC case management  
✔️ Efficiently tracks security incidents  
✔️ Enables collaboration among SOC analysts  

---

### **6. Email Notification to SOC Analysts**
- Shuffle **triggers email notifications** to the SOC team.
- TheHive sends case details via **email for quick response**.

---

### **7. SOC Analyst Receives and Acts on Incident**
- Analysts **review cases** in TheHive.
- If action is required, they trigger response actions.

---

### **8. Automated Response Execution**
- **Shuffle automates responses** (e.g., blocking an IP, isolating a system).
- The SOC analyst can manually approve or modify actions.

---

## **Advantages of This SOC Workflow**
✔️ **Automation:** Reduces manual effort in handling security incidents  
✔️ **Faster Response:** Real-time detection and automated mitigation  
✔️ **Centralized Visibility:** Integrated with TheHive for better case management  
✔️ **Threat Intelligence Enrichment:** Provides context for better decision-making  

---

## **Installation Guide**
### **Prerequisites**
- Linux server or VMs for **Wazuh Manager, Shuffle, and TheHive**
- Windows machine for **Wazuh Agent**
- Internet access for threat intelligence lookups

### **1. Install Wazuh**
Follow the official [Wazuh Installation Guide](https://documentation.wazuh.com/current/installation-guide/index.html).

### **2. Install Shuffle**
Refer to [Shuffle's Setup Documentation](https://shuffler.io/docs).

### **3. Install TheHive**
Check the [official installation guide](https://thehive-project.org/).

---

This **README.md** provides a clear stepwise breakdown of the SOC automation project but for deatiled stepwise configuration refer to [Configuration.md](https://github.com/Padmja26/SOC-Automation-Lab/blob/main/Configuration.md). 🚀
