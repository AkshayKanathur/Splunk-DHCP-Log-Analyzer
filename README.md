# 📡 Splunk DHCP Log Analyzer  

A cybersecurity project focused on **DHCP log analysis** using **Splunk SIEM**.  
This lab demonstrates how to monitor DHCP activity, extract fields, detect unauthorized clients, and analyze IP address assignments through Splunk searches and visualizations.  

---

## 🎯 Objective  
To build a **Splunk-based analysis workflow** that helps in understanding DHCP behavior, IP lease trends, and potential anomalies in network activity.  

---

## 🧩 Lab Setup  
- **Tool:** Splunk Enterprise  
- **Dataset:** `dhcp.log`  
- **Host:** `kali`  
- **Sourcetype:** `dhcp_log`  

---

## ⚙️ Task 1: Searching DHCP Events  

### 🕵️ Retrieve all DHCP logs  
```spl
source="dhcp.log" host="kali" sourcetype="dhcp_log"
```

---

## 🧩 Task 2: Field Extraction  

### 🔹 Extract important DHCP fields  
```spl
| rex field=_raw "^(?<timestamp>\d+\.\d+)\s+(?<transaction_id>[A-Za-z0-9]+)\s+(?<client_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<client_port>\d+)\s+(?<server_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<server_port>\d+)\s+(?<mac>[0-9a-fA-F:]+)\s+(?<leased_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<lease_time>[\d\.]+)\s+(?<xid>\d+)$"
```

---

## 📊 Task 3: DHCP Activity Analysis  

### 🔹 Analyze IP address distribution  
```spl
source="dhcp.log" host="kali" sourcetype="dhcp_log"
| stats count by leased_ip
```

### 🔹 Identify top leased IPs  
```spl
source="dhcp.log" host="kali" sourcetype="dhcp_log"
| top limit=10 leased_ip
```

### 🔹 Visualize DHCP activity over time  
```spl
source="dhcp.log" host="kali" sourcetype="dhcp_log"
| timechart span=1h count
```

---

## ⚠️ Task 4: Detect Unauthorized Clients  

### 🔹 Filter unknown or suspicious MAC addresses  
```spl
source="dhcp.log" host="kali" sourcetype="dhcp_log"
| search NOT mac="bc:ae:c5:9e:f3:b6"
```

---

## 🖼 Screenshots  

<img width="1920" height="1020" alt="Screenshot 2025-11-03 121507" src="https://github.com/user-attachments/assets/7a011970-f18d-4d4c-819c-0fa905889c5e" />
<img width="1920" height="1020" alt="Screenshot 2025-11-03 121535" src="https://github.com/user-attachments/assets/b00304e6-abc2-4c4b-a622-2259d0cb80e6" />
<img width="1920" height="1020" alt="Screenshot 2025-11-03 121609" src="https://github.com/user-attachments/assets/582d2964-2257-447d-a571-b3757d3e2b17" />
<img width="1920" height="1020" alt="Screenshot 2025-11-03 122205" src="https://github.com/user-attachments/assets/b92e1424-8ebf-4b90-bf25-b7343a971923" />
<img width="1920" height="1020" alt="Screenshot 2025-11-03 122621" src="https://github.com/user-attachments/assets/38c0ed56-6781-451b-a989-60712d1eb59c" />
<img width="1920" height="1020" alt="Screenshot 2025-11-03 122654" src="https://github.com/user-attachments/assets/c304c36d-3be3-4772-94a5-b25f56a0db4b" />
<img width="1920" height="1020" alt="Screenshot 2025-11-03 123023" src="https://github.com/user-attachments/assets/95724473-fde2-468e-ab73-6a78aac5fcc6" />

---

## 🙌 Acknowledgment  
Special thanks to [Rajneesh Gupta](https://github.com/0xrajneesh/) for sharing valuable insights and guidance during this project.  

---

## 🏁 Conclusion  
This project helped me:  
- Explore DHCP log analysis using Splunk  
- Extract meaningful fields with `rex`  
- Identify IP lease trends and detect unknown clients  
- Strengthen visibility into network-level activities  

---

## 🔖 Tags  
`#Splunk` `#CyberSecurity` `#SOC` `#SIEM` `#DHCPLogs` `#LogAnalysis` `#ThreatDetection` `#BlueTeam` `#HandsOnLearning`  
