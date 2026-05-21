Threat Intelligence Reports
> Analyzing adversary behavior and translating intelligence into actionable detections for SOC environments.
---
📌 About This Repository
This repository documents my hands-on work in Cyber Threat Intelligence (CTI) and Detection Engineering — covering the full workflow from researching adversary tradecraft, mapping techniques to MITRE ATT&CK, and writing detection logic deployable in SIEM environments.
All analysis and detection content is original work.
---
🗂️ Repository Structure
```
threat-intelligence-reports/
├── /reports/       # CTI reports on threat actors & malware families
└── /detections/    # Detection rules (EQL, Sigma, KQL)
```
---
📄 CTI Reports
Report	Technique	MITRE ATT&CK
ISO/MOTW Bypass — Qakbot Tradecraft	Mark-of-the-Web Bypass via ISO delivery	T1553.005, T1027, T1204.002
Each report includes:
Adversary TTP breakdown
MITRE ATT&CK mapping
Detection logic
SOC analyst guidance
---
🛡️ Detection Content
Detection rules derived from intelligence analysis are in the `/detections` folder.
Rule	Language	Technique Covered
ISO/MOTW Bypass Detection	EQL	T1553.005
---
🧠 Skills Demonstrated
`MITRE ATT&CK` `EQL` `Threat Intelligence Analysis` `Detection Engineering`
`Log Analysis` `SIEM` `SOC Operations`
---
🔗 Related Projects
SIEMLab — Microsoft Sentinel deployment and detection in Azure
detection-rules — Extended Elastic detection rules
---
👤 About Me
Geoffrey Awinyo — Cybersecurity Analyst | New York, NY
CompTIA A+ | CompTIA Network+ | CompTIA Security+ | HTB CDSA (in progress)
![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)
![YouTube](https://img.shields.io/badge/YouTube-PeepSecOps-red?logo=youtube)
