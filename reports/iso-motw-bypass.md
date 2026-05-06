# ISO MOTW Bypass (Qakbot Tradecraft)

## Overview
Adversaries have leveraged ISO files delivered via compressed archives (e.g., ZIP) to bypass Mark-of-the-Web (MOTW) protections. This technique has been observed in campaigns associated with Qakbot and similar malware families.

By embedding malicious content within ISO files, attackers evade security controls that rely on MOTW tagging, increasing the likelihood of successful execution when a user interacts with the file.

---

## Threat Summary

- **Technique**: Mark-of-the-Web Bypass via ISO Delivery  
- **Primary Objective**: Execute malicious payloads without triggering MOTW-based protections  
- **Delivery Method**: Phishing emails with ZIP attachments containing ISO files  
- **User Interaction**: User mounts ISO and executes embedded file (e.g., `.lnk`, `.exe`)  

---

## MITRE ATT&CK Mapping

- **T1553.005** – Subvert Trust Controls: Mark-of-the-Web Bypass  
- **T1027** – Obfuscated/Compressed Files  
- **T1204.002** – User Execution: Malicious File  

---

## Attack Flow

1. User receives phishing email with a compressed attachment (ZIP)  
2. ZIP archive contains an ISO file  
3. ISO file is extracted and mounted by the user  
4. Mounted ISO contains a malicious executable or shortcut file  
5. User executes the file, initiating malware infection  

---

## Telemetry & Data Sources

To detect this activity, monitor the following:

- Windows Event Logs  
- File creation events  
- Process execution logs  
- Mounting activity (VHDMP Operational logs)  
- Endpoint Detection & Response (EDR) telemetry  

---

## Detection Opportunities

### Key Behaviors to Monitor

- ISO files written to user directories (e.g., Downloads, Temp)  
- Mounting of ISO files from non-standard locations  
- Execution of files from mounted virtual drives  
- Suspicious parent-child process relationships involving archive tools  

---

## Example Detection Logic (EQL)

```sql
any where 
  event.code == "1" and 
  winlog.channel == "Microsoft-Windows-VHDMP-Operational" and 
  winlog.event_data.VhdFileName like~ ("*Temp*", "*.zip*", "*.iso")

## Detection Content

Detection logic and implementation guidance can be found here:

- [ISO MOTW Bypass Detection (EQL)](../detections/iso-motw-eql-rule.md)



