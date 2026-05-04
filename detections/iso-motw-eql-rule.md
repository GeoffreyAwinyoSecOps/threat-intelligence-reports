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


# ISO MOTW Bypass Detection

## Overview
This detection identifies potential Mark-of-the-Web (MOTW) bypass activity involving ISO files delivered via compressed archives and mounted from user-controlled directories.

Adversaries use this technique to evade security controls that rely on MOTW tagging, increasing the likelihood of successful execution when a user interacts with the file.

---

## Data Sources

- Windows Event Logs  
- Microsoft-Windows-VHDMP-Operational channel  
- Endpoint telemetry (file paths, mounting activity)  

---

## Detection Strategy

This detection focuses on identifying suspicious ISO mounting activity originating from non-standard locations.

### Key Indicators:
- ISO files mounted from `Temp` or `Downloads` directories  
- File paths referencing `.zip` or `.iso`  
- Mount activity initiated by user processes  

---

## Detection Logic (EQL)

```sql
any where 
  event.code == "1" and 
  winlog.channel == "Microsoft-Windows-VHDMP-Operational" and 
  winlog.event_data.VhdFileName like~ ("*Temp*", "*.zip*", "*.iso")
```

---

## Tuning Guidance

- Exclude known legitimate ISO usage (e.g., IT deployments, developer tools)  
- Baseline normal ISO mounting behavior in your environment  
- Correlate with:
  - Process execution events  
  - Email or browser download activity  
  - Parent-child process relationships  

---

## False Positives

- Legitimate software installations using ISO files  
- Administrative or developer activity involving disk images  
- Internal tooling that mounts virtual drives  

---

## Response Guidance

If this detection triggers:

1. Identify the user and origin of the ISO file  
2. Inspect mounted contents for executables or scripts  
3. Review process execution following mount activity  
4. Check for suspicious outbound network connections  
5. Isolate the host if malicious behavior is confirmed  

---

## MITRE ATT&CK Mapping

- T1553.005 – Mark-of-the-Web Bypass  
- T1027 – Obfuscated/Compressed Files  
- T1204.002 – User Execution: Malicious File  

---

## Notes

- Detection fidelity improves when correlated with process execution telemetry  
- Consider pairing with detections for `.lnk` or `.exe` execution from mounted drives  

---

## Disclaimer

This detection logic is based on lab validation and publicly observed adversary behavior. It should be tuned to align with the specific environment.

