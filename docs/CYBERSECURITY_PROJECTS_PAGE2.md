# Cybersecurity Projects — Page 2

> **Canva Layout Guide**
>
> Top Left (title + summary) | Top Right (terminal-output.png screenshot)
> Middle (detection rule cards)
> Bottom (what I learned + GitHub link)

---

# LogShield — Brute Force Detection & Log Analysis Tool

## Defensive Cybersecurity | Log Monitoring | Incident-Style Reporting

---

### Project Summary

LogShield is a Python-based defensive cybersecurity project that analyzes
authentication logs and detects suspicious login behavior.

The tool reads fake sample login logs, identifies possible brute-force patterns,
assigns severity levels, and generates both text and JSON incident-style reports.

This project helped me understand cybersecurity from a defender's perspective:
not only finding vulnerabilities, but also monitoring activity, detecting risk,
and preparing clear reports for response.

---

### What the Tool Detects

- Multiple failed login attempts from the same IP
- One IP trying multiple usernames
- Successful login after repeated failures
- Suspicious IP frequency
- Basic risk severity: Low, Medium, High

---

### Detection Logic

**Failed Login Threshold**
If one IP has repeated failed login attempts, it is marked as suspicious.

**Multiple Username Attempts**
If one IP tries several usernames, it may indicate account guessing.

**Success After Failures**
If a login succeeds after multiple failures, it becomes a high-risk pattern.

**Severity Scoring**
The tool assigns Low, Medium, or High severity based on behavior.

---

### Screenshots

| ![Terminal Output](../screenshots/terminal-output.png) | ![Text Report](../screenshots/generated-report.png) | ![JSON Report](../screenshots/json-report.png) |
|---|---|---|
| Terminal Security Report | incident_report.txt | incident_report.json |

---

### Cybersecurity Concepts Learned

- Log analysis
- Brute-force detection
- Authentication monitoring
- Suspicious IP identification
- Incident response basics
- SOC / SIEM-style thinking
- Severity scoring
- Defensive reporting

### What I Learned

LogShield helped me understand that cybersecurity is not only about preventing
attacks before they happen. It is also about observing system behavior,
detecting suspicious activity early, and creating reports that help people
respond.

This project connected my learning with real defensive security workflows used
in monitoring, alerting, and incident response.

---

**GitHub:** `github.com/guchchi/LogShield-Brute-Force-Log-Analyzer`

**Type:** Defensive Cybersecurity Project

**Status:** Local educational project using fake sample logs
