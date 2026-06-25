<div align="center">

# LogShield — Brute Force Detection & Log Analysis Tool

**Log Analysis · Suspicious Login Detection · Incident-Style Reporting · Defensive Security**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Defensive Security](https://img.shields.io/badge/focus-defensive-green)](#)
[![Log Analysis](https://img.shields.io/badge/purpose-log--analysis-orange)](#)
[![Educational Project](https://img.shields.io/badge/project-educational-yellow)](#)

</div>

LogShield is a defensive log-analysis project built to understand how suspicious authentication activity can be detected using simple rule-based analysis. It reads sample authentication logs, identifies possible brute-force login patterns, assigns severity levels, and generates incident-style reports.

---

## Project Status

Active — local educational lab. Currently supports parsing fake authentication logs, running three detection rules, and generating text and JSON incident reports.

---

## Why I Built This

I built this project to understand how authentication logs can reveal suspicious behavior. Log analysis is a fundamental skill in security operations, and this project helped me learn how repeated failed login patterns look in log data and how simple threshold-based rules can flag them.

---

## Cybersecurity Problem Statement

Brute-force attacks occur when an attacker repeatedly tries different passwords or usernames until access is gained. In real systems, each failed attempt is typically recorded in authentication logs. A single failed login may be a mistake, but many failed attempts from the same IP address or targeting the same account is a pattern worth investigating.

LogShield studies this problem by analyzing sample authentication logs and identifying:

- Multiple failed login attempts from the same IP address
- One IP address targeting multiple usernames
- Successful logins that occur after repeated failures
- The overall severity of suspicious activity

---

## What LogShield Does

- Reads authentication logs from a text file
- Parses each line into structured fields (timestamp, status, username, IP)
- Groups events by IP address and username
- Applies detection rules to identify suspicious patterns
- Assigns a severity level to each flagged IP address
- Prints a terminal summary with findings and recommendations
- Saves a human-readable text report
- Saves a structured JSON report

---

## Key Features

| Feature | Status |
|---|---|
| Parse authentication log entries | Implemented |
| Count failed login attempts per IP | Implemented |
| Detect repeated failures from same IP | Implemented |
| Detect multiple usernames from same IP | Implemented |
| Detect success after repeated failures | Implemented |
| Severity scoring (Low, Medium, High) | Implemented |
| Terminal summary output | Implemented |
| Text report export | Implemented |
| JSON report export | Implemented |
| Sample log file included | Implemented |
| Time-window based detection | Future |
| CSV/JSON log format support | Future |

---

## Detection Logic

1. Read each line from the sample log file
2. Extract timestamp, event status, username, and IP address using regular expressions
3. Group events by IP address
4. For each IP, count:
   - Total failed login attempts
   - Unique usernames targeted
   - Whether any successful login occurred after failures
5. Compare counts against defined thresholds:
   - **Failed Login Threshold:** 5 or more failed attempts from one IP
   - **Multiple Username Threshold:** 3 or more different usernames from one IP
6. Any success following failures is flagged regardless of count
7. Severity is calculated based on the combination of signals detected

### Threshold Configuration

Thresholds are defined as constants in `detector.py`:

```python
FAILED_ATTEMPT_THRESHOLD = 5
MULTIPLE_USERNAME_THRESHOLD = 3
```

---

## Security Concepts Demonstrated

- **Log analysis** — parsing and interpreting authentication event data
- **Brute-force detection** — identifying rapid failed login patterns
- **Authentication monitoring** — tracking success and failure rates
- **Suspicious IP identification** — flagging IPs with anomalous behavior
- **Severity scoring** — classifying risk based on observed patterns
- **Incident-style reporting** — documenting findings for review
- **Defensive monitoring** — applying rule-based detection to log data

---

## Architecture

```
sample_logs.txt → Parser → Detection Engine → Severity Scoring → Reports
                                                                ├── Terminal Output
                                                                ├── incident_report.txt
                                                                └── incident_report.json
```

### Folder Structure

```
LogShield/
├── main.py                # Entry point — reads logs, runs detection, saves reports
├── detector.py            # Detection engine — parsing, rules, severity
├── report.py              # Report generation — terminal, text, JSON
├── sample_logs.txt        # Fake authentication logs for testing
├── pyproject.toml         # Package metadata
├── CHANGELOG.md           # Version history
├── LICENSE                # MIT license
├── SECURITY.md            # Security policy
├── requirements.txt       # Dependencies (standard library only)
├── docs/                  # Documentation
│   ├── DETECTION_LOGIC.md
│   ├── SECURITY_REVIEW.md
│   ├── THREAT_MODEL.md
│   ├── EVIDENCE.md
│   └── FUTURE_IMPROVEMENTS.md
├── reports/               # Generated incident reports
├── screenshots/           # Screenshots and demo output
└── sample_logs.txt        # Sample authentication log data
```

---

## Example Input and Output

### Input (sample_logs.txt)

```
2026-06-18 10:01:11 FAILED username=admin ip=192.168.1.45
2026-06-18 10:01:17 FAILED username=admin ip=192.168.1.45
2026-06-18 10:01:25 FAILED username=root ip=192.168.1.45
2026-06-18 10:02:10 SUCCESS username=admin ip=192.168.1.45
```

### Terminal Output

```
==================================================
            LogShield Security Report
==================================================
  Generated:       2026-06-18 18:55:50
  Total Events:    27
  Failed Logins:   21
  Successful Logins: 6
  Suspicious IPs:  5

  [High] Suspicious IP: 192.168.1.45
  Reason:
    * 6 failed login attempts
    * 3 different usernames targeted: admin, root, test
    * Successful login after multiple failed attempts

  [High] Suspicious IP: 192.168.1.100
  Reason:
    * 7 failed login attempts
    * 6 different usernames targeted

--------------------------------------------------
               Recommended Actions
--------------------------------------------------
  * Enable account lockout policy after 5 failed attempts
  * Require multi-factor authentication (MFA) for all accounts
  * Rate-limit login attempts per IP address
  * Review authentication logs for unusual patterns
```

---

## Screenshots & Evidence

| Terminal Output | Text Report | JSON Report |
|---|---|---|
| ![Terminal](screenshots/terminal-output.png) | ![Text](screenshots/generated-report.png) | ![JSON](screenshots/json-report.png) |

| Sample Log View | Detection Rules |
|---|---|
| ![Sample Logs](screenshots/Screenshot%202026-06-18%20190518.png) | ![Detection](screenshots/Screenshot%202026-06-18%20190540.png) |

All screenshots are captured from local lab runs using only fake sample data. See [docs/EVIDENCE.md](docs/EVIDENCE.md) for detailed captions.

---

## How to Run Locally

### Prerequisites

- Python 3.8+
- No external dependencies

### Setup

```bash
git clone https://github.com/guchchi/LogShield-Brute-Force-Log-Analyzer.git
cd LogShield-Brute-Force-Log-Analyzer
python main.py
```

### Output

The tool generates:

- A terminal summary of suspicious IPs and severity
- `reports/incident_report.txt` — human-readable incident report
- `reports/incident_report.json` — structured JSON report

---

## Sample Logs

The included `sample_logs.txt` contains 27 fake authentication log entries using only private-range IP addresses (`10.0.0.x`, `172.16.0.x`, `192.168.1.x`) and fake usernames. These logs are safe to use for testing and are not real system logs.

---

## Limitations

- This is a student-built defensive learning project
- It uses sample logs, not real production logs
- Rule-based detection may produce false positives
- It does not block attackers or interact with real systems
- It does not replace a real SIEM or enterprise monitoring system
- It currently focuses on basic brute-force pattern detection
- More advanced correlation, time-window analysis, and log format support can be added later

---

## Future Improvements

See [docs/FUTURE_IMPROVEMENTS.md](docs/FUTURE_IMPROVEMENTS.md) for the full list.

Planned additions include:

- Time-window based detection (e.g., X failures in Y seconds)
- CSV and JSON log format support
- Configurable thresholds via command-line arguments
- Whitelist/allowlist support for trusted IPs
- Dashboard visualization of detected patterns
- Correlation between failed and successful logins
- Additional sample log datasets
- Unit tests for detection rules

---

## Portfolio Evidence Note

This project demonstrates my practical interest in defensive cybersecurity through log analysis, suspicious activity detection, and technical documentation. It is part of my cybersecurity learning portfolio and is also included as supporting background evidence for academic cybersecurity applications.

---

## Ethical Use Disclaimer

This project is created only for defensive cybersecurity learning, log-analysis practice, and safe lab-based experimentation. Do not use this project to analyze, collect, or expose logs from systems you do not own or do not have permission to review. Use only safe sample logs or authorized data.

---

## License

MIT — see [LICENSE](LICENSE).
