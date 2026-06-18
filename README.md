# LogShield — Brute Force Detection & Log Analysis Tool

LogShield is a beginner-friendly **defensive cybersecurity project** that
analyzes authentication logs, detects suspicious login behavior, and
generates a simple incident-style report.

> ⚠️ **Safety Note:** This project is **defensive and educational**. It uses
> fake sample logs only. It does not attack, scan, or interact with real
> systems.

---

## What This Project Demonstrates

| Skill Area | What You Learn |
|---|---|
| Log Analysis | Parsing and interpreting authentication logs |
| Brute-force Detection | Identifying rapid failed login attempts |
| Threat Detection Logic | Rule-based detection of suspicious patterns |
| Incident Response | Generating structured security reports |
| Defensive Cybersecurity | Monitoring, detecting, and recommending actions |
| SIEM/SOC Basics | Event correlation and severity scoring |
| Python Scripting | File I/O, regex, data structures, report generation |

---

## How It Works

```
sample_logs.txt → Parsing → Detection Rules → Severity Scoring → Incident Report
```

1. **Read** — Load sample authentication logs from a text file
2. **Parse** — Extract timestamp, status, username, and IP from each line
3. **Detect** — Run four detection rules to find suspicious activity
4. **Score** — Assign severity (Low / Medium / High) to each suspicious IP
5. **Report** — Print terminal summary and save reports to `reports/`

---

## Detection Rules

| Rule | What It Detects | Why It Matters |
|---|---|---|
| Failed Login Threshold | 5+ failed attempts from one IP | Indicates automated brute-force attack |
| Multiple Username Attempts | 3+ different usernames from one IP | Password spraying or user enumeration |
| Success After Failures | Successful login after repeated fails | Brute-force attack succeeded |
| Severity Scoring | Combined risk level per IP | Prioritizes incident response |

---

## Sample Log Format

```
2026-06-18 10:01:11 FAILED username=admin ip=192.168.1.45
2026-06-18 10:02:10 SUCCESS username=admin ip=192.168.1.45
```

Only fake/local IPs and fake usernames are used.

---

## Screenshots

| Screenshot | Description |
|---|---|
| ![Terminal Output](screenshots/terminal-output.png) | Clean terminal output showing the security report |
| ![Generated Report](screenshots/generated-report.png) | Text report saved to `reports/incident_report.txt` |
| ![JSON Report](screenshots/json-report.png) | JSON report saved to `reports/incident_report.json` |

---

## Setup

### Prerequisites

- Python 3.6+
- No external dependencies (uses only standard library)

### Run

```bash
git clone <https://github.com/guchchi/LogShield-Brute-Force-Log-Analyzer.git>
cd LogShield
python main.py
```

Expected output:

```
==============================
LogShield Security Report
==============================

  Total Events:    28
  Failed Logins:   22
  Successful Logins: 6
  Suspicious IPs:  3
```

---

## Project Structure

```
LogShield/
├── main.py              # Entry point
├── detector.py          # Detection engine
├── report.py            # Report generator
├── sample_logs.txt      # Sample authentication logs
├── requirements.txt     # Dependencies (standard library only)
├── README.md            # This file
├── SECURITY.md          # Security policy
├── .gitignore
├── reports/             # Generated incident reports
│   ├── incident_report.txt
│   └── incident_report.json
├── screenshots/         # Screenshots for README
└── docs/
    └── PORTFOLIO_SUMMARY.md
```

---

## What I Learned

- How login logs can reveal attack patterns
- How brute-force attacks appear in authentication data
- Why continuous monitoring matters in cybersecurity
- Why logs are a critical source of security intelligence
- How defensive tools detect and flag suspicious activity
- Basics of SOC/SIEM thinking — event correlation, severity,
  and incident response

---

## Portfolio Relevance

This project supports my cybersecurity portfolio by demonstrating:

- Defensive security thinking
- Log analysis and detection logic
- Incident-style reporting
- Python scripting for security tools

It was built as part of my application to the **IIT Kanpur B.Cyber program**
and reflects my commitment to learning defensive cybersecurity fundamentals.

---

## License

This project is for educational and portfolio use only.
