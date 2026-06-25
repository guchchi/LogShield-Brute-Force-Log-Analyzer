# Evidence

## Screenshots

The `screenshots/` directory contains images captured during local testing of LogShield. Below is the current inventory and what each screenshot documents.

### Inventory

| File | What It Proves |
|---|---|
| `terminal-output.png` | Full terminal output showing LogShield's security report with suspicious IPs, detection reasons, and recommended actions |
| `generated-report.png` | The generated `incident_report.txt` file showing the structured text report |
| `json-report.png` | The generated `incident_report.json` file showing the structured JSON report |
| `Screenshot 2026-06-18 190518.png` | Sample log data or intermediate analysis step during local testing |
| `Screenshot 2026-06-18 190540.png` | Additional detection output or report view during local testing |

### What the Screenshots Prove

- LogShield successfully reads and parses sample log files
- The detection engine identifies suspicious IPs based on failed attempt counts
- Multiple detection rules fire simultaneously (failed attempts + multiple usernames)
- Severity scoring correctly assigns High/Medium/Low based on observed patterns
- Reports are generated in both human-readable text and structured JSON formats
- Recommended defensive actions are included based on severity levels found

## Sample Log Data

The included `sample_logs.txt` contains 27 fake authentication log entries. All IPs are in private ranges:
- `10.0.0.x` — private class A
- `172.16.0.x` — private class B
- `192.168.1.x` — private class C

All usernames are fictitious (admin, guest, root, test, svc_account, etc.).

## Demo Output

When run with the included sample logs, LogShield detects:
- 5 suspicious IPs
- 3 high-severity findings
- Multiple detection triggers per IP

See the terminal output screenshot for the complete run output.

## Notes

- All testing is performed locally using only fake sample data
- No real authentication logs, real IPs, or real user data are used
- Screenshots are stored in the `screenshots/` directory at the repository root
