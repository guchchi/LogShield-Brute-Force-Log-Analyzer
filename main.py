"""LogShield — Brute Force Detection & Log Analysis Tool

Reads authentication logs, detects suspicious login behavior,
and generates an incident-style report.
"""

import os
from typing import List

from detector import parse_log_line, analyze_logs, LogEntry
from report import (
    generate_report,
    print_terminal_report,
    save_text_report,
    save_json_report,
)

LOG_FILE = "sample_logs.txt"
REPORTS_DIR = "reports"
TEXT_REPORT = os.path.join(REPORTS_DIR, "incident_report.txt")
JSON_REPORT = os.path.join(REPORTS_DIR, "incident_report.json")


def main() -> None:
    print("LogShield — initializing log analysis...")
    print()

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] {LOG_FILE} not found. Make sure it exists in the project directory.")
        return

    print(f"  Read {len(raw_lines)} log entries from {LOG_FILE}")

    parsed_logs: List[LogEntry] = []
    for line in raw_lines:
        entry = parse_log_line(line)
        if entry:
            parsed_logs.append(entry)

    print(f"  Parsed {len(parsed_logs)} valid log entries")
    print()

    findings, severity_map = analyze_logs(parsed_logs)
    report_data = generate_report(parsed_logs, findings, severity_map)
    print_terminal_report(report_data)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    save_text_report(report_data, TEXT_REPORT)
    save_json_report(report_data, JSON_REPORT)

    print()
    print("LogShield — analysis complete.")


if __name__ == "__main__":
    main()
