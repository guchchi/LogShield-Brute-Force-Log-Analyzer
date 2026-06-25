import json
from datetime import datetime
from typing import Any, Dict, List, Set

ReportData = Dict[str, Any]


def generate_report(
    parsed_logs: List[Dict[str, str]],
    findings: List[Dict[str, Any]],
    severity_map: Dict[str, str],
) -> ReportData:
    total_events = len(parsed_logs)
    failed_events = [e for e in parsed_logs if e["status"] == "FAILED"]
    success_events = [e for e in parsed_logs if e["status"] == "SUCCESS"]

    suspicious_ips = sorted(set(f["ip"] for f in findings))
    targeted_usernames = sorted(
        set(e["username"] for e in failed_events)
    )

    report_data: ReportData = {
        "report_title": "LogShield Security Incident Report",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_events": total_events,
            "failed_logins": len(failed_events),
            "successful_logins": len(success_events),
            "suspicious_ips_count": len(suspicious_ips),
            "suspicious_ips": suspicious_ips,
            "usernames_targeted": targeted_usernames,
        },
        "findings": findings,
        "severity_map": severity_map,
        "recommended_actions": _get_recommendations(severity_map),
    }

    return report_data


def _get_recommendations(severity_map: Dict[str, str]) -> List[str]:
    actions: Set[str] = set()

    actions.add("Review authentication logs for unusual patterns")

    if "High" in severity_map.values():
        actions.add("Enable account lockout policy after 5 failed attempts")
        actions.add("Require multi-factor authentication (MFA) for all accounts")
        actions.add("Rate-limit login attempts per IP address")
        actions.add("Block or monitor suspicious IP addresses at the firewall")
        actions.add("Force password reset for compromised accounts")

    if "Medium" in severity_map.values():
        actions.add("Review accounts that were accessed from suspicious IPs")
        actions.add("Implement geo-IP monitoring for unexpected login locations")

    return sorted(actions)


def print_terminal_report(report_data: ReportData) -> None:
    s = report_data["summary"]

    print("=" * 50)
    print("LogShield Security Report".center(50))
    print("=" * 50)
    print(f"  Generated:       {report_data['generated_at']}")
    print(f"  Total Events:    {s['total_events']}")
    print(f"  Failed Logins:   {s['failed_logins']}")
    print(f"  Successful Logins: {s['successful_logins']}")
    print(f"  Suspicious IPs:  {s['suspicious_ips_count']}")
    print()

    if not s["suspicious_ips"]:
        print("  No suspicious activity detected.")
        print()

    for ip in s["suspicious_ips"]:
        severity = report_data["severity_map"].get(ip, "Unknown")
        ip_findings = [f for f in report_data["findings"] if f["ip"] == ip]
        print(f"  [{severity}] Suspicious IP: {ip}")
        print(f"  Reason:")
        for f in ip_findings:
            print(f"    * {f['detail']}")
        print()

    print("-" * 50)
    print("Recommended Actions".center(50))
    print("-" * 50)
    for action in report_data["recommended_actions"]:
        print(f"  * {action}")
    print()
    print("=" * 50)


def save_text_report(report_data: ReportData, filepath: str) -> None:
    s = report_data["summary"]

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  LogShield Security Incident Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"  Generated: {report_data['generated_at']}\n")
        f.write(f"  Source:    sample_logs.txt\n")
        f.write("\n")
        f.write("-" * 60 + "\n")
        f.write("  Summary\n")
        f.write("-" * 60 + "\n")
        f.write(f"  Total Login Events:      {s['total_events']}\n")
        f.write(f"  Failed Login Attempts:   {s['failed_logins']}\n")
        f.write(f"  Successful Logins:       {s['successful_logins']}\n")
        f.write(f"  Suspicious IPs Found:    {s['suspicious_ips_count']}\n")
        f.write(f"  Usernames Targeted:      {', '.join(s['usernames_targeted'])}\n")
        f.write("\n")

        for ip in s["suspicious_ips"]:
            severity = report_data["severity_map"].get(ip, "Unknown")
            ip_findings = [f for f in report_data["findings"] if f["ip"] == ip]
            f.write(f"  [{severity}] Suspicious IP: {ip}\n")
            f.write("  Detection Reasons:\n")
            for finding in ip_findings:
                f.write(f"    - {finding['detail']}\n")
            f.write("\n")

        f.write("-" * 60 + "\n")
        f.write("  Recommended Defensive Actions\n")
        f.write("-" * 60 + "\n")
        for action in report_data["recommended_actions"]:
            f.write(f"  * {action}\n")
        f.write("\n")
        f.write("=" * 60 + "\n")
        f.write("  End of Report\n")
        f.write("=" * 60 + "\n")

    print(f"  [OK] Text report saved: {filepath}")


def save_json_report(report_data: ReportData, filepath: str) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print(f"  [OK] JSON report saved: {filepath}")
