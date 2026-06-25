import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

FAILED_ATTEMPT_THRESHOLD = 5
MULTIPLE_USERNAME_THRESHOLD = 3

LogEntry = Dict[str, str]
Finding = Dict[str, Any]


def parse_log_line(line: str) -> Optional[LogEntry]:
    pattern = r"(\S+ \S+) (FAILED|SUCCESS) username=(\S+) ip=(\S+)"
    match = re.match(pattern, line.strip())
    if not match:
        return None
    return {
        "timestamp": match.group(1),
        "status": match.group(2),
        "username": match.group(3),
        "ip": match.group(4),
    }


def analyze_logs(
    parsed_logs: List[LogEntry],
) -> Tuple[List[Finding], Dict[str, str]]:
    ip_events: Dict[str, List[LogEntry]] = defaultdict(list)

    for entry in parsed_logs:
        ip_events[entry["ip"]].append(entry)

    ip_failed_counts: Dict[str, int] = {}
    ip_usernames: Dict[str, Set[str]] = {}
    ip_success_after_failures: Dict[str, bool] = {}

    for ip, events in ip_events.items():
        failed = [e for e in events if e["status"] == "FAILED"]
        successes = [e for e in events if e["status"] == "SUCCESS"]
        ip_failed_counts[ip] = len(failed)
        usernames_tried = set(e["username"] for e in events)
        ip_usernames[ip] = usernames_tried
        ip_success_after_failures[ip] = bool(failed and successes)

    findings: List[Finding] = []

    findings.extend(
        detect_failed_attempts(ip_failed_counts, FAILED_ATTEMPT_THRESHOLD)
    )
    findings.extend(
        detect_multiple_usernames(ip_usernames, MULTIPLE_USERNAME_THRESHOLD)
    )
    findings.extend(
        detect_success_after_failures(ip_success_after_failures)
    )

    severity_map: Dict[str, str] = {}
    for ip in set(
        list(ip_failed_counts.keys())
        + list(ip_usernames.keys())
        + list(ip_success_after_failures.keys())
    ):
        severity_map[ip] = calculate_severity(
            failed_count=ip_failed_counts.get(ip, 0),
            username_count=len(ip_usernames.get(ip, set())),
            success_after_failures=ip_success_after_failures.get(ip, False),
        )

    return findings, severity_map


def detect_failed_attempts(
    ip_failed_counts: Dict[str, int], threshold: int
) -> List[Finding]:
    findings: List[Finding] = []
    for ip, count in ip_failed_counts.items():
        if count >= threshold:
            findings.append({
                "ip": ip,
                "rule": "high_failed_attempts",
                "detail": f"{count} failed login attempts",
                "count": count,
            })
    return findings


def detect_multiple_usernames(
    ip_usernames: Dict[str, Set[str]], threshold: int
) -> List[Finding]:
    findings: List[Finding] = []
    for ip, usernames in ip_usernames.items():
        if len(usernames) >= threshold:
            findings.append({
                "ip": ip,
                "rule": "multiple_usernames",
                "detail": f"{len(usernames)} different usernames targeted: {', '.join(sorted(usernames))}",
                "count": len(usernames),
            })
    return findings


def detect_success_after_failures(
    ip_success_after_failures: Dict[str, bool],
) -> List[Finding]:
    findings: List[Finding] = []
    for ip, has_pattern in ip_success_after_failures.items():
        if has_pattern:
            findings.append({
                "ip": ip,
                "rule": "success_after_failures",
                "detail": "Successful login after multiple failed attempts",
            })
    return findings


def calculate_severity(
    failed_count: int,
    username_count: int,
    success_after_failures: bool,
) -> str:
    if failed_count >= FAILED_ATTEMPT_THRESHOLD or success_after_failures:
        return "High"
    if failed_count >= 3 or username_count >= MULTIPLE_USERNAME_THRESHOLD:
        return "Medium"
    if failed_count >= 1:
        return "Low"
    return "None"
