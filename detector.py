import re
from collections import defaultdict

FAILED_ATTEMPT_THRESHOLD = 5
MULTIPLE_USERNAME_THRESHOLD = 3


def parse_log_line(line):
    """Parse a single log line into a structured dictionary.

    Expected format:
    2026-06-18 10:01:11 FAILED username=admin ip=192.168.1.45
    """
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


def analyze_logs(parsed_logs):
    """Run all detection rules against parsed logs and return findings.

    This is the core detection engine. It aggregates data per IP and per
    username, then runs each detection rule to flag suspicious behavior.
    """
    # Group events by IP address
    ip_events = defaultdict(list)
    username_events = defaultdict(list)

    for entry in parsed_logs:
        ip_events[entry["ip"]].append(entry)
        username_events[entry["username"]].append(entry)

    ip_failed_counts = {}
    ip_usernames = {}
    ip_success_after_failures = {}

    for ip, events in ip_events.items():
        failed = [e for e in events if e["status"] == "FAILED"]
        successes = [e for e in events if e["status"] == "SUCCESS"]
        ip_failed_counts[ip] = len(failed)

        # Collect unique usernames attempted from this IP
        usernames_tried = set(e["username"] for e in events)
        ip_usernames[ip] = usernames_tried

        # Track if any success came after failures (sign of successful brute-force)
        ip_success_after_failures[ip] = bool(failed and successes)

    findings = []

    # Rule 1: Failed login threshold
    findings.extend(
        detect_failed_attempts(ip_failed_counts, FAILED_ATTEMPT_THRESHOLD)
    )

    # Rule 2: Multiple username attempts
    findings.extend(
        detect_multiple_usernames(ip_usernames, MULTIPLE_USERNAME_THRESHOLD)
    )

    # Rule 3: Success after failures
    findings.extend(
        detect_success_after_failures(ip_success_after_failures)
    )

    # Calculate severity per IP
    severity_map = {}
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


def detect_failed_attempts(ip_failed_counts, threshold):
    """Rule 1: Flag IPs with failed attempts above the threshold.

    In brute-force attacks, attackers send many failed login attempts
    rapidly. Monitoring failed attempt counts per IP helps detect this.
    """
    findings = []
    for ip, count in ip_failed_counts.items():
        if count >= threshold:
            findings.append({
                "ip": ip,
                "rule": "high_failed_attempts",
                "detail": f"{count} failed login attempts",
                "count": count,
            })
    return findings


def detect_multiple_usernames(ip_usernames, threshold):
    """Rule 2: Flag IPs that try many different usernames.

    Attackers often cycle through lists of usernames to find valid
    accounts. A single IP targeting many usernames is suspicious.
    """
    findings = []
    for ip, usernames in ip_usernames.items():
        if len(usernames) >= threshold:
            findings.append({
                "ip": ip,
                "rule": "multiple_usernames",
                "detail": f"{len(usernames)} different usernames targeted: {', '.join(sorted(usernames))}",
                "count": len(usernames),
            })
    return findings


def detect_success_after_failures(ip_success_after_failures):
    """Rule 3: Flag IPs that succeeded after failing.

    This pattern suggests a successful brute-force attack: the attacker
    tried many times and eventually got in.
    """
    findings = []
    for ip, has_pattern in ip_success_after_failures.items():
        if has_pattern:
            findings.append({
                "ip": ip,
                "rule": "success_after_failures",
                "detail": "Successful login after multiple failed attempts",
            })
    return findings


def calculate_severity(failed_count, username_count, success_after_failures):
    """Calculate severity level based on detection signals.

    Low:    1-2 failed attempts
    Medium: 3-4 failed attempts or multiple usernames
    High:   5+ failed attempts or success after many failures
    """
    if failed_count >= FAILED_ATTEMPT_THRESHOLD or success_after_failures:
        return "High"
    if failed_count >= 3 or username_count >= MULTIPLE_USERNAME_THRESHOLD:
        return "Medium"
    if failed_count >= 1:
        return "Low"
    return "None"
