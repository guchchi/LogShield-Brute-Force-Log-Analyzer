# Detection Logic

## Overview

LogShield uses rule-based detection to identify suspicious login behavior from authentication log entries. The logic is designed to be simple, readable, and easy to understand for beginners learning about log analysis.

## Parsing

Each log line is parsed using a regular expression:

```
(\S+ \S+) (FAILED|SUCCESS) username=(\S+) ip=(\S+)
```

This extracts:
- **Timestamp** — date and time of the event
- **Status** — FAILED or SUCCESS
- **Username** — the account targeted
- **IP Address** — the source IP of the attempt

Lines that do not match this format are silently skipped.

## Detection Rules

### Rule 1: Failed Login Threshold

- **Threshold:** 5 or more failed attempts from the same IP address
- **Purpose:** Detects automated brute-force attacks where an attacker tries many passwords rapidly
- **Rationale:** A small number of failed logins may be user error, but sustained failures from one source suggest automated guessing
- **Example:** If IP `192.168.1.45` has 6 failed attempts, it is flagged

### Rule 2: Multiple Username Attempts

- **Threshold:** 3 or more different usernames from the same IP address
- **Purpose:** Detects password spraying or user enumeration where an attacker cycles through multiple accounts
- **Rationale:** A legitimate user typically logs into one account. An IP targeting many usernames suggests the attacker is probing for valid accounts
- **Example:** If IP `192.168.1.100` tries 6 different usernames (admin, backup, nobody, root, svc_account, test), it is flagged

### Rule 3: Success After Failures

- **Threshold:** Any successful login following one or more failed attempts from the same IP
- **Purpose:** Detects successful brute-force attacks where the attacker eventually found valid credentials
- **Rationale:** A success after many failures is the most serious indicator — it suggests the attacker got in
- **Example:** If IP `192.168.1.45` has 6 failed attempts and then a SUCCESS, it is flagged

## Severity Calculation

Severity is assigned per IP address based on the combination of signals:

| Condition | Severity |
|---|---|
| 5+ failed attempts OR success after failures | High |
| 3-4 failed attempts OR 3+ usernames | Medium |
| 1-2 failed attempts | Low |
| No suspicious signals | None |

## Aggregation

1. All parsed events are grouped by IP address
2. For each IP, the engine counts:
   - Total failed attempts
   - Unique usernames seen
   - Whether a successful event exists alongside failures
3. Each detection rule is evaluated independently
4. The final severity is the highest level triggered by any rule

## False Positive Considerations

- A user with a forgotten password might trigger the failed login threshold
- Shared IP addresses (NAT, VPN) may appear as multiple usernames from one source
- Success after failures is not always malicious — a user may eventually remember their password

These are documented to highlight that detection is only one part of a larger security review process.
