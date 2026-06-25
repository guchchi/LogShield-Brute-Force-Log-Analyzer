# Threat Model

## Scope

This project analyzes sample authentication logs in a safe lab environment. It is designed for defensive learning and does not interact with real systems.

## Assets

| Asset | Description |
|---|---|
| User accounts | The usernames present in the sample log data |
| Login systems | The simulated authentication events being analyzed |
| Authentication logs | The log entries being parsed and evaluated |
| Source IP information | The IP addresses recorded in log entries |
| Detection output | The findings, severity scores, and reports generated |

## Attacker Behavior Studied

- Repeated failed login attempts from a single source
- Password guessing attempts against multiple accounts
- Multiple attempts from the same IP address
- Attempts against privileged usernames such as admin
- High-frequency authentication failures in a short period

## Trust Boundaries

| Boundary | Description |
|---|---|
| Raw log file | The input file containing authentication events |
| Parser logic | Extracts structured fields from raw text |
| Detection threshold logic | Applies rules to identify suspicious patterns |
| Alert/output generation | Formats findings into reports |
| Analyst review | Human interpretation of the generated report |

## Risks Studied

| Risk | Description |
|---|---|
| Brute-force attack | Many failed logins from one IP targeting one username |
| Password spraying | One IP trying many different usernames |
| Account takeover | Success after repeated failures — credentials may be compromised |
| Detection evasion | Attacker spreading attempts across multiple IPs to avoid thresholds |

## Defensive Controls

- Threshold-based detection flags high volumes of failed attempts
- Severity scoring helps prioritize investigation
- Multiple detection rules cover different attack patterns
- Text and JSON reports support both human review and automation
- Recommended defensive actions provide response guidance
