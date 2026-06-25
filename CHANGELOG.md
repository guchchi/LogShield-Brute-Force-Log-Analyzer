# Changelog

## [1.0.0] — 2026-06-18

### Added

- Initial release of LogShield
- Log parsing engine for authentication log format
- Detection Rule 1: Failed login threshold (5+ attempts from one IP)
- Detection Rule 2: Multiple username attempts (3+ usernames from one IP)
- Detection Rule 3: Success after repeated failures
- Severity scoring: Low, Medium, High
- Terminal security report output
- Text report saved as `reports/incident_report.txt`
- JSON report saved as `reports/incident_report.json`
- Sample authentication logs with realistic but fake data
- Full type hints across all modules
- MIT License
