# Future Improvements

## Detection Enhancements

- **Time-window based detection** — flag IPs with X failures in Y seconds instead of a cumulative count
- **Configurable thresholds** — allow users to set thresholds via command-line arguments or config file
- **Whitelist/allowlist support** — exclude trusted IPs from detection
- **Failed/successful login correlation** — track which specific accounts were successfully compromised after failures
- **Geolocation lookup** — add optional IP geolocation to identify unexpected login locations

## Input Formats

- **CSV log support** — parse authentication logs in CSV format
- **JSON log support** — parse structured JSON log formats
- **Linux auth.log format** — add parser for standard Linux authentication logs (`/var/log/auth.log`)
- **Windows Event Log format** — add parser for Windows Event ID 4625 (failed logon) style logs

## Output and Reporting

- **Dashboard visualization** — generate simple HTML dashboard with charts
- **CSV export** — export findings to CSV for spreadsheet analysis
- **Email alerts** — optional email notification when high-severity patterns are detected
- **Summary metrics** — add more summary metrics such as unique IP count, unique username count, event timeline

## Code Quality

- **Unit tests** — add tests for each detection rule with known inputs and expected outputs
- **Configuration file** — support YAML or JSON config for thresholds, file paths, and output options
- **Logging** — add structured logging for debugging and audit trail
- **Performance** — optimize parsing for large log files

## Learning Features

- **More sample datasets** — add additional sample log files covering different attack scenarios
- **Annotated output** — add explanations alongside detection results for beginners
- **Interactive mode** — add step-by-step mode that explains each detection step
