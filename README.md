# Security Log Analyzer

A Python-based security log analyzer for detecting suspicious authentication activity.

## Overview

Security Log Analyzer is a Python project that analyzes authentication logs and identifies potentially suspicious login activity.

The project focuses on basic defensive security concepts such as failed login analysis, brute-force detection, and suspicious activity from multiple IP addresses.

The log data used in this project is synthetic and created for testing purposes.

## Features

* Parse authentication log entries
* Detect malformed log entries and invalid timestamps
* Count successful and failed login attempts
* Analyze failed login attempts by IP address
* Detect potential brute-force activity based on failed attempts within a time window
* Analyze failed login attempts by username
* Detect usernames associated with multiple IP addresses
* Generate a security analysis report
* Handle missing log files
* Automated unit tests using pytest

## Technologies

* Python 3
* Git & GitHub
* pytest

## Project Structure

```text
security-log-analyzer/
├── src/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── parser.py
│   ├── reporter.py
│   └── report_generator.py
├── logs/
│   └── sample_uth.log
├── reports/
│   └── security_report.txt
├── tests/
│   ├── test_analyzer.py
│   └── test_parser.py
├── .gitignore
├── pytest.ini
└── README.md
```

## How It Works

The analyzer reads authentication log entries and processes them through several stages:

1. Parse and validate each log entry.
2. Count successful and failed login attempts.
3. Group failed login attempts by IP address.
4. Detect potential brute-force activity.
5. Group failed login attempts by username.
6. Detect usernames associated with multiple IP addresses.
7. Display the results in the terminal.
8. Generate a security analysis report.

## Detection Rules

### Brute-Force Detection

An IP address is considered suspicious when at least **3 failed login attempts occur within 60 seconds**.

### Multiple-IP Detection

A username is considered suspicious when failed login attempts for that username originate from at least **3 different IP addresses**.

These thresholds can be configured in `src/analyzer.py`.

## Example Output

```text
Security Log Analyzer
=====================
Total log entries: 10
Successful logins: 4
Failed logins: 6

Failed login attempts by IP:
192.168.1.42: 3 failed attempts - SUSPICIOUS
10.0.0.25: 1 failed attempts
10.0.0.50: 1 failed attempts
10.0.0.51: 1 failed attempts

Suspicious IPs detected: 1

Failed login attempts by username:
admin: 5 failed attempts from 3 IP(s)
john: 1 failed attempts from 1 IP(s)

Suspicious usernames:
admin: SUSPICIOUS
```

## Security Report

The analyzer automatically generates a report at:

```text
reports/security_report.txt
```

The report includes:

* Summary statistics
* Suspicious IP addresses
* Suspicious usernames
* Overall findings

## Testing

The project includes automated unit tests using pytest.

Run the tests with:

```bash
pytest
```

The tests cover:

* Valid log parsing
* Malformed log handling
* Invalid timestamp handling
* Brute-force detection
* Non-brute-force activity
* Multiple-IP detection
* Non-suspicious username activity

All current tests pass successfully.

## Limitations

This project was developed as a learning and portfolio project.

The detection rules are intentionally simple and are not intended to replace a production Security Information and Event Management (SIEM) system.

The project currently analyzes static synthetic log files rather than real-time security events.

## Future Improvements

Possible future improvements include:

* Support for additional log formats
* Real-time log monitoring
* Configurable detection thresholds
* Export reports to JSON or CSV
* More advanced anomaly detection
* Improved test coverage
* Support for larger log datasets

## Author

**Vasileios Ladopoulos**

Digital Systems Student at the University of Thessaly.

Interested in software development, programming, databases, and cybersecurity.