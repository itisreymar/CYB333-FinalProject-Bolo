
# Python-Based Security Log Monitoring and Alert System

## Project Overview

This project was developed for CYB 333: Security Automation
at National University. It demonstrates how Python can be
used to automate authentication log analysis, identify
potential security threats, and generate security reports.

The application analyzes simulated authentication logs in
CSV format and uses configurable detection rules to identify
potential brute-force activity and successful logins
following repeated authentication failures.

## Features

- Automated CSV security log parsing
- Authentication event validation
- Chronological event sorting
- Potential brute-force attack detection
- Suspicious successful login detection
- Configurable detection thresholds
- Configurable detection time windows
- Duplicate alert prevention
- Automated security report generation
- Command-line interface
- Input validation and exception handling
- 17 automated unit tests

## Technologies Used

- Python 3
- Visual Studio Code
- Anaconda
- Windows PowerShell
- Git and GitHub
- Python unittest library

## Requirements

- Python 3.10 or newer
- Git (optional, for cloning the repository)

The application uses Python's standard library.
No additional Python packages are required.

## Project Structure

```text
CYB333-FinalProject-Bolo/
├── .gitignore
├── README.md
├── detector.py
├── log_parser.py
├── main.py
├── report_generator.py
├── security_logs.csv
└── test_detector.py
```

| File | Description |
| --- | --- |
| main.py | Main application and command-line interface |
| log_parser.py | Reads and validates authentication logs |
| detector.py | Identifies suspicious authentication activity |
| report_generator.py | Generates and exports security reports |
| security_logs.csv | Simulated authentication dataset |
| test_detector.py | Automated unit tests |
| .gitignore | Excludes generated reports and temporary files |

## Installation

Clone or download this repository and open the project
directory in a terminal.

Ensure Python is installed by running:

```bash
python --version
```

## Usage

Run the application using its default settings:

```bash
python main.py
```

Display available command-line options:

```bash
python main.py --help
```

Customize the detection threshold:

```bash
python main.py --threshold 10
```

Customize the detection time window:

```bash
python main.py --threshold 5 --window 1
```

Specify a different input file:

```bash
python main.py --file security_logs.csv
```

Customize the output report filename:

```bash
python main.py --output custom_report.txt
```

## Detection Rules

### HIGH: Possible Brute-Force Activity

A HIGH alert is generated when an IP address reaches
five failed authentication attempts within a five-minute
window using the default configuration.

### CRITICAL: Success After Repeated Failures

A CRITICAL alert is generated when a successful login
occurs after five failed authentication attempts
associated with the same username and source IP address
within the configured time window.

These alerts represent potentially suspicious activity
and do not independently confirm an account compromise.

## Expected Results

Using the included simulated dataset and default settings:

| Metric | Result |
| --- | --- |
| Total authentication events | 16 |
| Successful logins | 5 |
| Failed logins | 11 |
| HIGH alerts | 2 |
| CRITICAL alerts | 1 |
| Total security alerts | 3 |
| Suspicious IP addresses | 2 |
| Invalid records | 0 |

The application displays its findings in the terminal
and generates a file named security_report.txt.

## Automated Testing

Run the automated unit tests using:

```bash
python -m unittest -v
```

The test suite contains 17 automated tests covering:

- Normal authentication activity
- Brute-force detection
- Suspicious successful logins
- Detection threshold customization
- Time-window boundaries
- Duplicate alert prevention
- Empty datasets
- Missing input files
- Malformed CSV records
- Invalid detection settings
- Report generation

All 17 automated unit tests passed during development.

## Error Handling

The application provides controlled error messages for:

- Missing input files
- Invalid CSV structures
- Invalid detection thresholds
- Invalid detection time windows
- Attempts to overwrite the original input file

Malformed authentication records are skipped and
documented through data validation warnings.

## Security and Ethical Considerations

This project uses simulated authentication data and
IP addresses reserved for documentation purposes.

No real user credentials, production security logs,
or sensitive organizational information are included.

Generated security reports are excluded from GitHub
using the .gitignore file.

This application is intended for educational and
authorized defensive cybersecurity purposes.

## Limitations

- The application analyzes static CSV files rather
  than monitoring authentication events in real time.
- Detection relies on predefined rules and thresholds.
- Suspicious activity may require additional investigation.
- The application does not automatically block IP addresses.
- The detection engine expects chronologically sorted events.

## Future Improvements

Potential improvements include:

- Real-time security log monitoring
- Windows Event Log integration
- Linux authentication log integration
- Email notifications for critical alerts
- MITRE ATT&CK technique mapping
- Graphical security monitoring dashboard
- Additional threat detection rules

## AI Assistance

ChatGPT was used as an AI-assisted development resource
for project planning, Python code generation, troubleshooting
guidance, test case development, and documentation.

The application was executed and tested locally to
verify its functionality and expected behavior.

## Author

Reymar Bolo

National University

CYB 333: Security Automation

November 2026
