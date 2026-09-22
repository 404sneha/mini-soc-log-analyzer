# Mini SOC Log Analyzer

A small Python project that analyzes Linux authentication logs and flags suspicious login activity.

I built this to practice log analysis and detection logic in a more practical way.

## What it does

The analyzer currently looks for three types of activity:

- SSH brute-force attempts
- Repeated invalid-user authentication attempts
- A successful login after multiple failed attempts
- Password-spraying activity

Each detected event is turned into an alert with:

- Alert type
- Severity
- Source IP
- Number of failed attempts
- Risk score
- Description

The alerts are then exported as a JSON report.

## How it works

The project follows a simple detection pipeline:

```text
Authentication log
       |
       v
     Parser
       |
       v
Structured events
       |
       v
Detection rules
       |
       v
   Risk engine
       |
       v
 Security alerts
       |
       v
   JSON report
```

This isn't meant to replace a SIEM. It's just a small project to understand how detection and alerting work at a basic level.

## Detection rules
### SSH brute force

Failed SSH login attempts are grouped by source IP.

If an IP generates 5 or more failed attempts, the analyzer creates a HIGH severity alert.

### Invalid user enumeration

The analyzer also looks for repeated attempts to log in with usernames that don't exist on the system.

Two or more attempts from the same IP trigger a MEDIUM severity alert.

### Successful login after multiple failures

This rule looks at the sequence of events rather than treating each log entry independently.

If an IP has multiple failed login attempts followed by a successful login, the activity is flagged as CRITICAL.

This is where event correlation comes in. A single failed login isn't very interesting, but several failures followed by a successful login tell a different story.

### Password spraying

The analyzer looks for failed login attempts from the same source IP against multiple different usernames.

If an IP targets 3 or more different usernames, the activity is flagged as `HIGH`.

For example:
```text
10.10.10.50

admin       ❌
guest       ❌
developer   ❌

        ↓

PASSWORD_SPRAYING
```

## Example

Given a log containing:
```text
Failed password for admin from 192.168.1.50
Failed password for admin from 192.168.1.50
Failed password for admin from 192.168.1.50
Failed password for admin from 192.168.1.50
Failed password for admin from 192.168.1.50
Accepted password for admin from 192.168.1.50
```
The analyzer identifies the sequence and generates an alert similar to:
```text
Alert Type: SUCCESS_AFTER_MULTIPLE_FAILURES
Severity: CRITICAL
Risk Score: 100
Source IP: 192.168.1.50
Failed Attempts: 5
```
## Project structure
```text
mini-soc-log-analyzer/
|
├── sample_logs/
│   └── auth.log
|
├── src/
│   ├── parser.py
│   ├── detector.py
│   ├── risk_engine.py
│   └── main.py
|
├── tests/
│   └── test_detector.py
|
├── reports/
|
├── .gitignore
├── requirements.txt
└── README.md
```
## Running the project
Clone the repository:
```bash
git clone https://github.com/404sneha/mini-soc-log-analyzer.git
cd mini-soc-log-analyzer
```
Create a virtual environment:
```bash
python -m venv .venv
```
On Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
```
Run the analyzer:
```bash
python src/main.py
```
Run the tests:
```bash
python -m unittest discover -s tests -v
```
The current test suite covers all three detection rules.

## Tech used
- Python
- Regular expressions
- Python standard library
- Unit testing
- Git
- GitHub

No external Python packages are required at the moment.

## What's next
This is intentionally a starting point rather than a finished SOC platform.

Some things I want to add:

- Time-based detection windows
- Password spraying detection
- Windows Event Log support
- MITRE ATT&CK mapping
- CSV reporting
- IP reputation checks
- A small web dashboard
- Integration with tools such as Wazuh or a SIEM

## Why this project matters to me

I'm interested in SOC and defensive security, so I wanted one project where I could actually implement detection logic instead of just listing security tools on a resume.

I want to keep improving the detection rules and make them closer to what you'd see in a real SOC workflow.

## Author

Sneha Chaturvedi

B.Tech Information Technology

Interested in SOC operations, threat detection, security monitoring, and defensive security.