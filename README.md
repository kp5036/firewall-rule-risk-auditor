# Firewall Rule Risk Auditor

A Python and Flask web application that audits firewall-style rules, detects risky public exposure, classifies findings by severity, and generates plain-English remediation guidance.

**Live Demo:** https://firewall-rule-risk-auditor.onrender.com/

## Overview

Firewall Rule Risk Auditor is a security-focused software project built to identify common firewall and cloud security misconfigurations.

Users can paste firewall-style rules into the web app, and the tool analyzes each rule for public exposure, risky services, and least-privilege access issues. The app returns a clear risk level, explanation, and recommendation for each finding.

This project demonstrates both software engineering and cybersecurity fundamentals, including backend development, rule parsing, risk classification, security automation, and remediation reporting.

## Features

- Web interface for analyzing firewall-style rules
- Rule format guide for users
- Parses action, protocol, port, and source network
- Detects public exposure such as `0.0.0.0/0`
- Maps common ports to services such as SSH, HTTPS, MySQL, PostgreSQL, Redis, and RDP
- Classifies findings as HIGH, MEDIUM, LOW, SAFE, REVIEW, or INVALID
- Provides plain-English reasons and remediation recommendations
- Includes a CLI version that can generate an `audit_report.txt` file
- Deployed publicly on Render

## Rule Format

Rules should follow this format:

```text
ACTION PROTOCOL PORT FROM SOURCE
```

Example:

```text
ALLOW TCP 22 FROM 0.0.0.0/0
```

Meaning:

- `ALLOW` permits traffic
- `DENY` blocks traffic
- `TCP` is the protocol
- `22` is the port number
- `FROM` is the required keyword
- `0.0.0.0/0` means open to the public internet

## Example Input

```text
ALLOW TCP 22 FROM 0.0.0.0/0
ALLOW TCP 443 FROM 0.0.0.0/0
ALLOW TCP 3306 FROM 0.0.0.0/0
DENY TCP 23 FROM 0.0.0.0/0
```

## Example Output

```text
HIGH — SSH
Reason: SSH is exposed to the public internet.
Recommendation: Restrict access to trusted IP addresses or private network ranges.

LOW — HTTPS
Reason: HTTPS is publicly exposed, which is common for web services.
Recommendation: Confirm this service is intentionally public and protected with proper security controls.

HIGH — MySQL
Reason: MySQL is exposed to the public internet.
Recommendation: Restrict access to trusted IP addresses or private network ranges.

SAFE — Telnet
Reason: This rule denies traffic, so it does not expose the service.
Recommendation: No immediate action required.
```

## Common Ports Checked

| Port | Service |
|---|---|
| 22 | SSH |
| 23 | Telnet |
| 80 | HTTP |
| 443 | HTTPS |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 3389 | Remote Desktop Protocol |
| 6379 | Redis |
| 8080 | Alternate HTTP |

## Tech Stack

- Python
- Flask
- HTML
- CSS
- Gunicorn
- Render
- Git and GitHub

## Project Structure

```text
firewall-rule-risk-auditor/
├── app.py
├── main.py
├── parser.py
├── risk_engine.py
├── reporter.py
├── sample_rules.txt
├── audit_report.txt
├── requirements.txt
├── Procfile
├── templates/
│   └── index.html
└── static/
    └── style.css
```

## Run Locally

Clone the repository:

```bash
git clone https://github.com/kp5036/firewall-rule-risk-auditor.git
cd firewall-rule-risk-auditor
```

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run the web app:

```bash
python3 app.py
```

Open in your browser:

```text
http://127.0.0.1:5000
```

## CLI Usage

The project also includes a CLI version.

Run:

```bash
python3 main.py
```

This reads `sample_rules.txt` and generates:

```text
audit_report.txt
```

## Security Concepts Demonstrated

- Firewall rule review
- Public exposure detection
- Cloud security misconfiguration analysis
- Port and service risk mapping
- Least-privilege access review
- Risk classification
- Security automation
- Plain-English remediation reporting

## Author

**Krish Patel**

GitHub: https://github.com/kp5036  
LinkedIn: https://linkedin.com/in/krishpatel21