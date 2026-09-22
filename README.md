# AWS Cloud Security Misconfiguration Scanner

A Python-based security assessment tool that connects to a real AWS account and automatically detects common cloud security misconfigurations.

## Project Overview

The AWS Cloud Security Misconfiguration Scanner performs a read-only security assessment of an AWS account. It automatically discovers AWS resources, checks their configurations against predefined security rules, identifies security misconfigurations, assigns risk severity, calculates a security score, and provides recommendations.

## Objective

The objective of this project is to develop a read-only AWS cloud security scanner that automatically discovers cloud resources, evaluates their configurations against predefined security rules, identifies security misconfigurations, assigns risk severity, and provides recommendations to improve the security posture of the AWS environment.

## Features

- AWS account authentication using Boto3
- Automatic AWS resource discovery
- S3 security assessment (Public Access Block, ACLs, Bucket Policies, Encryption, Versioning)
- IAM security assessment (MFA enforcement, Access key age)
- EC2 & Security Group analysis (Public SSH, RDP, unrestricted ingress)
- CloudTrail configuration assessment (Multi-region, logging status)
- Risk severity classification and security score calculation
- Web Dashboard (Flask) and Terminal-based CLI
- One-click JSON & CSV report export

## AWS Services Scanned

### Amazon S3
- Block Public Access configuration
- Server-side encryption (SSE)
- Bucket versioning
- Bucket ACLs & bucket policies allowing public access

### AWS IAM
- Multi-Factor Authentication (MFA) enforcement on IAM users
- Active access key age and rotation (> 90 days)

### Amazon EC2 and Security Groups
- Inbound security group rules exposing ports to `0.0.0.0/0` or `::/0`
- Unrestricted traffic (`All Traffic / Protocol -1`)
- SSH (Port 22) exposure
- RDP (Port 3389) exposure
- Custom public ports exposure

### AWS CloudTrail
- Trail existence in the account
- Active logging status
- Multi-region trail configuration

## Risk Classification

| Severity | Risk Points |
| :--- | :--- |
| **CRITICAL** | 20 |
| **HIGH** | 10 |
| **MEDIUM** | 5 |
| **LOW** | 2 |

### Security Score Formula:
```text
Security Score = max(0, 100 - Total Risk)
```

**Score Status:**
- **GOOD**: 90 – 100
- **MODERATE**: 70 – 89
- **NEEDS ATTENTION**: 40 – 69
- **HIGH RISK**: 0 – 39

## Architecture

```text
                  AWS CLOUD
                      |
                    Boto3
                      |
                      v
              +---------------+
              |    Scanner    |
              |  scanner.py   |
              +-------+-------+
                      |
         +------------+------------+
         |            |            |
         v            v            v
        S3           IAM       EC2 / Security
                                 Groups
         |            |            |
         +------------+------------+
                      |
                      v
                  CloudTrail
                      |
                      v
               Security Checks
                      |
                      v
               Risk Calculation
                      |
                      v
              Security Assessment
                      |
         +------------+------------+
         |                         |
         v                         v
   Web Dashboard             Terminal Report
  (JSON/CSV Export)         (report.json/csv)
```

## Technology Stack

- **Language:** Python 3.x
- **Cloud SDK:** AWS Boto3
- **Web Interface:** Flask, HTML5, CSS3, JavaScript
- **Supported AWS Services:** IAM, S3, EC2, VPC Security Groups, CloudTrail, STS

## Project Structure

```text
aws-cloud-security-scanner/
│
├── app.py                 # Flask web dashboard application
├── scanner.py             # Core security assessment engine (CLI & API)
├── requirements.txt       # Project dependencies
├── .gitignore             # Git ignore rules
├── templates/
│   └── index.html         # Web dashboard HTML template
├── static/
│   ├── style.css          # Dashboard stylesheet
│   └── app.js             # Frontend controller
└── README.md              # Project documentation
```

## Requirements

- Python 3.8+
- Active AWS Account
- AWS CLI installed and configured
- AWS IAM credentials with read-only permissions (`SecurityAudit` or `ReadOnlyAccess`)

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/mowlishwar07/AWS-Cloud-Security-Scanner.git
cd AWS-Cloud-Security-Scanner
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure AWS credentials
```bash
aws configure
```
Enter your AWS Access Key, Secret Key, and default region (e.g. `ap-south-1`) when prompted.

> **Note:** The scanner uses the standard AWS credential chain through Boto3. Never hard-code AWS credentials in the source code.

## Running the Scanner

### Option A: Web Dashboard (Interactive UI)
```bash
python app.py
```
Open your browser and navigate to:
```text
http://127.0.0.1:5000
```
- Select your target AWS region from the dropdown.
- Click **"Run Security Scan"**.
- View the security score, severity breakdown, and filter findings by service or severity.
- Export findings directly to **JSON** or **CSV**.

### Option B: Terminal CLI
```bash
python scanner.py
```
Enter your AWS region when prompted. The scanner will output the assessment in the console and automatically save `report.json` and `report.csv` in the project root.

## Example Output

```text
==================================================
              SECURITY ASSESSMENT
==================================================

Findings Summary
--------------------------------------------------
CRITICAL : 0
HIGH     : 2
MEDIUM   : 1
LOW      : 0

Total Findings : 3
Total Risk     : 25
Security Score : 75/100
Assessment     : MODERATE

==================================================
               SECURITY FINDINGS
==================================================

--------------------------------------------------
Finding #1
Service        : IAM
Resource       : test-user
Issue          : MFA is not enabled for the IAM user
Severity       : HIGH
Risk           : 10
Recommendation : Enable MFA for the IAM user

--------------------------------------------------
Finding #2
Service        : S3
Resource       : public-bucket-test
Issue          : S3 Block Public Access is not fully enabled
Severity       : HIGH
Risk           : 10
Recommendation : Enable all S3 Block Public Access settings

==================================================
                 SCAN COMPLETE
==================================================
✓ Saved reports:
  • report.json
  • report.csv
```

## Security Design

The scanner is strictly a **read-only** assessment tool:
- Does **not** modify AWS resources
- Does **not** delete resources
- Does **not** exploit vulnerabilities
- Masks sensitive access key IDs in console logs
- Only reads configuration metadata using AWS `describe_*`, `list_*`, and `get_*` APIs

## Author

**Mowlishwar T**  
B.E. Computer Science and Engineering (Cyber Security)

## License

This project is developed for educational and security assessment purposes under the MIT License.
