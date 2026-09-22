# AWS Cloud Security Misconfiguration Scanner

A Python-based security assessment tool that connects to a real AWS account and automatically detects common cloud security misconfigurations.

## Project Overview

The AWS Cloud Security Misconfiguration Scanner performs a read-only security assessment of an AWS account. It automatically discovers AWS resources, checks their configurations against predefined security rules, identifies security misconfigurations, assigns risk severity, calculates a security score, and provides recommendations.

## Objective

The objective of this project is to develop a read-only AWS cloud security scanner that automatically discovers cloud resources, evaluates their configurations against predefined security rules, identifies security misconfigurations, assigns risk severity, and provides recommendations to improve the security posture of the AWS environment.

## Features

- AWS account authentication using Boto3
- Automatic AWS resource discovery
- S3 security assessment
- IAM security assessment
- EC2 security assessment
- Security Group analysis
- CloudTrail configuration assessment
- Security misconfiguration detection
- Risk severity classification
- Security score calculation
- Security recommendations
- Terminal-based security report

## AWS Services Scanned

### Amazon S3

The scanner checks S3 buckets for:

- Block Public Access
- Server-side encryption
- Bucket versioning

### AWS IAM

The scanner checks IAM users for:

- MFA configuration
- Access key status

### Amazon EC2 and Security Groups

The scanner checks security groups for potentially dangerous inbound rules, including:

- Unrestricted traffic
- SSH (Port 22)
- RDP (Port 3389)
- Other publicly exposed ports

### AWS CloudTrail

The scanner checks:

- CloudTrail trail existence
- Logging status
- Multi-region configuration

## Risk Classification

| Severity | Risk |
|----------|------|
| CRITICAL | 20 |
| HIGH | 10 |
| MEDIUM | 5 |
| LOW | 2 |

Security score:

```text
Security Score = max(0, 100 - Total Risk)

Example:

CRITICAL : 0
HIGH     : 2
MEDIUM   : 0
LOW      : 0

Total Findings : 2
Total Risk     : 20
Security Score : 80/100
Architecture
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
                     v
              Terminal Output
Technology Stack
Python
Boto3
Amazon Web Services (AWS)
AWS IAM
Amazon S3
Amazon EC2
Amazon CloudTrail
AWS Security Groups
Project Structure
aws-cloud-security-scanner/
│
├── app.py                 # Flask web dashboard application
├── scanner.py             # Core security assessment engine (CLI & API)
├── requirements.txt       # Dependencies (boto3, flask)
├── .gitignore             # Git ignore rules for Python & AWS credentials
├── templates/
│   └── index.html         # Dashboard HTML template
├── static/
│   ├── style.css          # Clean dashboard stylesheet
│   └── app.js             # Frontend controller
└── README.md              # Project documentation

Requirements
Python 3.x
AWS Account
AWS CLI
Boto3, Flask
AWS IAM credentials with read-only permissions

Installation
1. Clone the repository
git clone https://github.com/mowlishwar07/AWS-Cloud-Security-Scanner.git
cd AWS-Cloud-Security-Scanner

2. Install dependencies
pip install -r requirements.txt

3. Configure AWS credentials
aws configure

Enter your AWS credentials and region when prompted.

Example:

Default region name: ap-south-1
Default output format: json

The scanner uses the standard AWS credential chain through Boto3.
Do not hard-code AWS credentials in the source code.

Running the Scanner

Option A: Web Dashboard (Interactive UI)
python app.py

Open your browser and navigate to:
http://127.0.0.1:5000

Features:
- Run live AWS security scans across regions
- Interactive filtering by severity (Critical, High, Medium, Low) and service
- One-click JSON & CSV report download

Option B: Terminal CLI
python scanner.py

Enter your AWS region:

========================================
     AWS CLOUD SECURITY SCANNER
========================================

Enter AWS Region:
> ap-south-1

The scanner will authenticate with AWS, discover resources, perform security checks, save report.json & report.csv, and display the assessment summary.

Example Output
==================================================
          SECURITY ASSESSMENT
==================================================

Findings Summary
--------------------------------------------------
CRITICAL : 0
HIGH     : 2
MEDIUM   : 0
LOW      : 0

Total Findings : 2
Total Risk     : 20
Security Score : 80/100

==================================================
           SECURITY FINDINGS
==================================================

--------------------------------------------------
Finding #1
Service        : IAM
Resource       : cloud-security-scanner
Issue          : MFA is not enabled for the IAM user
Severity       : HIGH
Risk           : 10
Recommendation: Enable MFA for the IAM user

--------------------------------------------------
Finding #2
Service        : CloudTrail
Resource       : AWS Account
Issue          : CloudTrail trail is not configured
Severity       : HIGH
Risk           : 10
Recommendation: Create and enable a CloudTrail trail for AWS activity logging

==================================================
             SCAN COMPLETE
==================================================
Security Design

The scanner is designed as a read-only security assessment tool.

It:

Does not modify AWS resources
Does not delete resources
Does not exploit vulnerabilities
Does not perform penetration testing
Does not automatically apply security changes

The tool only reads AWS configuration information and reports potential security issues.

Project Scope
In Scope
AWS resource discovery
IAM security configuration
S3 security configuration
EC2 security groups
Network exposure
CloudTrail configuration
Risk assessment
Security scoring
Security recommendations
Out of Scope
Penetration testing
Vulnerability exploitation
Malware detection
Continuous monitoring
Automated remediation
Web application security testing
Source-code vulnerability scanning
Why This Project?

Cloud security incidents can occur because of simple configuration mistakes.

For example:

No MFA
   |
   v
Compromised credentials
   |
   v
Unauthorized AWS access

Another example:

SSH exposed to Internet
        |
        v
Increased attack surface
        |
        v
Possible unauthorized access

The scanner helps identify such configuration weaknesses before they become security problems.

Future Enhancements
Additional AWS service checks
IPv6 security group analysis
IAM access key age analysis
IAM permission analysis
JSON reports
CSV reports
Automated remediation
Web-based dashboard
Continuous security monitoring
AWS Security Hub integration
Author

Mowlishwar T

B.E. Computer Science and Engineering (Cyber Security)

License

This project is developed for educational and security assessment purposes.