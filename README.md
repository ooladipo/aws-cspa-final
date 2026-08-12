# 🛡️ AWS Cloud Security Posture Assessment Tool (aws-cspa)

A lightweight Node.js tool for detecting common misconfigurations in AWS environments.

**MSc Cybersecurity Project — Arden University Berlin**

---

## What It Checks

| Check | Service | What It Detects |
|-------|---------|-----------------|
| Public Access Block | S3 | Buckets missing public access block settings |
| Public ACL Grants | S3 | Buckets with ACLs granting public read/write |
| Wildcard Policies | IAM | Policies with Action:* or Resource:* |
| Policies on Users | IAM | Policies attached directly to users (anti-pattern) |
| Logging Disabled | CloudTrail | Trails that exist but are not actively logging |
| Single-Region Trail | CloudTrail | Trails that don't cover all regions |
| Log Validation Off | CloudTrail | Trails without integrity validation enabled |

---

## Setup

### 1. Prerequisites
- Node.js v18+
- An AWS account (free tier works)
- AWS CLI installed and configured

### 2. Install
```bash
git clone https://github.com/ooladipo/aws-cspa-final.git
cd aws-cspa
npm install
```

### 3. Configure AWS Credentials
```bash
aws configure
# Enter your Access Key ID, Secret Access Key, and default region
```

Or set environment variables:
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=eu-west-1
```

### 4. Required IAM Permissions
Your AWS user/role needs these permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketAcl",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:ListUsers",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Run

```bash
npm start
```

The tool will:
1. Connect to your AWS account
2. Run all three checks (S3, IAM, CloudTrail)
3. Print a summary to the terminal
4. Save a full HTML report to `./reports/`

---

## Output

**Terminal:**
```
══════════════════════════════════════════════════════════
  AWS Cloud Security Posture Assessment Tool
  Version 1.0.0
══════════════════════════════════════════════════════════

✔ S3 check complete
✔ IAM check complete
✔ CloudTrail check complete

──────────────────────────────────────────────────────────
  ASSESSMENT SUMMARY
──────────────────────────────────────────────────────────
  🔴 Critical : 2
  🟠 High     : 1
  🟡 Medium   : 3
  🔵 Low      : 0
  ✅ Passed   : 5
──────────────────────────────────────────────────────────

  📄 Full report saved to: /path/to/reports/report-xxxxx.html
```

**HTML Report:** A clean, colour-coded risk report with findings, details, and recommendations for each misconfiguration detected.

---

## Project Structure

```
aws-cspa/
├── index.js                        # Main entry point
├── package.json
├── README.md
├── reports/                        # Generated HTML reports
└── src/
    ├── checks/
    │   ├── s3Check.js              # S3 public access checks
    │   ├── iamCheck.js             # IAM policy checks
    │   └── cloudtrailCheck.js      # CloudTrail logging checks
    └── report/
        └── reportGenerator.js      # HTML report generator
```

---

## Technologies

- **Runtime:** Node.js (ES Modules)
- **AWS SDK:** `@aws-sdk/client-s3`, `@aws-sdk/client-iam`, `@aws-sdk/client-cloudtrail`
- **CLI UX:** `chalk`, `ora`
- **Report:** Vanilla HTML/CSS (no dependencies)

---

## Academic Context

This tool was developed as part of an MSc Cybersecurity dissertation at Arden University Berlin. It demonstrates practical application of cloud security principles including the CIS AWS Foundations Benchmark and AWS Well-Architected Security Pillar.
