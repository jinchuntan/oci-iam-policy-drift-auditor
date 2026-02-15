# ACE Contribution Sample

## Title
OCI IAM Policy Drift Auditor with Risk Severity and Audit Correlation

## Description
This OCI Python SDK automation audits IAM policies across scoped compartments, detects risky policy statements using severity-based rules, and correlates findings with recent IAM change activity from OCI Audit. It enriches risk context by mapping referenced IAM groups to current member counts and summarizing tenancy MFA adoption. The tool generates JSON and Markdown artifacts and uploads them to OCI Object Storage for governance evidence and operational review. The workflow is non-destructive and uses read-only OCI APIs except Object Storage uploads.

## Suggested Product Tags
- Oracle Cloud Infrastructure
- OCI Python SDK
- Identity and Access Management (IAM)
- Audit
- Object Storage
- Cloud Security
- Governance
- Automation
- Compliance
