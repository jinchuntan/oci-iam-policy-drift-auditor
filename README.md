# OCI IAM Policy Drift Auditor

Standalone OCI automation tool that audits IAM policy risk posture and recent IAM policy-change activity, then uploads evidence artifacts to OCI Object Storage.

## Purpose

This tool helps governance and security teams detect risky IAM policy statements and recent IAM drift.

It performs read-only collection from:

- OCI Identity (compartments, policies, users, groups, memberships, dynamic groups)
- OCI Audit (recent IAM-related activity)
- OCI Object Storage (artifact upload only)

No destructive OCI actions are executed.

## Key Checks

- Scans policies across scoped compartments
- Flags risky statements with severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- Maps referenced groups to member-count blast radius
- Pulls recent identity-related audit events (policy/group/dynamic-group changes)
- Produces JSON and Markdown reports
- Uploads artifacts to Object Storage for evidence retention

## Project Structure

```text
.
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
├── run.ps1
├── run_audit.py
├── docs
│   └── ACE_SUBMISSION_SAMPLE.md
└── src
    └── oci_iam_policy_drift_auditor
        ├── __init__.py
        ├── __main__.py
        ├── clients.py
        ├── config.py
        ├── main.py
        ├── models.py
        ├── analyzers
        │   ├── __init__.py
        │   └── policy_risk_analyzer.py
        ├── collectors
        │   ├── __init__.py
        │   ├── audit_collector.py
        │   └── identity_collector.py
        └── helpers
            ├── __init__.py
            ├── object_storage_uploader.py
            └── output_writer.py
```

## Prerequisites

- Windows PowerShell
- Python 3.10+ installed (`python` or `py` command available)
- OCI SDK config profile in `C:\Users\<user>\.oci\config`
- IAM permissions for read-only Identity/Audit and Object Storage upload
- At least one writable Object Storage bucket in scope (or set `OCI_OBJECT_STORAGE_BUCKET`)

## Quick Start (Recommended)

```powershell
cd <path-to-repo>\oci-iam-policy-drift-auditor
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

What this does automatically:

- creates `.venv` if missing
- installs `requirements.txt`
- creates `.env` from `.env.example` if missing
- runs the auditor

## Local-Only Run (No Upload)

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1 -SkipUpload
```

Use this mode when Object Storage permissions/bucket are not yet ready.

## Manual Run (Alternative)

```powershell
cd <path-to-repo>\oci-iam-policy-drift-auditor

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

Copy-Item .env.example .env
.\.venv\Scripts\python.exe run_audit.py
```

If `python` command is unavailable, use `py -3`.

## Environment Variables

See `.env.example`.

Common variables:

- `OCI_CONFIG_FILE` (optional; defaults to `~/.oci/config`)
- `OCI_CONFIG_PROFILE`
- `OCI_REGION`
- `OCI_ROOT_COMPARTMENT_OCID`
- `OCI_INCLUDE_SUBCOMPARTMENTS`
- `OCI_AUDIT_LOOKBACK_HOURS`
- `OCI_OBJECT_STORAGE_NAMESPACE` (optional; auto-resolved if omitted)
- `OCI_OBJECT_STORAGE_BUCKET` (optional; auto-discovered if omitted)
- `OCI_OBJECT_STORAGE_PREFIX`
- `OCI_FAIL_ON_UPLOAD_ERROR`

## Output Artifacts

Local output path (default `output/`):

- `iam_policy_drift_audit_<timestamp>.json`
- `iam_policy_drift_audit_<timestamp>.md`

Uploaded to Object Storage:

- `oci://<bucket>@<namespace>/<prefix>/iam_policy_drift_audit_<timestamp>.json`
- `oci://<bucket>@<namespace>/<prefix>/iam_policy_drift_audit_<timestamp>.md`

## Evidence Steps

### 1) Terminal Evidence

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

Capture these terminal lines as evidence:

- discovered compartment count
- policy collection progress
- report file paths
- uploaded Object Storage URIs (`oci://...`)

### 2) Object Storage Evidence

Use bucket/namespace from the printed upload URI and run:

```powershell
oci os object list `
  --namespace-name <namespace> `
  --bucket-name <bucket> `
  --prefix iam-policy-drift-audit
```

Optional object metadata verification:

```powershell
oci os object head `
  --namespace-name <namespace> `
  --bucket-name <bucket> `
  --name "iam-policy-drift-audit/<artifact-file-name>"
```

## Output
<img width="868" height="140" alt="image" src="https://github.com/user-attachments/assets/b9caf140-b4f6-473a-9c03-287ac8909f33" />
<img width="1919" height="992" alt="image" src="https://github.com/user-attachments/assets/1d6fa21f-86f5-433f-9dde-7802e16c9204" />




## Troubleshooting

- `python` not found: install Python 3.10+ or use `py -3`
- `Could not find config file`: set `OCI_CONFIG_FILE` in `.env` to your OCI config path
- Upload failure: set `OCI_OBJECT_STORAGE_BUCKET` explicitly or run `-SkipUpload` first

## Safety Notes

- Read-only calls to Identity and Audit APIs
- Only write operation is Object Storage upload
- No create/update/delete operations on OCI resources

