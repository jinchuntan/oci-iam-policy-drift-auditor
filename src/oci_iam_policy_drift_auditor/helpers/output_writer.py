from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_json_report(report: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_markdown_report(report: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_to_markdown(report), encoding="utf-8")


def _to_markdown(report: dict[str, Any]) -> str:
    metadata = report["metadata"]
    summary = report["summary"]

    lines: list[str] = []
    lines.append("# OCI IAM Policy Drift Auditor Report")
    lines.append("")
    lines.append(f"- Generated (UTC): `{metadata['generated_at_utc']}`")
    lines.append(f"- Region: `{metadata['region']}`")
    lines.append(f"- Tenancy: `{metadata['tenancy_ocid']}`")
    lines.append(f"- Audit Lookback (hours): `{metadata['audit_lookback_hours']}`")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Scanned Compartments | {summary['scanned_compartment_count']} |")
    lines.append(f"| Skipped Compartments | {summary['skipped_compartment_count']} |")
    lines.append(f"| Policies Scanned | {summary['total_policies_scanned']} |")
    lines.append(f"| Risky Statements | {summary['risky_statement_count']} |")
    lines.append(f"| Identity Audit Events | {summary['identity_audit_event_count']} |")
    lines.append(f"| Policy Change Events | {summary['policy_change_event_count']} |")
    lines.append(f"| Tenancy Users | {summary['tenancy_user_count']} |")
    lines.append(f"| Users with MFA Enabled | {summary['tenancy_user_mfa_enabled_count']} |")
    lines.append("")

    lines.append("## Risk Severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = summary["risky_statement_count_by_severity"].get(severity, 0)
        lines.append(f"| {severity} | {count} |")
    lines.append("")

    if report["skipped_compartments"]:
        lines.append("## Skipped Compartments")
        lines.append("")
        lines.append("| Compartment OCID | Reason |")
        lines.append("|---|---|")
        for item in report["skipped_compartments"]:
            lines.append(f"| {item['compartment_id']} | {item['reason']} |")
        lines.append("")

    lines.append("## Top Risky Statements (Top 50)")
    lines.append("")
    lines.append("| Severity | Compartment | Policy | Referenced Group | Group Members | Statement |")
    lines.append("|---|---|---|---|---:|---|")
    for item in report["risky_policies"][:50]:
        group_name = item["referenced_group"] or "-"
        group_members = item["referenced_group_member_count"]
        group_members_text = str(group_members) if group_members is not None else "-"
        statement = item["statement"].replace("|", "\\|")
        lines.append(
            f"| {item['risk_level']} | {item['compartment_name']} | {item['policy_name']} | "
            f"{group_name} | {group_members_text} | {statement} |"
        )
    if not report["risky_policies"]:
        lines.append("| - | - | - | - | - | No risky policy statements detected. |")
    lines.append("")

    lines.append("## Recent IAM Policy Change Events (Top 50)")
    lines.append("")
    lines.append("| Event Time (UTC) | Principal | Event Type | Event Name | Resource |")
    lines.append("|---|---|---|---|---|")
    for event in report["recent_policy_change_events"][:50]:
        lines.append(
            f"| {event['event_time_utc']} | {event['principal_name']} | {event['event_type']} | "
            f"{event['event_name'] or '-'} | {event['resource_name'] or '-'} |"
        )
    if not report["recent_policy_change_events"]:
        lines.append("| - | - | - | - | No recent IAM policy change events in audit window. |")

    lines.append("")
    lines.append("## Full Data")
    lines.append("")
    lines.append("- Full machine-readable data is available in the JSON artifact.")

    return "\n".join(lines)
