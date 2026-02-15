from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import re
from typing import Any


class PolicyRiskAnalyzer:
    _severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    _risk_rules: list[tuple[str, re.Pattern[str], str]] = [
        (
            "CRITICAL",
            re.compile(r"\bmanage\s+all-resources\s+in\s+tenancy\b", re.IGNORECASE),
            "Statement allows tenancy-wide management of all resources.",
        ),
        (
            "HIGH",
            re.compile(r"\ballow\s+group\s+\*\s+to\b|\ballow\s+any-group\s+to\b", re.IGNORECASE),
            "Statement uses wildcard group principal.",
        ),
        (
            "HIGH",
            re.compile(r"\bto\s+manage\s+policies\b", re.IGNORECASE),
            "Statement can manage IAM policies.",
        ),
        (
            "HIGH",
            re.compile(r"\bto\s+manage\s+groups\b", re.IGNORECASE),
            "Statement can manage IAM groups.",
        ),
        (
            "HIGH",
            re.compile(r"\bto\s+manage\s+users\b", re.IGNORECASE),
            "Statement can manage IAM users.",
        ),
        (
            "MEDIUM",
            re.compile(r"\bmanage\s+all-resources\s+in\s+compartment\b", re.IGNORECASE),
            "Statement allows compartment-wide management of all resources.",
        ),
        (
            "LOW",
            re.compile(r"\bto\s+use\s+all-resources\b", re.IGNORECASE),
            "Statement allows broad usage of all resources.",
        ),
    ]

    _group_ref = re.compile(r"\ballow\s+group\s+([a-z0-9_.\-]+)\s+to\b", re.IGNORECASE)

    _policy_event_terms = {
        "createpolicy",
        "updatepolicy",
        "deletepolicy",
        "creategroup",
        "updategroup",
        "deletegroup",
        "createdynamicgroup",
        "updatedynamicgroup",
        "deletedynamicgroup",
    }

    def analyze(
        self,
        generated_at: datetime,
        region: str,
        tenancy_ocid: str,
        audit_lookback_hours: int,
        compartments: list[Any],
        policy_inventory: list[dict[str, Any]],
        groups: list[Any],
        users: list[Any],
        memberships: list[Any],
        dynamic_groups: list[Any],
        audit_events: list[Any],
        skipped_compartments: list[dict[str, str]],
    ) -> dict[str, Any]:
        group_name_by_id = {group.id: group.name for group in groups}
        group_member_counts: Counter[str] = Counter()
        for membership in memberships:
            group_member_counts[membership.group_id] += 1

        risky_policies: list[dict[str, Any]] = []

        for item in policy_inventory:
            policy = item["policy"]
            compartment = item["compartment"]

            for statement in policy.statements or []:
                match = self._evaluate_statement(statement)
                if not match:
                    continue

                referenced_group = self._extract_group_name(statement)
                referenced_group_member_count = None
                if referenced_group:
                    group_id = self._find_group_id_by_name(groups, referenced_group)
                    if group_id:
                        referenced_group_member_count = group_member_counts.get(group_id, 0)

                risky_policies.append(
                    {
                        "risk_level": match["risk_level"],
                        "reasons": match["reasons"],
                        "compartment_id": compartment.id,
                        "compartment_name": compartment.name,
                        "policy_id": policy.id,
                        "policy_name": policy.name,
                        "policy_description": policy.description,
                        "statement": statement,
                        "referenced_group": referenced_group,
                        "referenced_group_member_count": referenced_group_member_count,
                    }
                )

        risky_policies.sort(
            key=lambda item: (
                self._severity_rank.get(item["risk_level"], 9),
                item["compartment_name"].lower(),
                item["policy_name"].lower(),
            )
        )

        parsed_events = [self._normalize_audit_event(event) for event in audit_events]
        identity_events = [event for event in parsed_events if "identity" in event["event_type"].lower()]
        policy_change_events = [event for event in identity_events if self._is_policy_change_event(event)]
        policy_change_events.sort(key=lambda item: item["event_time_utc"], reverse=True)

        risky_by_severity = Counter(item["risk_level"] for item in risky_policies)
        policy_counts_by_compartment = Counter(item["compartment_name"] for item in risky_policies)

        mfa_enabled = sum(1 for user in users if bool(getattr(user, "is_mfa_activated", False)))

        return {
            "metadata": {
                "report_name": "iam_policy_drift_audit",
                "generated_at_utc": generated_at.isoformat(),
                "region": region,
                "tenancy_ocid": tenancy_ocid,
                "audit_lookback_hours": audit_lookback_hours,
            },
            "summary": {
                "scanned_compartment_count": len(compartments),
                "skipped_compartment_count": len(skipped_compartments),
                "total_policies_scanned": len(policy_inventory),
                "risky_statement_count": len(risky_policies),
                "risky_statement_count_by_severity": dict(risky_by_severity),
                "identity_audit_event_count": len(identity_events),
                "policy_change_event_count": len(policy_change_events),
                "tenancy_group_count": len(groups),
                "tenancy_dynamic_group_count": len(dynamic_groups),
                "tenancy_user_count": len(users),
                "tenancy_user_mfa_enabled_count": mfa_enabled,
                "risky_policy_compartments_top": policy_counts_by_compartment.most_common(10),
            },
            "skipped_compartments": skipped_compartments,
            "risky_policies": risky_policies,
            "recent_policy_change_events": policy_change_events[:200],
            "group_membership_summary": self._build_group_summary(groups, group_name_by_id, group_member_counts),
        }

    def _evaluate_statement(self, statement: str) -> dict[str, Any] | None:
        reasons: list[str] = []
        severities: list[str] = []

        for severity, pattern, reason in self._risk_rules:
            if pattern.search(statement):
                reasons.append(reason)
                severities.append(severity)

        if not reasons:
            return None

        highest = min(severities, key=lambda level: self._severity_rank[level])
        return {"risk_level": highest, "reasons": reasons}

    def _extract_group_name(self, statement: str) -> str | None:
        match = self._group_ref.search(statement)
        return match.group(1) if match else None

    def _find_group_id_by_name(self, groups: list[Any], group_name: str) -> str | None:
        target = group_name.strip().lower()
        for group in groups:
            if group.name.lower() == target:
                return group.id
        return None

    def _normalize_audit_event(self, event: Any) -> dict[str, Any]:
        data = getattr(event, "data", None)
        if not isinstance(data, dict):
            data = {}

        identity = data.get("identity") if isinstance(data.get("identity"), dict) else {}

        event_time = getattr(event, "event_time", None)
        if isinstance(event_time, datetime):
            event_time_utc = event_time.astimezone(timezone.utc).isoformat()
        else:
            event_time_utc = ""

        return {
            "event_id": getattr(event, "event_id", None),
            "event_type": getattr(event, "event_type", ""),
            "event_source": getattr(event, "source", ""),
            "event_time_utc": event_time_utc,
            "event_name": data.get("eventName") or data.get("event_name") or "",
            "compartment_id": data.get("compartmentId") or data.get("compartment_id") or "",
            "resource_name": data.get("resourceName") or data.get("resource_name") or "",
            "principal_name": identity.get("principalName") or identity.get("principal_name") or "UNKNOWN_PRINCIPAL",
            "request_action": data.get("requestAction") or data.get("request_action") or "",
        }

    def _is_policy_change_event(self, event: dict[str, Any]) -> bool:
        candidate = f"{event['event_type']} {event['event_name']}"
        normalized = "".join(ch for ch in candidate.lower() if ch.isalnum())
        return any(term in normalized for term in self._policy_event_terms)

    def _build_group_summary(
        self,
        groups: list[Any],
        group_name_by_id: dict[str, str],
        group_member_counts: Counter[str],
    ) -> list[dict[str, Any]]:
        summary = []
        for group in groups:
            summary.append(
                {
                    "group_id": group.id,
                    "group_name": group_name_by_id.get(group.id, group.id),
                    "member_count": group_member_counts.get(group.id, 0),
                }
            )

        summary.sort(key=lambda item: item["member_count"], reverse=True)
        return summary
