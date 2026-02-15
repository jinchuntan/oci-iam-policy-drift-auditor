from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from oci.exceptions import ServiceError

from .analyzers import PolicyRiskAnalyzer
from .clients import create_clients, create_oci_config
from .collectors import AuditCollector, IdentityCollector
from .config import AppConfig
from .helpers import ObjectStorageUploader, write_json_report, write_markdown_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit OCI IAM policy risk posture and recent IAM changes.")
    parser.add_argument(
        "--skip-upload",
        action="store_true",
        help="Generate local reports only, do not upload to Object Storage.",
    )
    return parser.parse_args()


def discover_candidate_buckets(
    object_storage_client: Any,
    namespace: str,
    compartment_ids: list[str],
) -> list[str]:
    seen: set[str] = set()
    buckets: list[str] = []

    for compartment_id in compartment_ids:
        try:
            response = object_storage_client.list_buckets(
                namespace_name=namespace,
                compartment_id=compartment_id,
            )
        except ServiceError:
            continue

        for bucket in response.data:
            name = getattr(bucket, "name", None)
            if not name or name in seen:
                continue
            seen.add(name)
            buckets.append(name)

    return sorted(buckets)


def main() -> int:
    args = parse_args()

    try:
        app_config = AppConfig.from_env()
        oci_config = create_oci_config(app_config)
        clients = create_clients(oci_config)
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Failed to initialize configuration or OCI clients: {exc}")
        return 1

    identity_collector = IdentityCollector(clients["identity"])
    audit_collector = AuditCollector(clients["audit"])

    tenancy_ocid = oci_config["tenancy"]
    region = oci_config["region"]

    try:
        compartments = identity_collector.list_compartments(
            tenancy_ocid=tenancy_ocid,
            root_compartment_ocid=app_config.root_compartment_ocid,
            include_subcompartments=app_config.include_subcompartments,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Failed to list compartments: {exc}")
        return 1

    print(f"[INFO] Discovered {len(compartments)} accessible compartments in scope.")

    skipped_compartments: list[dict[str, str]] = []
    policy_inventory: list[dict[str, Any]] = []

    for index, compartment in enumerate(compartments, start=1):
        print(f"[INFO] [{index}/{len(compartments)}] Collecting policies: {compartment.name}")
        try:
            policies = identity_collector.list_policies(compartment.id)
            for policy in policies:
                policy_inventory.append({"compartment": compartment, "policy": policy})
        except ServiceError as exc:
            skipped_compartments.append(
                {
                    "compartment_id": compartment.id,
                    "reason": f"identity.list_policies failed: {exc.status} {exc.code} {exc.message}",
                }
            )
            print(f"[WARN] Could not read policies in compartment {compartment.name}")
        except Exception as exc:  # noqa: BLE001
            skipped_compartments.append(
                {
                    "compartment_id": compartment.id,
                    "reason": f"identity.list_policies failed: {exc}",
                }
            )
            print(f"[WARN] Unexpected policy read error in compartment {compartment.name}: {exc}")

    print("[INFO] Collecting tenancy IAM principal inventory (users, groups, memberships, dynamic groups).")

    try:
        groups = identity_collector.list_groups(tenancy_ocid)
    except Exception as exc:  # noqa: BLE001
        groups = []
        print(f"[WARN] list_groups failed: {exc}")

    try:
        users = identity_collector.list_users(tenancy_ocid)
    except Exception as exc:  # noqa: BLE001
        users = []
        print(f"[WARN] list_users failed: {exc}")

    try:
        user_ids = [user.id for user in users]
        memberships = identity_collector.list_user_group_memberships_for_users(tenancy_ocid, user_ids)
    except Exception as exc:  # noqa: BLE001
        memberships = []
        print(f"[WARN] list_user_group_memberships_for_users failed: {exc}")

    try:
        dynamic_groups = identity_collector.list_dynamic_groups(tenancy_ocid)
    except Exception as exc:  # noqa: BLE001
        dynamic_groups = []
        print(f"[WARN] list_dynamic_groups failed: {exc}")

    generated_at = datetime.now(timezone.utc)
    start_time = generated_at - timedelta(hours=app_config.audit_lookback_hours)
    end_time = generated_at

    print(
        "[INFO] Collecting Audit events "
        f"from {start_time.isoformat()} to {end_time.isoformat()} for scoped compartments."
    )

    audit_events: list[Any] = []
    seen_event_ids: set[str] = set()

    for compartment in compartments:
        try:
            events = audit_collector.list_events(
                compartment_ocid=compartment.id,
                start_time=start_time,
                end_time=end_time,
            )
        except ServiceError as exc:
            print(
                "[WARN] audit.list_events failed for "
                f"{compartment.name}: {exc.status} {exc.code} {exc.message}"
            )
            continue
        except Exception as exc:  # noqa: BLE001
            print(f"[WARN] audit.list_events failed for {compartment.name}: {exc}")
            continue

        for event in events:
            event_id = getattr(event, "event_id", None)
            if event_id and event_id in seen_event_ids:
                continue
            if event_id:
                seen_event_ids.add(event_id)
            audit_events.append(event)

    analyzer = PolicyRiskAnalyzer()
    report = analyzer.analyze(
        generated_at=generated_at,
        region=region,
        tenancy_ocid=tenancy_ocid,
        audit_lookback_hours=app_config.audit_lookback_hours,
        compartments=compartments,
        policy_inventory=policy_inventory,
        groups=groups,
        users=users,
        memberships=memberships,
        dynamic_groups=dynamic_groups,
        audit_events=audit_events,
        skipped_compartments=skipped_compartments,
    )

    timestamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path(app_config.output_dir)
    json_path = output_dir / f"iam_policy_drift_audit_{timestamp}.json"
    markdown_path = output_dir / f"iam_policy_drift_audit_{timestamp}.md"

    write_json_report(report, json_path)
    write_markdown_report(report, markdown_path)

    print(f"[INFO] JSON report written: {json_path}")
    print(f"[INFO] Markdown report written: {markdown_path}")

    if args.skip_upload:
        print("[INFO] Upload skipped (--skip-upload).")
        return 0

    try:
        namespace = app_config.object_storage_namespace or clients["object_storage"].get_namespace().data
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Could not resolve Object Storage namespace: {exc}")
        return 2 if app_config.fail_on_upload_error else 0

    bucket_candidates: list[str] = []
    if app_config.object_storage_bucket:
        bucket_candidates.append(app_config.object_storage_bucket)

    if app_config.auto_discover_bucket:
        discovered = discover_candidate_buckets(
            object_storage_client=clients["object_storage"],
            namespace=namespace,
            compartment_ids=[item.id for item in compartments],
        )
        for bucket in discovered:
            if bucket not in bucket_candidates:
                bucket_candidates.append(bucket)

    if not bucket_candidates:
        print("[ERROR] No accessible bucket found for upload.")
        print("[ERROR] Set OCI_OBJECT_STORAGE_BUCKET or allow list_buckets access in scope.")
        return 2 if app_config.fail_on_upload_error else 0

    upload_success = False
    last_upload_error: str | None = None

    for bucket in bucket_candidates:
        uploader = ObjectStorageUploader(
            object_storage_client=clients["object_storage"],
            namespace=namespace,
            bucket=bucket,
            prefix=app_config.object_storage_prefix,
        )

        print(f"[INFO] Attempting report upload to bucket: {bucket}")

        try:
            json_result = uploader.upload_file(json_path, "application/json")
            md_result = uploader.upload_file(markdown_path, "text/markdown")
            print(f"[INFO] Uploaded: {json_result.uri}")
            print(f"[INFO] Uploaded: {md_result.uri}")
            upload_success = True
            break
        except Exception as exc:  # noqa: BLE001
            last_upload_error = str(exc)
            print(f"[WARN] Upload attempt failed for bucket {bucket}: {exc}")

    if not upload_success:
        print("[ERROR] Upload failed for all candidate buckets.")
        if last_upload_error:
            print(f"[ERROR] Last upload error: {last_upload_error}")
        if app_config.fail_on_upload_error:
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

